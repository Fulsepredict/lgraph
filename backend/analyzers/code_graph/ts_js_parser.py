"""
Синтаксический анализатор JavaScript / TypeScript / TSX на базе Tree-sitter.

Почему здесь одновременно извлекаются функции, интерфейсы И вызовы fetch / IPC:
За один быстрый проход по синтаксическому дереву файла мы получаем как карту символов,
так и точки межъязыковых мостов (`fetch`, `axios`, кастомные обёртки и `ipcRenderer`/`ipcMain`),
передавая их в `BridgeLinker` вместе с точным URI вызывающей функции.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

import tree_sitter_javascript as tsjavascript
import tree_sitter_typescript as tstypescript
from tree_sitter import Language, Node, Parser

from backend.analyzers.code_graph.ts_js_call_helpers import scan_js_call_expressions
from backend.core.models import (
    GraphNodeRecord,
    NodeType,
    RiskLevel,
    build_canonical_uri,
    compute_text_hash,
    redact_inline_secrets,
)

JS_LANGUAGE = Language(tsjavascript.language())
TS_LANGUAGE = Language(tstypescript.language_typescript())
TSX_LANGUAGE = Language(tstypescript.language_tsx())

# Единые переиспользуемые C-парсеры под потоковой блокировкой (предохранитель G-08)
_JS_PARSER = Parser(JS_LANGUAGE)
_TS_PARSER = Parser(TS_LANGUAGE)
_TSX_PARSER = Parser(TSX_LANGUAGE)
_JS_TS_PARSE_LOCK = threading.Lock()


@dataclass(slots=True)
class JsTsFileParseResult:
    scheme: str = "ts"
    nodes: list[GraphNodeRecord] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    calls: list[tuple[str, str]] = field(default_factory=list)
    raw_call_sites: list[dict[str, Any]] = field(default_factory=list)
    has_redacted_secret: bool = False


def _node_text(node: Node | None, source_bytes: bytes) -> str:
    if node is None:
        return ""
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _named_children(node: Node | None) -> list[Node]:
    """Безопасный обход именованных дочерних узлов в обход C-дефекта `.named_children` в tree-sitter 0.26."""
    if node is None or node.child_count == 0:
        return []
    return [c for c in node.children if c.is_named]


def _select_parser_and_scheme(rel_path: str) -> tuple[Parser, str]:
    lower = rel_path.lower()
    if lower.endswith(".tsx"):
        return _TSX_PARSER, "ts"
    if lower.endswith(".ts"):
        return _TS_PARSER, "ts"
    return _JS_PARSER, "js"


def parse_js_ts_file(rel_path: str, source_bytes: bytes, file_risk: RiskLevel) -> JsTsFileParseResult:
    """Разбирает `.js`, `.cjs`, `.mjs`, `.jsx`, `.ts`, `.tsx` файл за один проход AST."""
    parser, scheme = _select_parser_and_scheme(rel_path)
    with _JS_TS_PARSE_LOCK:
        tree = parser.parse(source_bytes)
        root = tree.root_node

    result = JsTsFileParseResult(scheme=scheme)
    file_uri = build_canonical_uri(scheme, rel_path)
    line_count = source_bytes.count(b"\n") + 1

    result.nodes.append(
        GraphNodeRecord(
            uri=file_uri,
            node_type=NodeType.FILE,
            name=rel_path.rsplit("/", 1)[-1],
            rel_path=rel_path,
            start_line=1,
            end_line=line_count,
            c4_level=4,
            risk_level=file_risk,
            meta={"line_count": line_count, "language": scheme},
        )
    )

    for child in _named_children(root):
        actual = child
        if child.type == "export_statement":
            # Разворачиваем `export function ...` / `export interface ...` / `export const ...`
            for sub in _named_children(child):
                if sub.type in (
                    "function_declaration",
                    "class_declaration",
                    "interface_declaration",
                    "type_alias_declaration",
                    "lexical_declaration",
                ):
                    actual = sub
                    break

        if child.type == "import_statement":
            src_node = child.child_by_field_name("source")
            imp_str, imp_sec = redact_inline_secrets(_node_text(src_node, source_bytes).strip("\"'` "))
            if imp_sec:
                result.has_redacted_secret = True
            if imp_str:
                result.imports.append(imp_str)

        if actual.type in ("interface_declaration", "type_alias_declaration"):
            name_txt = _node_text(actual.child_by_field_name("name"), source_bytes).strip()
            if name_txt:
                uri = build_canonical_uri(scheme, rel_path, name_txt)
                full_txt = _node_text(actual, source_bytes)
                result.nodes.append(
                    GraphNodeRecord(
                        uri=uri,
                        node_type=NodeType.DATA_CONTRACT,
                        name=name_txt,
                        rel_path=rel_path,
                        start_line=child.start_point.row + 1,
                        end_line=child.end_point.row + 1,
                        c4_level=4,
                        risk_level=file_risk,
                        signature=f"interface {name_txt}",
                        signature_hash=compute_text_hash(full_txt),
                        body_hash=compute_text_hash(full_txt),
                        parent_uri=file_uri,
                    )
                )

        elif actual.type == "class_declaration":
            name_txt = _node_text(actual.child_by_field_name("name"), source_bytes).strip()
            if name_txt:
                uri = build_canonical_uri(scheme, rel_path, name_txt)
                body_node = actual.child_by_field_name("body")
                body_txt = _node_text(body_node, source_bytes)
                result.nodes.append(
                    GraphNodeRecord(
                        uri=uri,
                        node_type=NodeType.CLASS,
                        name=name_txt,
                        rel_path=rel_path,
                        start_line=child.start_point.row + 1,
                        end_line=child.end_point.row + 1,
                        c4_level=4,
                        risk_level=file_risk,
                        signature=f"class {name_txt}",
                        signature_hash=compute_text_hash(f"class {name_txt}"),
                        body_hash=compute_text_hash(body_txt),
                        parent_uri=file_uri,
                    )
                )
                for member in _named_children(body_node):
                    if member.type == "method_definition":
                        m_nm = _node_text(member.child_by_field_name("name"), source_bytes).strip()
                        if m_nm:
                            _extract_js_function(
                                member, member, f"{name_txt}.{m_nm}", scheme, rel_path, uri, file_risk, source_bytes, result
                            )

        elif actual.type == "function_declaration":
            _extract_js_function(
                outer_node=child,
                fn_node=actual,
                fn_name=_node_text(actual.child_by_field_name("name"), source_bytes).strip(),
                scheme=scheme,
                rel_path=rel_path,
                file_uri=file_uri,
                file_risk=file_risk,
                source_bytes=source_bytes,
                result=result,
            )

        elif actual.type in ("lexical_declaration", "variable_declaration"):
            for decl in _named_children(actual):
                if decl.type != "variable_declarator":
                    continue
                var_name = _node_text(decl.child_by_field_name("name"), source_bytes).strip()
                val_node = decl.child_by_field_name("value")
                # Поддержка обёрток React (`memo(...)`, `React.memo(...)`, `forwardRef(...)`, `observer(...)`)
                if val_node and val_node.type == "call_expression":
                    for arg_c in _named_children(val_node.child_by_field_name("arguments")):
                        if arg_c.type in ("arrow_function", "function_expression", "function"):
                            val_node = arg_c
                            break
                if val_node and val_node.type in ("arrow_function", "function_expression", "function"):
                    _extract_js_function(
                        outer_node=child,
                        fn_node=val_node,
                        fn_name=var_name,
                        scheme=scheme,
                        rel_path=rel_path,
                        file_uri=file_uri,
                        file_risk=file_risk,
                        source_bytes=source_bytes,
                        result=result,
                    )
                elif val_node and val_node.type == "object" and var_name:
                    # Поддержка сервисных объектов вида `export const api = { async getSettings() { ... } }`
                    for prop in _named_children(val_node):
                        if prop.type == "method_definition":
                            m_nm = _node_text(prop.child_by_field_name("name"), source_bytes).strip()
                            if m_nm:
                                _extract_js_function(
                                    prop, prop, f"{var_name}.{m_nm}", scheme, rel_path, file_uri, file_risk, source_bytes, result
                                )
                        elif prop.type == "pair":
                            p_val = prop.child_by_field_name("value")
                            p_key = _node_text(prop.child_by_field_name("key"), source_bytes).strip("\"' ")
                            if p_key and p_val and p_val.type in ("arrow_function", "function_expression", "function"):
                                _extract_js_function(
                                    prop, p_val, f"{var_name}.{p_key}", scheme, rel_path, file_uri, file_risk, source_bytes, result
                                )

    # Сканируем все вызовы верхнего и вложенного уровня (CommonJS `require`, `ipcRenderer`, `fetch` и др.)
    known_symbol_uris = {n.uri for n in result.nodes}
    calls_had_secret = scan_js_call_expressions(
        root=root,
        file_uri=file_uri,
        scheme=scheme,
        rel_path=rel_path,
        source_bytes=source_bytes,
        out_imports=result.imports,
        out_calls=result.calls,
        out_call_sites=result.raw_call_sites,
        known_symbol_uris=known_symbol_uris,
    )
    if calls_had_secret:
        result.has_redacted_secret = True
    return result


def _extract_js_function(
    outer_node: Node,
    fn_node: Node,
    fn_name: str,
    scheme: str,
    rel_path: str,
    file_uri: str,
    file_risk: RiskLevel,
    source_bytes: bytes,
    result: JsTsFileParseResult,
) -> None:
    if not fn_name:
        return
    params_txt = _node_text(fn_node.child_by_field_name("parameters"), source_bytes).strip()
    ret_node = fn_node.child_by_field_name("return_type")
    ret_txt = _node_text(ret_node, source_bytes).strip() if ret_node else ""
    body_node = fn_node.child_by_field_name("body")
    fn_uri = build_canonical_uri(scheme, rel_path, fn_name)
    sig, sig_sec = redact_inline_secrets(f"function {fn_name}{params_txt}{ret_txt}")
    if sig_sec:
        result.has_redacted_secret = True

    result.nodes.append(
        GraphNodeRecord(
            uri=fn_uri,
            node_type=NodeType.FUNCTION,
            name=fn_name,
            rel_path=rel_path,
            start_line=outer_node.start_point.row + 1,
            end_line=outer_node.end_point.row + 1,
            c4_level=4,
            risk_level=file_risk,
            signature=sig[:240],
            signature_hash=compute_text_hash(sig),
            body_hash=compute_text_hash(_node_text(body_node, source_bytes)),
            parent_uri=file_uri,
        )
    )
