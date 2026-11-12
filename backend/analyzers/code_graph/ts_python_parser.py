"""
Синтаксический анализатор Python на базе Tree-sitter (v0.26+).

Почему мы разделяем `signature_hash` и `body_hash` на этапе разбора AST:
Если разработчик или ИИ оптимизировал цикл внутри функции, изменится только `body_hash`,
а `signature_hash` (имя, аргументы, тип возврата и декораторы маршрута) останется прежним.
Это позволяет Impact Engine не поднимать ложную тревогу по всем вызывающим модулям.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any

import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser

from backend.core.models import (
    GraphNodeRecord,
    NodeType,
    RiskLevel,
    build_canonical_uri,
    compute_text_hash,
    redact_inline_secrets,
    wrap_untrusted_code_doc,
)

PY_LANGUAGE = Language(tspython.language())
# Важно (G-08): переиспользуем единый синглтон Parser под Lock, чтобы исключить GC-деаллокацию
# временных C-парсеров `tree-sitter 0.26.0` во время обхода AST и ускорить индексацию.
_PY_PARSER = Parser(PY_LANGUAGE)
_PY_PARSE_LOCK = threading.Lock()

_FASTAPI_HTTP_METHODS: frozenset[str] = frozenset({"get", "post", "put", "delete", "patch"})
_ROUTER_PREFIX_RE = re.compile(
    r"""include_router\(\s*([A-Za-z_][A-Za-z0-9_.]*)(?:[^)]*?prefix\s*=\s*['"]([^'"]+)['"])?""",
    re.DOTALL,
)
_API_ROUTER_DEF_RE = re.compile(
    r"""([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)?APIRouter\([^)]*?prefix\s*=\s*['"]([^'"]+)['"]""",
    re.DOTALL,
)
_ROUTE_DEC_RE = re.compile(
    r"""^@([A-Za-z_][A-Za-z0-9_]*)\.([a-z]+)\(\s*(?:path\s*=\s*)?['"]([^'"]*)['"]""",
    re.DOTALL,
)


@dataclass(slots=True)
class PythonFileParseResult:
    nodes: list[GraphNodeRecord] = field(default_factory=list)
    imports: list[tuple[str, list[str]]] = field(default_factory=list)  # (module_path, imported_names)
    calls: list[tuple[str, str]] = field(default_factory=list)          # (caller_uri, called_name)
    fastapi_routes: list[dict[str, Any]] = field(default_factory=list)  # {func_uri, method, path, router_var}
    router_includes: list[dict[str, str]] = field(default_factory=list) # {router_var, prefix, imported_from}


def _node_text(node: Node | None, source_bytes: bytes) -> str:
    if node is None:
        return ""
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _named_children(node: Node | None) -> list[Node]:
    """
    Безопасное получение именованных дочерних узлов AST.
    Почему не `node.named_children`: в C-расширении `tree-sitter 0.26.0` под Windows
    вызов `.named_children` на листовых узлах с `named_child_count == 0` может вызывать
    Access Violation. Фильтрация `node.children` по `is_named` полностью исключает этот сбой.
    """
    if node is None or node.child_count == 0:
        return []
    return [c for c in node.children if c.is_named]


def _extract_docstring(block_node: Node | None, source_bytes: bytes) -> str:
    """Извлекает первую строку документации модуля/класса/функции и изолирует её тегом безопасности."""
    if block_node is None:
        return ""
    for child in _named_children(block_node):
        if child.type == "expression_statement" and child.named_child_count > 0:
            expr = child.named_child(0)
            if expr and expr.type == "string":
                raw = _node_text(expr, source_bytes).strip()
                cleaned = raw.strip("\"' \n\r\t")
                if cleaned.startswith(('""', "''")):
                    cleaned = cleaned.strip("\"' \n\r\t")
                return wrap_untrusted_code_doc(cleaned)
        break
    return ""


def _collect_calls_in_subtree(root: Node, caller_uri: str, source_bytes: bytes, out_calls: list[tuple[str, str]]) -> None:
    """Собирает имена вызываемых функций/методов внутри тела функции (без захода во вложенные def)."""
    stack: list[Node] = _named_children(root)
    while stack:
        cur = stack.pop()
        if cur.type in ("function_definition", "class_definition"):
            continue
        if cur.type == "call":
            fn_node = cur.child_by_field_name("function")
            if fn_node is not None:
                fn_txt, _ = redact_inline_secrets(_node_text(fn_node, source_bytes).strip())
                if fn_txt and len(fn_txt) <= 120:
                    out_calls.append((caller_uri, fn_txt))
        stack.extend(_named_children(cur))


def parse_python_file(rel_path: str, source_bytes: bytes, file_risk: RiskLevel) -> PythonFileParseResult:
    """Разбирает один `.py` файл и возвращает найденные сущности, импорты, вызовы и FastAPI-маршруты."""
    with _PY_PARSE_LOCK:
        tree = _PY_PARSER.parse(source_bytes)
        root = tree.root_node

    result = PythonFileParseResult()
    file_uri = build_canonical_uri("py", rel_path)
    module_doc = _extract_docstring(root, source_bytes)
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
            summary_ru=module_doc,
            meta={"line_count": line_count, "language": "python"},
        )
    )

    imported_symbol_origins: dict[str, str] = {}

    for child in _named_children(root):
        if child.type == "import_statement":
            for name_node in _named_children(child):
                raw_imp = _node_text(name_node, source_bytes).strip()
                parts_as = [p.strip() for p in raw_imp.split(" as ", 1)]
                mod_name = parts_as[0]
                if mod_name:
                    result.imports.append((mod_name, []))
                    bound_nm = parts_as[1] if len(parts_as) == 2 and parts_as[1] else mod_name
                    imported_symbol_origins[bound_nm] = f"{mod_name}:"
        elif child.type == "import_from_statement":
            mod_node = child.child_by_field_name("module_name") or next(
                (c for c in _named_children(child) if c.type == "relative_import"), None
            )
            mod_name = _node_text(mod_node, source_bytes).strip()
            names: list[str] = []
            for sub in _named_children(child):
                if sub == mod_node:
                    continue
                raw_sym = _node_text(sub, source_bytes).strip()
                if " as " in raw_sym:
                    orig_sym, alias_sym = [p.strip() for p in raw_sym.split(" as ", 1)]
                    names.append(orig_sym)
                    imported_symbol_origins[alias_sym] = f"{mod_name}:{orig_sym}"
                elif raw_sym:
                    names.append(raw_sym)
                    imported_symbol_origins[raw_sym] = f"{mod_name}:{raw_sym}"
            if mod_name:
                result.imports.append((mod_name, names))

        elif child.type in ("function_definition", "decorated_definition", "class_definition"):
            _process_top_or_class_item(
                node=child,
                rel_path=rel_path,
                parent_uri=file_uri,
                class_prefix="",
                file_risk=file_risk,
                source_bytes=source_bytes,
                result=result,
            )

    # Поддержка префикса как внутри `APIRouter(prefix="/api/...")`, так и в `app.include_router(..., prefix=...)`
    full_text = source_bytes.decode("utf-8", errors="replace")
    local_router_prefixes = {
        m.group(1): m.group(2).rstrip("/")
        for m in _API_ROUTER_DEF_RE.finditer(full_text)
    }
    for rt in result.fastapi_routes:
        local_pref = local_router_prefixes.get(rt["router_var"], "")
        if local_pref:
            sub = str(rt["path"])
            rt["path"] = f"{local_pref}/{sub.lstrip('/')}" if sub else local_pref

    for match in _ROUTER_PREFIX_RE.finditer(full_text):
        router_var = match.group(1)
        prefix = match.group(2) or ""
        origin = imported_symbol_origins.get(router_var, "")
        if not origin and "." in router_var:
            head_var, tail_attr = router_var.rsplit(".", 1)
            base_origin = imported_symbol_origins.get(head_var) or imported_symbol_origins.get(router_var.split(".", 1)[0], "")
            if ":" in base_origin:
                b_mod, b_sym = base_origin.split(":", 1)
                if not b_sym:
                    origin = f"{b_mod}:{tail_attr}"
                elif not b_mod.strip("."):
                    origin = f"{b_mod}:{b_sym}"
                else:
                    origin = f"{b_mod}.{b_sym}:{tail_attr}"
        result.router_includes.append(
            {"router_var": router_var, "prefix": prefix, "imported_from": origin, "importer_rel_path": rel_path}
        )

    return result


def _process_top_or_class_item(
    node: Node,
    rel_path: str,
    parent_uri: str,
    class_prefix: str,
    file_risk: RiskLevel,
    source_bytes: bytes,
    result: PythonFileParseResult,
) -> None:
    decorators_text: list[str] = []
    actual = node
    if node.type == "decorated_definition":
        for sub in _named_children(node):
            if sub.type == "decorator":
                decorators_text.append(_node_text(sub, source_bytes).strip())
            elif sub.type in ("function_definition", "class_definition"):
                actual = sub

    if actual.type == "class_definition":
        name_node = actual.child_by_field_name("name")
        cls_name = _node_text(name_node, source_bytes).strip()
        if not cls_name:
            return
        super_node = actual.child_by_field_name("superclasses")
        super_txt = _node_text(super_node, source_bytes).strip()
        body_node = actual.child_by_field_name("body")
        cls_uri = build_canonical_uri("py", rel_path, cls_name)
        sig = f"class {cls_name}{super_txt}"
        is_pydantic = any(b in super_txt for b in ("BaseModel", "SQLModel", "TypedDict", "BaseSettings"))

        result.nodes.append(
            GraphNodeRecord(
                uri=cls_uri,
                node_type=NodeType.DATA_CONTRACT if is_pydantic else NodeType.CLASS,
                name=cls_name,
                rel_path=rel_path,
                start_line=node.start_point.row + 1,
                end_line=node.end_point.row + 1,
                c4_level=4,
                risk_level=file_risk,
                signature=sig,
                signature_hash=compute_text_hash(sig),
                body_hash=compute_text_hash(_node_text(body_node, source_bytes)),
                summary_ru=_extract_docstring(body_node, source_bytes),
                parent_uri=parent_uri,
                meta={"bases": super_txt, "is_pydantic": is_pydantic},
            )
        )
        if body_node is not None:
            for member in _named_children(body_node):
                if member.type in ("function_definition", "decorated_definition"):
                    _process_top_or_class_item(
                        node=member,
                        rel_path=rel_path,
                        parent_uri=cls_uri,
                        class_prefix=f"{cls_name}.",
                        file_risk=file_risk,
                        source_bytes=source_bytes,
                        result=result,
                    )

    elif actual.type == "function_definition":
        name_node = actual.child_by_field_name("name")
        fn_name = _node_text(name_node, source_bytes).strip()
        if not fn_name:
            return
        params_txt = _node_text(actual.child_by_field_name("parameters"), source_bytes).strip()
        ret_node = actual.child_by_field_name("return_type")
        ret_txt = f" -> {_node_text(ret_node, source_bytes).strip()}" if ret_node else ""
        body_node = actual.child_by_field_name("body")
        qualname = f"{class_prefix}{fn_name}"
        fn_uri = build_canonical_uri("py", rel_path, qualname)
        dec_prefix = " ".join(decorators_text)
        raw_sig = f"{dec_prefix + ' ' if dec_prefix else ''}def {qualname}{params_txt}{ret_txt}"
        sig, _ = redact_inline_secrets(raw_sig)

        is_test = fn_name.startswith("test_") or "/tests/" in f"/{rel_path}/"
        result.nodes.append(
            GraphNodeRecord(
                uri=fn_uri,
                node_type=NodeType.TEST if is_test else NodeType.FUNCTION,
                name=qualname,
                rel_path=rel_path,
                start_line=node.start_point.row + 1,
                end_line=node.end_point.row + 1,
                c4_level=4,
                risk_level=file_risk,
                signature=sig[:240],
                signature_hash=compute_text_hash(sig),
                body_hash=compute_text_hash(_node_text(body_node, source_bytes)),
                summary_ru=_extract_docstring(body_node, source_bytes),
                parent_uri=parent_uri,
            )
        )
        if body_node is not None:
            _collect_calls_in_subtree(body_node, fn_uri, source_bytes, result.calls)
            # Поддержка паттерна App Factory (`def create_app(): @app.get(...) def route(): ...`)
            if not class_prefix:
                for nested in _named_children(body_node):
                    if nested.type == "decorated_definition":
                        _process_top_or_class_item(
                            node=nested,
                            rel_path=rel_path,
                            parent_uri=fn_uri,
                            class_prefix=f"{qualname}.",
                            file_risk=file_risk,
                            source_bytes=source_bytes,
                            result=result,
                        )

        # Распознаём одно- и многострочные декораторы маршрутов FastAPI (`@router.post(...)` / `path="/..."`)
        for dec in decorators_text:
            m = _ROUTE_DEC_RE.match(dec)
            if m and m.group(2) in _FASTAPI_HTTP_METHODS:
                result.fastapi_routes.append(
                    {
                        "func_uri": fn_uri,
                        "router_var": m.group(1),
                        "method": m.group(2).upper(),
                        "path": m.group(3),
                    }
                )
