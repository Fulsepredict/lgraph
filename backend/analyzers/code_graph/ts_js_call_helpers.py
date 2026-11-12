"""
Вспомогательный модуль извлечения вызовов (`fetch`, `axios`, `IPC`, кастомные обёртки)
и конкатенации URL из синтаксического дерева JavaScript / TypeScript.

Почему выделен отдельно от `ts_js_parser.py`:
Соблюдение правила анти-монолита `<= 350` строк (`GR-LGRAPH-SIZE`) и разделение ответственности:
`ts_js_parser.py` отвечает за объявления модулей/классов/функций, а этот модуль — за граф вызовов.
"""

from __future__ import annotations

import re
from typing import Any

from tree_sitter import Node

from backend.core.models import build_canonical_uri, redact_inline_secrets


def _txt(node: Node | None, source_bytes: bytes) -> str:
    if node is None:
        return ""
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _named(node: Node | None) -> list[Node]:
    if node is None or node.child_count == 0:
        return []
    return [c for c in node.children if c.is_named]


def find_enclosing_js_function_uri(
    call_node: Node,
    file_uri: str,
    scheme: str,
    rel_path: str,
    source_bytes: bytes,
    known_symbol_uris: set[str] | None = None,
) -> str:
    """
    Находит ближайшую внешнюю функцию/компонент/метод из `known_symbol_uris` для привязки вызова.
    Почему проверяется `known_symbol_uris`: вложенные колбэки (`useEffect(() => ...)`, `setTimeout(() => ...)`)
    не являются самостоятельными узлами графа; без подъёма выше вызов получал бы фантомный URI.
    """
    cur = call_node.parent
    while cur is not None:
        cand_uri = ""
        if cur.type == "function_declaration":
            nm = _txt(cur.child_by_field_name("name"), source_bytes).strip()
            if nm:
                cand_uri = build_canonical_uri(scheme, rel_path, nm)
        elif cur.type == "method_definition":
            m_nm = _txt(cur.child_by_field_name("name"), source_bytes).strip()
            if m_nm:
                par = cur.parent
                if par and par.type == "class_body" and par.parent:
                    c_nm = _txt(par.parent.child_by_field_name("name"), source_bytes).strip()
                    cand_uri = build_canonical_uri(scheme, rel_path, f"{c_nm}.{m_nm}" if c_nm else m_nm)
                elif par and par.type == "object" and par.parent and par.parent.type == "variable_declarator":
                    o_nm = _txt(par.parent.child_by_field_name("name"), source_bytes).strip()
                    cand_uri = build_canonical_uri(scheme, rel_path, f"{o_nm}.{m_nm}" if o_nm else m_nm)
                else:
                    cand_uri = build_canonical_uri(scheme, rel_path, m_nm)
        elif cur.type in ("arrow_function", "function_expression", "function") and cur.parent:
            if cur.parent.type == "variable_declarator":
                nm = _txt(cur.parent.child_by_field_name("name"), source_bytes).strip()
                if nm:
                    cand_uri = build_canonical_uri(scheme, rel_path, nm)
            elif (
                cur.parent.type == "arguments"
                and cur.parent.parent
                and cur.parent.parent.type == "call_expression"
                and cur.parent.parent.parent
                and cur.parent.parent.parent.type == "variable_declarator"
            ):
                nm = _txt(cur.parent.parent.parent.child_by_field_name("name"), source_bytes).strip()
                if nm:
                    cand_uri = build_canonical_uri(scheme, rel_path, nm)
            elif (
                cur.parent.type == "pair"
                and cur.parent.parent
                and cur.parent.parent.parent
                and cur.parent.parent.parent.type == "variable_declarator"
            ):
                p_key = _txt(cur.parent.child_by_field_name("key"), source_bytes).strip("\"' ")
                o_nm = _txt(cur.parent.parent.parent.child_by_field_name("name"), source_bytes).strip()
                if o_nm and p_key:
                    cand_uri = build_canonical_uri(scheme, rel_path, f"{o_nm}.{p_key}")

        if cand_uri and (known_symbol_uris is None or cand_uri in known_symbol_uris):
            return cand_uri
        cur = cur.parent
    return file_uri


def flatten_binary_url_arg(arg_node: Node, source_bytes: bytes) -> tuple[str, str]:
    """Превращает конкатенацию строк URL (`API_BASE_URL + '/items/' + id`) в шаблон для BridgeLinker."""
    raw = _txt(arg_node, source_bytes).strip()
    if arg_node.type != "binary_expression" or "/" not in raw:
        return raw, arg_node.type
    parts: list[str] = []

    def _walk(n: Node) -> None:
        if n.type == "binary_expression" and "+" in _txt(n, source_bytes):
            children = _named(n)
            if len(children) == 2:
                _walk(children[0])
                _walk(children[1])
                return
        txt = _txt(n, source_bytes).strip()
        if n.type in ("string", "template_string"):
            parts.append(txt.strip("\"'`"))
        else:
            parts.append(f"${{{txt}}}")

    _walk(arg_node)
    joined = "".join(parts)
    return (f"`{joined}`", "template_string") if "/" in joined else (raw, arg_node.type)


def scan_js_call_expressions(
    root: Node,
    file_uri: str,
    scheme: str,
    rel_path: str,
    source_bytes: bytes,
    out_imports: list[str],
    out_calls: list[tuple[str, str]],
    out_call_sites: list[dict[str, Any]],
    known_symbol_uris: set[str] | None = None,
) -> bool:
    """Обходит вызовы функций в файле, маскируя инлайн-секреты для AST-кэша и возвращая флаг их обнаружения."""
    found_secret = False
    stack: list[Node] = [root]
    while stack:
        cur = stack.pop()
        if cur.type == "call_expression":
            fn_node = cur.child_by_field_name("function")
            args_node = cur.child_by_field_name("arguments")
            raw_callee = _txt(fn_node, source_bytes).strip()
            callee_txt, callee_sec = redact_inline_secrets(raw_callee)
            if callee_sec:
                found_secret = True
            caller_uri = find_enclosing_js_function_uri(
                cur, file_uri, scheme, rel_path, source_bytes, known_symbol_uris
            )

            if callee_txt and len(callee_txt) <= 120:
                out_calls.append((caller_uri, callee_txt))

            arg_nodes = _named(args_node)
            arg_texts: list[str] = []
            for a in arg_nodes:
                at_raw = _txt(a, source_bytes).strip()
                _, arg_sec = redact_inline_secrets(at_raw)
                if arg_sec:
                    found_secret = True
                arg_texts.append(at_raw)

            if raw_callee == "require" and arg_texts:
                req_mod, req_sec = redact_inline_secrets(arg_texts[0].strip("\"'` "))
                if req_sec:
                    found_secret = True
                if req_mod:
                    out_imports.append(req_mod)

            if arg_nodes:
                raw_first, first_type = flatten_binary_url_arg(arg_nodes[0], source_bytes)
                first_raw, first_sec = redact_inline_secrets(raw_first)
                if first_sec:
                    found_secret = True
                method_hint = ""
                if len(arg_texts) >= 2:
                    m_match = re.search(r"""method\s*:\s*['"]([A-Za-z]+)['"]""", arg_texts[1])
                    if m_match:
                        method_hint = m_match.group(1).upper()
                out_call_sites.append(
                    {
                        "caller_uri": caller_uri,
                        "file_uri": file_uri,
                        "callee": callee_txt,
                        "first_arg_raw": first_raw,
                        "first_arg_type": first_type,
                        "method_hint": method_hint,
                        "line": cur.start_point.row + 1,
                    }
                )
        stack.extend(_named(cur))
    return found_secret
