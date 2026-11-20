"""
Вспомогательные функции разбора контрактов данных (`@dataclass` / Pydantic / TS),
аннотаций типов (`type_refs`) и внутриязыкового разрешения вызовов (`CALLS`).

Почему модуль вынесен ниже парсеров и `scanner.py`:
1. Удерживает парсеры и `scanner.py <= 350` строк при строгом DAG без циклов (`GR-LGRAPH-CYCLES`).
2. Изолирует разрешение `CALLS` строго внутри одного языка (`py -> py`, `ts/js -> ts/js`).
3. Строит внутриязыковые рёбра `CALLS` (`VERIFIED`, `type_annotation <Name>`) без создания `USES_CONTRACT`.
"""

from __future__ import annotations

import re
from typing import Any

from tree_sitter import Node

from backend.core.models import (
    ConfidenceTier,
    EdgeType,
    GraphEdgeRecord,
    compute_text_hash,
    redact_inline_secrets,
)

_DATACLASS_DEC_RE = re.compile(r"^@(?:[A-Za-z_][A-Za-z0-9_]*\.)?dataclass(?:\s*\(|\s*$)")
_FORWARD_REF_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
_PY_CONTRACT_BASES: tuple[str, ...] = ("BaseModel", "SQLModel", "TypedDict", "BaseSettings")

_PY_IGNORED_TYPES: frozenset[str] = frozenset(
    "int str float bool bytes bytearray dict list set tuple frozenset object type None Any Optional "
    "Union Literal Annotated Sequence Mapping MutableMapping Iterable Iterator Callable Coroutine "
    "Awaitable Final ClassVar Self Generic TypeVar Protocol NamedTuple TypedDict BaseModel SQLModel "
    "BaseSettings Path UUID Decimal datetime date time timedelta Request Response BackgroundTasks "
    "Depends Query Body Header Cookie Form File UploadFile HTTPException WebSocket APIRouter FastAPI "
    "Exception BaseException".split()
)
_TS_IGNORED_TYPES: frozenset[str] = frozenset(
    "Promise Array ReadonlyArray Record Partial Required Readonly Pick Omit Exclude Extract NonNullable "
    "ReturnType Parameters Awaited Map Set WeakMap WeakSet Date RegExp Error Function Object String "
    "Number Boolean Symbol BigInt Uint8Array ArrayBuffer Blob File FormData Headers Request Response "
    "URL URLSearchParams ReactNode ReactElement FC FunctionComponent JSX HTMLElement Event MouseEvent "
    "ChangeEvent FormEvent KeyboardEvent RefObject MutableRefObject Dispatch SetStateAction "
    "CSSProperties unknown any void never".split()
)


def _txt(node: Node | None, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace") if node else ""


def _named(node: Node | None) -> list[Node]:
    """Безопасный обход дочерних узлов в обход C-дефекта `.named_children` в tree-sitter 0.26."""
    if node is None or node.child_count == 0:
        return []
    return [c for c in node.children if c.is_named]


def uri_lang_family(uri: str) -> str:
    """Возвращает языковое семейство URI (`py` или `js_ts`) для строгой изоляции `CALLS`."""
    scheme = uri.split("://", 1)[0].lower() if "://" in uri else ""
    if scheme == "py":
        return "py"
    return "js_ts" if scheme in ("ts", "js") else scheme


def is_dataclass_decorator(dec_text: str) -> bool:
    """Распознаёт `@dataclass` и `@dataclasses.dataclass(...)`."""
    return bool(_DATACLASS_DEC_RE.match(dec_text.strip()))


def _dedupe(items: list[str], exclude: str = "") -> list[str]:
    seen: set[str] = set()
    return [x for x in items if x and x != exclude and not (x in seen or seen.add(x))]


def _collect_py_type_refs(root: Node | None, source_bytes: bytes, out: list[str]) -> None:
    if root is None:
        return
    stack: list[Node] = [root]
    while stack:
        cur = stack.pop()
        if cur.type == "attribute":
            full = _txt(cur, source_bytes).strip()
            if full and full.rsplit(".", 1)[-1] not in _PY_IGNORED_TYPES and _FORWARD_REF_RE.match(full):
                out.append(full)
            continue
        if cur.type == "identifier":
            ident = _txt(cur, source_bytes).strip()
            if ident and ident not in _PY_IGNORED_TYPES:
                out.append(ident)
            continue
        if cur.type == "string":
            raw = _txt(cur, source_bytes).strip().strip("\"'")
            short = raw.rsplit(".", 1)[-1]
            if raw and short not in _PY_IGNORED_TYPES and _FORWARD_REF_RE.match(raw) and short[:1].isupper():
                out.append(raw)
            continue
        sub = _named(cur)
        if sub:
            stack.extend(reversed(sub))


def _collect_ts_type_refs(root: Node | None, source_bytes: bytes, out: list[str]) -> None:
    if root is None:
        return
    stack: list[Node] = [root]
    while stack:
        cur = stack.pop()
        if cur.type == "nested_type_identifier":
            full = _txt(cur, source_bytes).strip()
            if full and full.rsplit(".", 1)[-1] not in _TS_IGNORED_TYPES:
                out.append(full)
            continue
        if cur.type == "type_identifier":
            ident = _txt(cur, source_bytes).strip()
            if ident and ident not in _TS_IGNORED_TYPES:
                out.append(ident)
            continue
        sub = _named(cur)
        if sub:
            stack.extend(reversed(sub))


def build_python_contract_info(
    cls_name: str, super_txt: str, decorators_text: list[str], body_node: Node | None, source_bytes: bytes
) -> tuple[bool, bool, bool, str, str, list[str]]:
    """
    Классифицирует `BaseModel`/`SQLModel`/`TypedDict`/`BaseSettings`/`@dataclass` и включает
    канонические объявления полей (`name: annotation`) в `signature_hash`.
    """
    is_pydantic = any(b in super_txt for b in _PY_CONTRACT_BASES)
    is_dataclass = any(is_dataclass_decorator(d) for d in decorators_text)
    if not (is_pydantic or is_dataclass):
        safe_sig, _ = redact_inline_secrets(f"class {cls_name}{super_txt}")
        return False, False, False, safe_sig[:240], compute_text_hash(safe_sig), []

    fields_decl: list[str] = []
    field_refs: list[str] = []
    for stmt in _named(body_node):
        if stmt.type != "expression_statement":
            continue
        kids = _named(stmt)
        if not kids or kids[0].type != "assignment":
            continue
        left, type_node = kids[0].child_by_field_name("left"), kids[0].child_by_field_name("type")
        if left is None or left.type != "identifier" or type_node is None:
            continue
        fname = _txt(left, source_bytes).strip()
        ftype = " ".join(_txt(type_node, source_bytes).split())
        if not fname or not ftype or ftype.startswith(("ClassVar", "typing.ClassVar")):
            continue
        fields_decl.append(f"{fname}: {ftype}")
        _collect_py_type_refs(type_node, source_bytes, field_refs)

    header = f"{'@dataclass ' if is_dataclass else ''}class {cls_name}{super_txt}"
    raw_full = f"{header} {{ {'; '.join(fields_decl)} }}" if fields_decl else header
    safe_full, _ = redact_inline_secrets(raw_full)
    return True, is_pydantic, is_dataclass, safe_full[:240], compute_text_hash(safe_full), _dedupe(field_refs, cls_name)


def _extract_fn_param_and_return_refs(
    fn_node: Node, source_bytes: bytes, param_ann_type: str, collector: Any
) -> list[str]:
    refs: list[str] = []
    params_node = fn_node.child_by_field_name("parameters")
    if params_node is not None:
        stack = _named(params_node)
        while stack:
            cur = stack.pop()
            if cur.type == param_ann_type:
                collector(cur, source_bytes, refs)
                continue
            sub = _named(cur)
            if sub:
                stack.extend(reversed(sub))
    collector(fn_node.child_by_field_name("return_type"), source_bytes, refs)
    return _dedupe(refs)


def extract_python_fn_type_refs(fn_node: Node, source_bytes: bytes) -> list[str]:
    """Извлекает ссылки на типы из параметров и типа возврата Python-функции."""
    return _extract_fn_param_and_return_refs(fn_node, source_bytes, "type", _collect_py_type_refs)


def extract_ts_fn_type_refs(fn_node: Node, source_bytes: bytes) -> list[str]:
    """Извлекает ссылки на типы из параметров и возвращаемого типа TS-функции (`Promise<OrderSummary>`)."""
    return _extract_fn_param_and_return_refs(fn_node, source_bytes, "type_annotation", _collect_ts_type_refs)


def extract_ts_type_decl_refs(decl_node: Node, self_name: str, source_bytes: bytes) -> list[str]:
    """Извлекает ссылки на вложенные типы внутри TS `interface` или `type`."""
    refs: list[str] = []
    _collect_ts_type_refs(decl_node.child_by_field_name("body") or decl_node.child_by_field_name("value"), source_bytes, refs)
    return _dedupe(refs, self_name)


def extract_ts_symbol_imports(
    import_stmt: Node, imp_spec: str, source_bytes: bytes, out_symbol_imports: dict[str, str]
) -> None:
    """Извлекает карту импортированных символов TS/JS (`local_name -> '<spec>:<orig_symbol>'`)."""
    if not imp_spec:
        return
    for ch in _named(import_stmt):
        if ch.type != "import_clause":
            continue
        for item in _named(ch):
            if item.type == "identifier":
                local = _txt(item, source_bytes).strip()
                if local:
                    out_symbol_imports[local] = f"{imp_spec}:default"
            elif item.type == "namespace_import":
                for sub in _named(item):
                    if sub.type == "identifier":
                        ns = _txt(sub, source_bytes).strip()
                        if ns:
                            out_symbol_imports[ns] = f"{imp_spec}:"
            elif item.type == "named_imports":
                for spec in _named(item):
                    if spec.type != "import_specifier":
                        continue
                    orig = _txt(spec.child_by_field_name("name"), source_bytes).strip()
                    local = _txt(spec.child_by_field_name("alias"), source_bytes).strip() or orig
                    if orig and local:
                        out_symbol_imports[local] = f"{imp_spec}:{orig}"


def build_imported_files_index(code_edges: list[GraphEdgeRecord]) -> dict[str, set[str]]:
    """Строит карту `src_file_uri -> {dst_file_uri, ...}` по рёбрам `IMPORTS`."""
    imported_by_src: dict[str, set[str]] = {}
    for edge in code_edges:
        if edge.edge_type == EdgeType.IMPORTS:
            imported_by_src.setdefault(edge.src_uri, set()).add(edge.dst_uri)
    return imported_by_src


def _resolve_alias_name(raw_name: str, sym_imports: dict[str, str]) -> str:
    if "." not in raw_name:
        origin = sym_imports.get(raw_name, "")
        if ":" in origin:
            orig = origin.split(":", 1)[1].strip()
            if orig and orig != "default":
                return orig
    return raw_name.rsplit(".", 1)[-1]


def resolve_intra_language_calls(
    pending_calls: list[tuple[str, str]],
    symbol_uris_by_lang_name: dict[tuple[str, str], list[str]],
    symbol_uris_by_lang_qualname: dict[tuple[str, str], list[str]],
    imported_files_by_src: dict[str, set[str]],
    symbol_imports_by_file: dict[str, dict[str, str]],
    out_edges: list[GraphEdgeRecord],
) -> None:
    """
    Разрешает `CALLS` строго внутри одного языкового семейства (`py -> py`, `js/ts -> js/ts`),
    отдавая приоритет символам того же файла и импортированных модулей.
    """
    seen: set[tuple[str, str, str]] = set()
    for caller_uri, raw_callee in pending_calls:
        lang = uri_lang_family(caller_uri)
        caller_file = caller_uri.split("#", 1)[0]
        caller_rel = caller_file.split("://", 1)[-1] if "://" in caller_file else caller_file
        sym_imps = symbol_imports_by_file.get(caller_rel, {})
        imported_files = imported_files_by_src.get(caller_file, set())

        qual_cands = [u for u in symbol_uris_by_lang_qualname.get((lang, raw_callee), []) if u != caller_uri]
        target_name = _resolve_alias_name(raw_callee, sym_imps)
        cands = qual_cands or [u for u in symbol_uris_by_lang_name.get((lang, target_name), []) if u != caller_uri]
        if not cands:
            continue

        same_file = [u for u in cands if u.split("#", 1)[0] == caller_file]
        if len(same_file) > 1 and raw_callee.startswith(("self.", "cls.", "this.")) and "#" in caller_uri:
            caller_sym = caller_uri.split("#", 1)[1]
            if "." in caller_sym:
                scoped = [u for u in same_file if u.endswith(f"#{caller_sym.split('.', 1)[0]}.{target_name}")]
                if scoped:
                    same_file = scoped

        chosen, tier, conf = [], ConfidenceTier.HEURISTIC, 0.6
        if same_file:
            if len(same_file) == 1:
                chosen, tier, conf = same_file, ConfidenceTier.VERIFIED, 0.92
            elif len(same_file) <= 3:
                chosen, conf = same_file, 0.65
        else:
            imp_cands = [u for u in cands if u.split("#", 1)[0] in imported_files]
            if imp_cands:
                if len(imp_cands) == 1:
                    chosen, tier, conf = imp_cands, ConfidenceTier.VERIFIED, 0.92
                elif len(imp_cands) <= 3:
                    chosen, conf = imp_cands, 0.65
            elif 1 <= len(cands) <= 3:
                chosen, conf = cands, (0.85 if len(cands) == 1 else 0.6)

        ev = f"calls `{raw_callee}`"
        for dst_u in chosen:
            if (caller_uri, dst_u, ev) not in seen:
                seen.add((caller_uri, dst_u, ev))
                out_edges.append(
                    GraphEdgeRecord(
                        src_uri=caller_uri, dst_uri=dst_u, edge_type=EdgeType.CALLS,
                        confidence=conf, confidence_tier=tier, evidence=ev,
                    )
                )


def resolve_type_annotation_edges(
    pending_type_refs: list[tuple[str, str]],
    type_uris_by_lang_name: dict[tuple[str, str], list[str]],
    imported_files_by_src: dict[str, set[str]],
    symbol_imports_by_file: dict[str, dict[str, str]],
    out_edges: list[GraphEdgeRecord],
) -> None:
    """
    Разрешает внутриязыковые `type_refs` в рёбра `CALLS` (`VERIFIED`, `confidence=0.95`).
    Инвариант Golden-тестов: НИКОГДА не создаёт `EdgeType.USES_CONTRACT`.
    """
    seen: set[tuple[str, str]] = set()
    for owner_uri, raw_type_name in pending_type_refs:
        lang = uri_lang_family(owner_uri)
        owner_file = owner_uri.split("#", 1)[0]
        owner_rel = owner_file.split("://", 1)[-1] if "://" in owner_file else owner_file
        target_name = _resolve_alias_name(raw_type_name, symbol_imports_by_file.get(owner_rel, {}))
        cands = [u for u in type_uris_by_lang_name.get((lang, target_name), []) if u != owner_uri]
        if not cands:
            continue

        same_file = [u for u in cands if u.split("#", 1)[0] == owner_file]
        imp_cands = [u for u in cands if u.split("#", 1)[0] in imported_files_by_src.get(owner_file, set())]
        chosen = same_file or imp_cands or (cands if len(cands) == 1 else [])
        ev = f"type_annotation {target_name}"
        for dst_u in chosen:
            if (owner_uri, dst_u) not in seen:
                seen.add((owner_uri, dst_u))
                out_edges.append(
                    GraphEdgeRecord(
                        src_uri=owner_uri, dst_uri=dst_u, edge_type=EdgeType.CALLS,
                        confidence=0.95, confidence_tier=ConfidenceTier.VERIFIED, evidence=ev,
                    )
                )
