"""
Разрешение локальных, относительных и алиасных импортов Python и JS/TS в рёбра графа `IMPORTS`.

Почему здесь поддержаны относительные точки Python (`from ..core import x`) и `@/` алиасы TS:
В реальных проектах на FastAPI и React/Vite половина внутренних связей пишется через относительные
точки (`.`, `..`) или алиас `@/services/api`. Без их точного разрешения правила `forbidden_dependency`,
`must_route_via`, поиск циклов и `ImpactEngine` не увидели бы реальных зависимостей между слоями.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from backend.core.config import is_reparse_or_symlink
from backend.core.models import (
    ConfidenceTier,
    EdgeType,
    GraphEdgeRecord,
    normalize_rel_path,
)

_JSONC_COMMENTS_RE = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)


def _strip_jsonc(raw: str) -> str:
    """Аккуратно удаляет комментарии и висящие запятые из `tsconfig.json` / `jsconfig.json`."""
    no_comments = _JSONC_COMMENTS_RE.sub("", raw)
    return re.sub(r",\s*([}\]])", r"\1", no_comments)


def _load_ts_path_aliases(project_root: Path | None) -> list[tuple[str, str]]:
    """
    Извлекает префиксы алиасов из `tsconfig.json` / `jsconfig.json` (например, `@/* -> frontend/src/*`).
    Возвращает список пар `(alias_prefix, target_rel_dir)`.
    """
    if project_root is None:
        return []
    aliases: list[tuple[str, str]] = []
    candidate_dirs = ("", "frontend", "client", "web", "app")
    for sub in candidate_dirs:
        cfg_dir = (project_root / sub) if sub else project_root
        for cfg_name in ("tsconfig.app.json", "tsconfig.json", "jsconfig.json"):
            cfg_path = cfg_dir / cfg_name
            if not cfg_path.is_file() or is_reparse_or_symlink(cfg_path):
                continue
            try:
                parsed = json.loads(_strip_jsonc(cfg_path.read_text(encoding="utf-8", errors="replace")))
            except Exception:
                continue
            compiler_opts = (parsed.get("compilerOptions") or {}) if isinstance(parsed, dict) else {}
            base_url = str(compiler_opts.get("baseUrl") or ".")
            paths_map = compiler_opts.get("paths") or {}
            if not isinstance(paths_map, dict):
                continue
            for pat, targets in paths_map.items():
                if not isinstance(pat, str) or not isinstance(targets, list) or not targets:
                    continue
                alias_pref = pat[:-1] if pat.endswith("*") else pat
                first_target = str(targets[0])
                target_pref = first_target[:-1] if first_target.endswith("*") else first_target
                combined = normalize_rel_path(str((cfg_dir / base_url / target_pref).relative_to(project_root))) if (cfg_dir / base_url / target_pref).is_relative_to(project_root) else ""
                if alias_pref and combined is not None:
                    aliases.append((alias_pref, combined))
    return aliases


def resolve_python_imports(
    pending: list[tuple[str, str, list[str]]],
    file_uri_by_rel: dict[str, str],
    out_edges: list[GraphEdgeRecord],
) -> None:
    """
    Превращает импорты Python (`import a.b`, `from a import b`, `from .sub import c`, `from .. import d`)
    в точные рёбра `IMPORTS` с поддержкой как корневых, так и контейнерных пакетов (`backend/`).
    """
    for src_file_uri, mod_dotted, names in pending:
        src_rel = src_file_uri.split("://", 1)[-1] if "://" in src_file_uri else src_file_uri
        src_parts = [p for p in src_rel.split("/") if p]
        src_dir_parts = src_parts[:-1]

        candidates: list[str] = []
        if mod_dotted.startswith("."):
            dots = len(mod_dotted) - len(mod_dotted.lstrip("."))
            rem = mod_dotted[dots:].replace(".", "/").strip("/")
            up_levels = max(0, dots - 1)
            if up_levels <= len(src_dir_parts):
                anchor = src_dir_parts[: len(src_dir_parts) - up_levels]
                base_parts = anchor + ([rem] if rem else [])
                base_rel = "/".join(base_parts)
                if base_rel:
                    candidates.extend([f"{base_rel}.py", f"{base_rel}/__init__.py"])
                    for nm in names:
                        candidates.extend([f"{base_rel}/{nm}.py", f"{base_rel}/{nm}/__init__.py"])
                else:
                    for nm in names:
                        candidates.extend([f"{nm}.py", f"{nm}/__init__.py"])
        else:
            base_rel = mod_dotted.replace(".", "/").strip("/")
            # 1. Стандартный путь от корня репозитория (`from backend.core import models`)
            prefixes = [base_rel]
            # 2. Фоллбэк на корневую папку контейнера (`from core import models` внутри `backend/api/main.py`)
            if len(src_parts) >= 2 and not base_rel.startswith(src_parts[0] + "/"):
                prefixes.append(f"{src_parts[0]}/{base_rel}")

            for pref in prefixes:
                candidates.extend([f"{pref}.py", f"{pref}/__init__.py"])
                for nm in names:
                    candidates.extend([f"{pref}/{nm}.py", f"{pref}/{nm}/__init__.py"])

        matched_any = False
        seen_dst: set[str] = set()
        for cand in candidates:
            dst_uri = file_uri_by_rel.get(cand)
            if dst_uri and dst_uri != src_file_uri and dst_uri not in seen_dst:
                seen_dst.add(dst_uri)
                matched_any = True
                out_edges.append(
                    GraphEdgeRecord(
                        src_uri=src_file_uri,
                        dst_uri=dst_uri,
                        edge_type=EdgeType.IMPORTS,
                        confidence=1.0,
                        confidence_tier=ConfidenceTier.VERIFIED,
                        evidence=f"import {mod_dotted}",
                    )
                )
        _ = matched_any


def _collapse_dot_segments(raw_path: str) -> str:
    resolved_parts: list[str] = []
    for seg in raw_path.replace("\\", "/").split("/"):
        if seg == "..":
            if resolved_parts:
                resolved_parts.pop()
        elif seg and seg != ".":
            resolved_parts.append(seg)
    return "/".join(resolved_parts)


def resolve_js_ts_imports(
    pending: list[tuple[str, str, str]],
    file_uri_by_rel: dict[str, str],
    out_edges: list[GraphEdgeRecord],
    project_root: Path | None = None,
) -> None:
    """Превращает относительные (`./x`, `../y`) и алиасные (`@/x`, `~/x`) импорты JS/TS в рёбра `IMPORTS`."""
    exts = ("", ".ts", ".tsx", ".js", ".jsx", ".cjs", ".mjs", "/index.ts", "/index.tsx", "/index.js", "/index.jsx")
    ts_aliases = _load_ts_path_aliases(project_root)

    for src_file_uri, importer_rel, imp_spec in pending:
        candidate_bases: list[str] = []

        if imp_spec.startswith("."):
            parent_dir = Path(importer_rel).parent
            candidate_bases.append(_collapse_dot_segments(str(parent_dir / imp_spec)))
        else:
            # Проверяем настроенные алиасы из tsconfig.json
            for alias_pref, target_dir in ts_aliases:
                if imp_spec.startswith(alias_pref):
                    sub_tail = imp_spec[len(alias_pref) :].lstrip("/")
                    joined = f"{target_dir}/{sub_tail}" if target_dir else sub_tail
                    candidate_bases.append(_collapse_dot_segments(joined))

            # Универсальная поддержка стандартных алиасов `@/` и `~/` (Vite / Next.js / React)
            if imp_spec.startswith(("@/", "~/")):
                sub_tail = imp_spec[2:].lstrip("/")
                top_folder = importer_rel.split("/", 1)[0] if "/" in importer_rel else ""
                if top_folder:
                    candidate_bases.append(_collapse_dot_segments(f"{top_folder}/src/{sub_tail}"))
                    candidate_bases.append(_collapse_dot_segments(f"{top_folder}/{sub_tail}"))
                candidate_bases.append(_collapse_dot_segments(f"src/{sub_tail}"))

        if not candidate_bases:
            continue

        resolved = False
        for clean_base in candidate_bases:
            if resolved:
                break
            for sfx in exts:
                dst_uri = file_uri_by_rel.get(clean_base + sfx)
                if dst_uri and dst_uri != src_file_uri:
                    out_edges.append(
                        GraphEdgeRecord(
                            src_uri=src_file_uri,
                            dst_uri=dst_uri,
                            edge_type=EdgeType.IMPORTS,
                            confidence=1.0,
                            confidence_tier=ConfidenceTier.VERIFIED,
                            evidence=f"import '{imp_spec}'",
                        )
                    )
                    resolved = True
                    break
