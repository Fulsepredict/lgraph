"""
Хранилище архитектурных заметок (штампы сигнатур, provenance, TTL) и неблокирующей телеметрии капсулы.

Почему вынесено строго ниже `repository.py` и `queries.py` (DAG: models/schema -> note_telemetry_store):
1. Гарантирует 0 циклических импортов (`GR-LGRAPH-CYCLES`) и компактность файлов (`<= 350` строк).
2. Read-only телеметрия (`record_capsule_pack`, `record_capsule_read`) буферизуется в памяти под
   `threading.Lock` за `< 0.05 мс` без write-lock на `lgraph.sqlite3`; персистентный сброс идёт
   best-effort в отдельный файл `*_telemetry.sqlite3`.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections import OrderedDict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from backend.core.models import redact_inline_secrets, sanitize_untrusted_doc_tags
from backend.storage.schema import begin_immediate_transaction, open_sqlite_connection, utc_now_iso

ALLOWED_NOTE_PROVENANCE: frozenset[str] = frozenset({"human", "agent", "auto"})
ALLOWED_NOTE_RISK_LEVELS: frozenset[str] = frozenset({"", "low", "medium", "critical"})
MAX_NOTE_SUMMARY_CHARS: int = 2000
MAX_NOTE_TTL_DAYS: int = 3650
MAX_TELEMETRY_BUFFER_ENTRIES: int = 256

_TELEMETRY_SCHEMA_DDL: str = (
    "CREATE TABLE IF NOT EXISTS capsule_telemetry ("
    "project_id TEXT NOT NULL, task_key TEXT NOT NULL, index_revision INTEGER NOT NULL DEFAULT 0, "
    "packed_uris_json TEXT NOT NULL DEFAULT '[]', omitted_uris_json TEXT NOT NULL DEFAULT '[]', "
    "read_uris_json TEXT NOT NULL DEFAULT '[]', edited_uris_json TEXT NOT NULL DEFAULT '[]', "
    "edit_recall REAL NOT NULL DEFAULT 0.0, edited_but_omitted_json TEXT NOT NULL DEFAULT '[]', "
    "updated_at_iso TEXT NOT NULL DEFAULT '', PRIMARY KEY (project_id, task_key));"
)

_TELEMETRY_LOCK = threading.Lock()
_TELEMETRY_BUFFER: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()


def _get_field(row: Any, key: str, default: Any = None) -> Any:
    if row is None:
        return default
    if isinstance(row, dict):
        return row.get(key, default)
    if isinstance(row, sqlite3.Row):
        return row[key] if key in row.keys() else default
    return getattr(row, key, default)


def normalize_note_target_uri(target_uri: str) -> str:
    """Канонизирует устаревшую схему `domain://<x>` в `c3://domain/<x>`, оставляя остальные URI без изменений."""
    cleaned = str(target_uri or "").strip()
    if cleaned.lower().startswith("domain://"):
        tail = cleaned[9:].lstrip("/")
        if tail:
            return f"c3://domain/{tail}"
    return cleaned


def sanitize_note_summary(summary_ru: str, max_len: int = MAX_NOTE_SUMMARY_CHARS) -> str:
    """Маскирует секреты, вырезает теги `<untrusted_code_doc>`, схлопывает переносы строк и обрезает до `max_len`."""
    if not summary_ru:
        return ""
    redacted, _ = redact_inline_secrets(summary_ru)
    collapsed = " ".join(sanitize_untrusted_doc_tags(redacted).split())
    return collapsed[:max_len].rstrip() if (max_len > 0 and len(collapsed) > max_len) else collapsed


def evaluate_note_staleness(note_row: Any, node_row: Any, now_utc: datetime | None = None) -> tuple[bool, str]:
    """Проверяет устаревание заметки: `target_deleted`, `signature_changed` или `ttl_expired`."""
    if node_row is None:
        return True, "target_deleted"

    note_sig = str(_get_field(note_row, "target_signature_hash", "") or "").strip()
    node_sig = str(_get_field(node_row, "signature_hash", "") or "").strip()
    if note_sig and node_sig and note_sig != node_sig:
        return True, "signature_changed"

    ttl_days = int(_get_field(note_row, "ttl_days", 0) or 0)
    if ttl_days > 0:
        updated_iso = str(_get_field(note_row, "updated_at_iso", "") or "").strip()
        if updated_iso:
            try:
                updated_dt = datetime.fromisoformat(updated_iso)
            except ValueError:
                return False, ""
            if updated_dt.tzinfo is None:
                updated_dt = updated_dt.replace(tzinfo=timezone.utc)
            ref_now = now_utc if now_utc is not None else datetime.now(timezone.utc)
            if ref_now.tzinfo is None:
                ref_now = ref_now.replace(tzinfo=timezone.utc)
            if ref_now >= updated_dt + timedelta(days=ttl_days):
                return True, "ttl_expired"
    return False, ""


def save_architectural_note_record(
    db_path: Path, project_id: str, target_uri: str, summary_ru: str,
    risk_level: str = "", provenance: str = "human", ttl_days: int = 0,
) -> None:
    """Валидирует, санитизирует и атомарно сохраняет заметку со штампами сигнатуры и ревизии."""
    raw_stripped = str(target_uri or "").strip()
    norm_uri = normalize_note_target_uri(raw_stripped)
    if not norm_uri:
        raise ValueError("Параметр target_uri не может быть пустым.")
    clean_risk = str(risk_level or "").strip().lower()
    if clean_risk not in ALLOWED_NOTE_RISK_LEVELS:
        raise ValueError("Параметр risk_level должен быть одним из: '', 'low', 'medium', 'critical'.")
    clean_prov = str(provenance or "").strip().lower()
    if clean_prov not in ALLOWED_NOTE_PROVENANCE:
        raise ValueError("Параметр provenance должен быть одним из: 'human', 'agent', 'auto'.")
    if isinstance(ttl_days, bool) or not isinstance(ttl_days, int) or ttl_days < 0 or ttl_days > MAX_NOTE_TTL_DAYS:
        raise ValueError(f"Параметр ttl_days должен быть целым числом в диапазоне 0..{MAX_NOTE_TTL_DAYS}.")

    clean_summary, now_iso = sanitize_note_summary(summary_ru, max_len=MAX_NOTE_SUMMARY_CHARS), utc_now_iso()
    with closing(open_sqlite_connection(db_path)) as conn:
        with begin_immediate_transaction(conn):
            existing = conn.execute(
                "SELECT risk_level FROM architectural_notes WHERE project_id = ? AND target_uri = ?",
                (project_id, norm_uri),
            ).fetchone()
            effective_risk = clean_risk or (str(existing["risk_level"]) if existing else "")
            node_row = conn.execute(
                "SELECT signature_hash, body_hash FROM nodes WHERE project_id = ? AND uri = ?",
                (project_id, norm_uri),
            ).fetchone()
            sig_hash = str(node_row["signature_hash"]) if node_row else ""
            body_hash = str(node_row["body_hash"]) if node_row else ""
            proj_row = conn.execute(
                "SELECT index_revision FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
            saved_rev = int(proj_row["index_revision"]) if proj_row else 0

            if not clean_summary and not effective_risk:
                conn.execute(
                    "DELETE FROM architectural_notes WHERE project_id = ? AND target_uri = ?", (project_id, norm_uri)
                )
            else:
                conn.execute(
                    "INSERT OR REPLACE INTO architectural_notes ("
                    "project_id, target_uri, summary_ru, risk_level, updated_at_iso, "
                    "target_signature_hash, target_body_hash, saved_revision, provenance, ttl_days"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (project_id, norm_uri, clean_summary, effective_risk, now_iso,
                     sig_hash, body_hash, saved_rev, clean_prov, ttl_days),
                )
            if raw_stripped and raw_stripped != norm_uri:
                conn.execute(
                    "DELETE FROM architectural_notes WHERE project_id = ? AND target_uri = ?",
                    (project_id, raw_stripped),
                )
            conn.execute("UPDATE nodes SET summary_ru = ? WHERE project_id = ? AND uri = ?", (clean_summary, project_id, norm_uri))
            conn.execute("UPDATE nodes_fts SET summary_ru = ? WHERE project_id = ? AND uri = ?", (clean_summary, project_id, norm_uri))
            if clean_risk:
                conn.execute("UPDATE nodes SET risk_level = ? WHERE project_id = ? AND uri = ?", (clean_risk, project_id, norm_uri))


def list_architectural_notes_enriched(db_path: Path, project_id: str) -> list[dict[str, Any]]:
    """Возвращает непустые заметки по приоритету `critical -> medium -> low` с флагами устаревания."""
    now_utc = datetime.now(timezone.utc)
    with closing(open_sqlite_connection(db_path)) as conn:
        rows = conn.execute(
            "SELECT a.target_uri, a.summary_ru, a.risk_level AS note_risk_level, a.updated_at_iso, "
            "a.target_signature_hash, a.target_body_hash, a.saved_revision, a.provenance, a.ttl_days, "
            "n.uri AS matched_node_uri, n.name AS node_name, n.rel_path AS node_rel_path, "
            "n.node_type AS node_type_val, COALESCE(n.c4_level, 4) AS c4_level, "
            "n.signature_hash AS node_signature_hash, n.body_hash AS node_body_hash "
            "FROM architectural_notes a LEFT JOIN nodes n ON n.project_id = a.project_id AND n.uri = ("
            "CASE WHEN LOWER(a.target_uri) LIKE 'domain://%' AND LENGTH(LTRIM(SUBSTR(a.target_uri, 10), '/')) > 0 "
            "THEN 'c3://domain/' || LTRIM(SUBSTR(a.target_uri, 10), '/') ELSE a.target_uri END) "
            "WHERE a.project_id = ? AND a.summary_ru != '' "
            "ORDER BY CASE COALESCE(NULLIF(a.risk_level, ''), n.risk_level, '') WHEN 'critical' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, "
            "c4_level ASC, a.updated_at_iso DESC",
            (project_id,),
        ).fetchall()

    result: list[dict[str, Any]] = []
    for r in rows:
        norm_uri = normalize_note_target_uri(str(r["target_uri"]))
        node_ctx = (
            {"signature_hash": str(r["node_signature_hash"] or ""), "body_hash": str(r["node_body_hash"] or "")}
            if r["matched_node_uri"] is not None else None
        )
        is_stale, stale_reason = evaluate_note_staleness(r, node_ctx, now_utc=now_utc)
        result.append(
            {
                "target_uri": norm_uri, "summary_ru": str(r["summary_ru"]),
                "note_risk_level": str(r["note_risk_level"]), "updated_at_iso": str(r["updated_at_iso"]),
                "name": str(r["node_name"]) if r["node_name"] is not None else norm_uri,
                "rel_path": str(r["node_rel_path"]) if r["node_rel_path"] is not None else "",
                "node_type": str(r["node_type_val"]) if r["node_type_val"] is not None else "Note",
                "c4_level": int(r["c4_level"]), "provenance": str(r["provenance"] or "human"),
                "saved_revision": int(r["saved_revision"] or 0), "ttl_days": int(r["ttl_days"] or 0),
                "is_stale": is_stale, "stale_reason": stale_reason,
            }
        )
    return result


def get_telemetry_db_path(db_path: Path) -> Path:
    """Возвращает путь к отдельной SQLite БД телеметрии (`*_telemetry.sqlite3`)."""
    return db_path.with_name(f"{db_path.stem}_telemetry.sqlite3")


def _buffer_key(db_path: Path, project_id: str, task_key: str) -> tuple[str, str, str]:
    # Используем normcase(abspath) вместо resolve() для 0 файловых системных вызовов (< 0.05 мс)
    return (os.path.normcase(os.path.abspath(str(db_path))), project_id, str(task_key or "").strip() or "default")


def _get_or_create_entry_locked(key: tuple[str, str, str]) -> dict[str, Any]:
    entry = _TELEMETRY_BUFFER.get(key)
    if entry is None:
        entry = {"index_revision": 0, "packed_uris": set(), "omitted_uris": set(),
                 "read_uris": set(), "edited_uris": set(), "updated_at_iso": ""}
        _TELEMETRY_BUFFER[key] = entry
        while len(_TELEMETRY_BUFFER) > MAX_TELEMETRY_BUFFER_ENTRIES:
            _TELEMETRY_BUFFER.popitem(last=False)
    else:
        _TELEMETRY_BUFFER.move_to_end(key)
    return entry


def _clean_uri_set(uris: list[str]) -> set[str]:
    return {str(u).strip() for u in (uris or []) if str(u).strip()}


def _uri_to_rel_path(uri_or_path: str) -> str:
    text = uri_or_path.strip().replace("\\", "/")
    return (text.split("://", 1)[1] if "://" in text else text).split("#", 1)[0].strip("/")


def _score_capsule(packed_set: set[str], omitted_set: set[str], edited_set: set[str]) -> tuple[float, list[str]]:
    packed_rels = {_uri_to_rel_path(u) for u in packed_set if _uri_to_rel_path(u)}
    omitted_rels = {_uri_to_rel_path(u) for u in omitted_set if _uri_to_rel_path(u)}

    def _matches(item: str, uris: set[str], rels: set[str]) -> bool:
        if item in uris:
            return True
        if "#" in item:
            return False
        rp = _uri_to_rel_path(item)
        return bool(rp) and rp in rels

    hits, edited_but_omitted = 0, []
    for ed in sorted(edited_set):
        if _matches(ed, packed_set, packed_rels):
            hits += 1
        elif _matches(ed, omitted_set, omitted_rels):
            edited_but_omitted.append(ed)
    return (round(hits / len(edited_set), 4) if edited_set else 0.0), edited_but_omitted


def record_capsule_pack(
    db_path: Path, project_id: str, index_revision: int, packed_uris: list[str], omitted_uris: list[str], task_key: str = ""
) -> None:
    """Буферизует выданные и опущенные URI капсулы строго в памяти (0 блокировок SQLite, `< 0.05 мс`)."""
    key = _buffer_key(db_path, project_id, task_key)
    clean_packed, clean_omitted, now_iso = _clean_uri_set(packed_uris), _clean_uri_set(omitted_uris), utc_now_iso()
    with _TELEMETRY_LOCK:
        entry = _get_or_create_entry_locked(key)
        entry["index_revision"] = int(index_revision)
        entry["packed_uris"].update(clean_packed)
        entry["omitted_uris"].update(clean_omitted)
        entry["omitted_uris"].difference_update(entry["packed_uris"])
        entry["updated_at_iso"] = now_iso


def record_capsule_read(db_path: Path, project_id: str, read_uris: list[str], task_key: str = "") -> None:
    """Буферизует прочитанные агентом URI строго в памяти (0 блокировок SQLite, `< 0.05 мс`)."""
    key = _buffer_key(db_path, project_id, task_key)
    clean_read, now_iso = _clean_uri_set(read_uris), utc_now_iso()
    with _TELEMETRY_LOCK:
        entry = _get_or_create_entry_locked(key)
        entry["read_uris"].update(clean_read)
        entry["updated_at_iso"] = now_iso


def record_capsule_edits_and_score(
    db_path: Path, project_id: str, edited_uris: list[str], task_key: str = ""
) -> dict[str, Any]:
    """Считает `edit_recall` и best-effort атомарно объединяет/сохраняет запись в `*_telemetry.sqlite3`."""
    key = _buffer_key(db_path, project_id, task_key)
    effective_key, clean_edited, now_iso = key[2], _clean_uri_set(edited_uris), utc_now_iso()
    with _TELEMETRY_LOCK:
        entry = _get_or_create_entry_locked(key)
        entry["edited_uris"].update(clean_edited)
        entry["updated_at_iso"] = now_iso
        index_rev = int(entry["index_revision"])
        packed_set, omitted_set = set(entry["packed_uris"]), set(entry["omitted_uris"])
        read_set, edited_set = set(entry["read_uris"]), set(entry["edited_uris"])

    edit_recall, edited_but_omitted = _score_capsule(packed_set, omitted_set, edited_set)
    try:
        with closing(open_sqlite_connection(get_telemetry_db_path(db_path))) as conn:
            conn.executescript(_TELEMETRY_SCHEMA_DDL)
            with begin_immediate_transaction(conn):
                row = conn.execute(
                    "SELECT index_revision, packed_uris_json, omitted_uris_json, read_uris_json, edited_uris_json "
                    "FROM capsule_telemetry WHERE project_id = ? AND task_key = ?",
                    (project_id, effective_key),
                ).fetchone()
                if row:
                    index_rev = max(index_rev, int(row["index_revision"] or 0))
                    packed_set.update(_clean_uri_set(json.loads(row["packed_uris_json"] or "[]")))
                    omitted_set.update(_clean_uri_set(json.loads(row["omitted_uris_json"] or "[]")))
                    omitted_set.difference_update(packed_set)
                    read_set.update(_clean_uri_set(json.loads(row["read_uris_json"] or "[]")))
                    edited_set.update(_clean_uri_set(json.loads(row["edited_uris_json"] or "[]")))
                edit_recall, edited_but_omitted = _score_capsule(packed_set, omitted_set, edited_set)
                conn.execute(
                    "INSERT OR REPLACE INTO capsule_telemetry ("
                    "project_id, task_key, index_revision, packed_uris_json, omitted_uris_json, "
                    "read_uris_json, edited_uris_json, edit_recall, edited_but_omitted_json, updated_at_iso"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (project_id, effective_key, index_rev,
                     json.dumps(sorted(packed_set), ensure_ascii=False),
                     json.dumps(sorted(omitted_set), ensure_ascii=False),
                     json.dumps(sorted(read_set), ensure_ascii=False),
                     json.dumps(sorted(edited_set), ensure_ascii=False),
                     edit_recall, json.dumps(edited_but_omitted, ensure_ascii=False), now_iso),
                )
    except Exception:
        pass

    with _TELEMETRY_LOCK:
        entry = _get_or_create_entry_locked(key)
        entry["index_revision"] = max(int(entry["index_revision"]), index_rev)
        entry["packed_uris"].update(packed_set)
        entry["omitted_uris"].update(omitted_set)
        entry["omitted_uris"].difference_update(entry["packed_uris"])
        entry["read_uris"].update(read_set)
        entry["edited_uris"].update(edited_set)
        entry["updated_at_iso"] = max(str(entry["updated_at_iso"]), now_iso)
    return {
        "task_key": effective_key, "packed_count": len(packed_set), "read_count": len(read_set),
        "edited_count": len(edited_set), "edit_recall": edit_recall, "edited_but_omitted_uris": edited_but_omitted,
    }
