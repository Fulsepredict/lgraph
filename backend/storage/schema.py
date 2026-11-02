"""
Схема базы данных SQLite для хранения графа архитектуры, кэша SHA-256 и заметок.

Почему выбрана связка SQLite WAL + двусторонние покрывающие индексы + FTS5:
1. Режим WAL позволяет окну UI и нескольким MCP-агентам читать граф одновременно
   с фоновой переиндексацией без ошибок `database is locked`.
2. Два зеркальных индекса на таблице `edges` (`src -> dst` и `dst -> src`) дают
   обход входящих и исходящих зависимостей за единицы миллисекунд без сканирования таблицы.
3. Отдельная таблица `architectural_notes` хранит паспорта модулей отдельно от узлов AST,
   поэтому пересборка файла никогда не стирает человеческие и агентские описания.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

SCHEMA_DDL: str = """
CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    root_path TEXT NOT NULL UNIQUE,
    index_revision INTEGER NOT NULL DEFAULT 0,
    indexed_at_iso TEXT NOT NULL DEFAULT '',
    is_stale INTEGER NOT NULL DEFAULT 0,
    config_mtime_ns INTEGER NOT NULL DEFAULT 0,
    config_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS file_cache (
    project_id TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    mtime_ns INTEGER NOT NULL DEFAULT 0,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    line_count INTEGER NOT NULL DEFAULT 0,
    language TEXT NOT NULL DEFAULT '',
    has_redacted_secret INTEGER NOT NULL DEFAULT 0,
    cached_payload_json TEXT NOT NULL DEFAULT '{}',
    updated_at_iso TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, rel_path)
);

CREATE TABLE IF NOT EXISTS nodes (
    project_id TEXT NOT NULL,
    uri TEXT NOT NULL,
    node_type TEXT NOT NULL,
    name TEXT NOT NULL,
    rel_path TEXT NOT NULL DEFAULT '',
    start_line INTEGER NOT NULL DEFAULT 0,
    end_line INTEGER NOT NULL DEFAULT 0,
    c4_level INTEGER NOT NULL DEFAULT 4,
    risk_level TEXT NOT NULL DEFAULT 'low',
    signature TEXT NOT NULL DEFAULT '',
    signature_hash TEXT NOT NULL DEFAULT '',
    body_hash TEXT NOT NULL DEFAULT '',
    summary_ru TEXT NOT NULL DEFAULT '',
    pattern_tag TEXT NOT NULL DEFAULT '',
    parent_uri TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 1.0,
    source_module TEXT NOT NULL DEFAULT 'code_graph',
    meta_json TEXT NOT NULL DEFAULT '{}',
    index_revision INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, uri)
);

CREATE INDEX IF NOT EXISTS ix_nodes_project_c4
    ON nodes(project_id, c4_level, node_type);

CREATE INDEX IF NOT EXISTS ix_nodes_project_file
    ON nodes(project_id, rel_path);

CREATE TABLE IF NOT EXISTS edges (
    project_id TEXT NOT NULL,
    src_uri TEXT NOT NULL,
    dst_uri TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    confidence_tier TEXT NOT NULL DEFAULT 'verified',
    source_module TEXT NOT NULL DEFAULT 'code_graph',
    evidence TEXT NOT NULL DEFAULT '',
    meta_json TEXT NOT NULL DEFAULT '{}',
    index_revision INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, src_uri, dst_uri, edge_type, evidence)
);

CREATE INDEX IF NOT EXISTS ix_edges_outbound
    ON edges(project_id, src_uri, edge_type, dst_uri, confidence);

CREATE INDEX IF NOT EXISTS ix_edges_inbound
    ON edges(project_id, dst_uri, edge_type, src_uri, confidence);

CREATE TABLE IF NOT EXISTS architectural_notes (
    project_id TEXT NOT NULL,
    target_uri TEXT NOT NULL,
    summary_ru TEXT NOT NULL DEFAULT '',
    risk_level TEXT NOT NULL DEFAULT '',
    updated_at_iso TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, target_uri)
);

CREATE TABLE IF NOT EXISTS guardrail_rules (
    project_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    scope TEXT NOT NULL,
    exclude_scope TEXT NOT NULL DEFAULT '',
    predicate_type TEXT NOT NULL,
    predicate_params_json TEXT NOT NULL DEFAULT '{}',
    rationale_ru TEXT NOT NULL,
    remediation_ru TEXT NOT NULL,
    PRIMARY KEY (project_id, rule_id)
);

CREATE VIRTUAL TABLE IF NOT EXISTS nodes_fts USING fts5(
    project_id UNINDEXED,
    uri UNINDEXED,
    name,
    rel_path,
    summary_ru,
    signature
);
"""


def open_sqlite_connection(db_path: Path) -> sqlite3.Connection:
    """
    Открывает соединение SQLite с настройками параллельного чтения WAL.
    Важно для Windows: всегда оборачивать вызов в `with closing(open_sqlite_connection(...))`
    при работе, чтобы файловый дескриптор закрывался сразу после завершения операции.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def _ensure_column_exists(conn: sqlite3.Connection, table_name: str, col_name: str, col_ddl: str) -> None:
    """Безопасно добавляет новую колонку в уже существующую БД пользователя без потери заметок."""
    existing = {str(r["name"]) for r in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}
    if col_name not in existing:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_ddl}")


def initialize_database(db_path: Path) -> None:
    """Создаёт таблицы графа и выполняет безопасную авто-миграцию схемы до версии v2.4."""
    with closing(open_sqlite_connection(db_path)) as conn:
        with conn:
            conn.executescript(SCHEMA_DDL)
            _ensure_column_exists(conn, "projects", "config_mtime_ns", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column_exists(conn, "file_cache", "mtime_ns", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column_exists(conn, "file_cache", "size_bytes", "INTEGER NOT NULL DEFAULT 0")
