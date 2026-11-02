"""
Единая модель данных графа Lgraph, генератор вечных канонических URI и фильтр секретов.

Почему используется Canonical URI вместо числового ID или номера строки:
При добавлении одной пустой строки в начале файла все номера строк смещаются.
Смысловой адрес вида `py://backend/core/session.py#SessionManager.connect` остаётся
неизменным между правками, поэтому заметки человека и правила Guardrails не отклеиваются.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import unquote


class NodeType(StrEnum):
    PROJECT = "Project"
    EXTERNAL_SYSTEM = "ExternalSystem"
    CONTAINER = "Container"
    DOMAIN_MODULE = "DomainModule"
    FILE = "File"
    CLASS = "Class"
    FUNCTION = "Function"
    VARIABLE = "Variable"
    API_ENDPOINT = "APIEndpoint"
    IPC_CHANNEL = "IPCChannel"
    DATA_CONTRACT = "DataContract"
    DATABASE_TABLE = "DatabaseTable"
    CONFIGURATION = "Configuration"
    GUARDRAIL_RULE = "GuardrailRule"
    TEST = "Test"


class EdgeType(StrEnum):
    CONTAINS = "CONTAINS"
    IMPORTS = "IMPORTS"
    CALLS = "CALLS"
    INHERITS = "INHERITS"
    IMPLEMENTS = "IMPLEMENTS"
    BRIDGES_TO = "BRIDGES_TO"
    USES_CONTRACT = "USES_CONTRACT"
    READS_TABLE = "READS_TABLE"
    WRITES_TABLE = "WRITES_TABLE"
    CONFIGURED_BY = "CONFIGURED_BY"
    GOVERNED_BY = "GOVERNED_BY"
    TESTS = "TESTS"
    SENDS_REQUEST_TO = "SENDS_REQUEST_TO"


class RiskLevel(StrEnum):
    LOW = "low"          # Зелёный контур: UI-оформление, простые утилиты
    MEDIUM = "medium"    # Жёлтый контур: бизнес-логика, API-маршруты, состояние
    CRITICAL = "critical"  # Красный контур: секреты, шифрование, прокси, платежи, удаление БД


class ConfidenceTier(StrEnum):
    VERIFIED = "verified"                  # 1.0: точное совпадение контракта или типов
    EXACT = "exact"                        # 1.0: каноническое совпадение маршрута/канала
    PATTERN_MATCHED = "pattern_matched"    # 0.75-0.9: шаблонное совпадение URL с параметрами
    HEURISTIC = "heuristic"                # 0.55-0.7: синтаксическое разрешение без типов
    UNRESOLVED_DYNAMIC = "unresolved_dynamic"  # <0.4: адрес/вызов вычисляется в рантайме


# Регулярные выражения для перехвата случайно захардкоженных в коде секретов, ключей и токенов
_INLINE_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),                         # OpenAI / LLM ключи
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{24,}\b"),                    # GitHub токены
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                              # AWS Access Key ID
    re.compile(r"\b\d{8,11}:[A-Za-z0-9_-]{32,}\b"),                   # Telegram Bot токены
    re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\b"),  # JWT
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),             # PEM ключи
    re.compile(r"(?i)(?:postgres|postgresql|mysql|mongodb|redis|socks5|http|https)://[^/\s:@]+:[^/\s@]+@"),
    re.compile(
        r"""(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|bot[_-]?token|auth[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]"""
    ),
)


def normalize_rel_path(rel_path: str) -> str:
    """Приводит относительный путь к единому кроссплатформенному виду с прямыми слэшами."""
    cleaned = rel_path.replace("\\", "/").strip()
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.strip("/")


def to_project_rel_path(raw_item: str, project_root: Path) -> str:
    """
    Безопасно приводит любой путь от ИИ-агента (абсолютный путь Windows/POSIX, `file:///...`,
    канонический URI `py://...#func` или относительный путь) к каноническому `rel_path` внутри проекта.
    Почему это критично: инструменты IDE передают абсолютные пути (`D:\\proj\\backend\\app.py`),
    и без обрезки корня проекта фильтрация правил давала бы ложно-пустые совпадения.
    Если передан абсолютный путь от ЧУЖОГО проекта вне `project_root` — возвращает пустую строку `""`.
    """
    text = raw_item.strip().strip("\"'` ")
    if not text:
        return ""

    # 1. Ссылки формата `file:///D:/projects/my_app/...#L10-L20`
    if text.lower().startswith("file://"):
        text = unquote(text[7:].split("#", 1)[0])
        if len(text) >= 3 and text[0] == "/" and text[2] == ":":
            text = text[1:]

    # 2. Канонические URI узлов графа (`py://backend/api/main.py#func` и т.п.)
    elif "://" in text:
        scheme, rest = text.split("://", 1)
        if scheme.lower() in ("py", "ts", "js"):
            return normalize_rel_path(rest.split("#", 1)[0])
        return ""

    # Убираем якорь строк/символов (`#L12`, `#my_func`), если агент приписал его к пути файла
    text = text.split("#", 1)[0].replace("\\", "/").rstrip("/")
    if not text:
        return ""

    root_norm = str(project_root.resolve()).replace("\\", "/").rstrip("/")
    is_win_abs = len(text) >= 2 and text[1] == ":"
    is_posix_abs = text.startswith("/") and not text.startswith("//")

    if is_win_abs or is_posix_abs or text.startswith("//"):
        cmp_text = text.lower() if os.name == "nt" else text
        cmp_root = root_norm.lower() if os.name == "nt" else root_norm
        if cmp_text == cmp_root:
            return ""
        if cmp_text.startswith(cmp_root + "/"):
            return normalize_rel_path(text[len(root_norm) + 1 :])
        return ""

    return normalize_rel_path(text)


def build_canonical_uri(scheme: str, rel_path: str, symbol_qualname: str | None = None) -> str:
    """
    Формирует стабильный адрес сущности, например:
    - Файл: `py://backend/api/routes.py`
    - Метод: `py://backend/api/routes.py#AccountRouter.get_profile`
    - Контейнер: `c2://container/backend`
    """
    norm_path = normalize_rel_path(rel_path)
    if symbol_qualname:
        return f"{scheme}://{norm_path}#{symbol_qualname}"
    return f"{scheme}://{norm_path}"


def compute_sha256_bytes(data: bytes) -> str:
    """Возвращает SHA-256 отпечаток байтового содержимого."""
    return hashlib.sha256(data).hexdigest()


def compute_text_hash(text: str) -> str:
    """Нормализует пробелы по краям и считает короткий 16-символьный хэш для сравнения сигнатур/тел."""
    normalized = "\n".join(line.rstrip() for line in text.strip().splitlines())
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def redact_inline_secrets(raw_text: str) -> tuple[str, bool]:
    """
    Маскирует случайно забытые в исходном коде токены, пароли в URL и ключи API.
    Возвращает (безопасный_текст, был_ли_обнаружен_секрет).
    """
    if not raw_text:
        return "", False
    found_secret = False
    sanitized = raw_text
    for pattern in _INLINE_SECRET_PATTERNS:
        if pattern.search(sanitized):
            found_secret = True
            sanitized = pattern.sub("<REDACTED_SECRET>", sanitized)
    return sanitized, found_secret


def wrap_untrusted_code_doc(doc_text: str, max_chars: int = 280) -> str:
    """
    Оборачивает комментарии из чужого кода в изолирующий тег, чтобы защитить AI-агента
    от косвенной Prompt Injection (скрытых команд внутри чужих комментариев).
    """
    clean, _ = redact_inline_secrets(doc_text.strip())
    if not clean:
        return ""
    # Удаляем попытки закрыть наш защитный контейнер изнутри комментария
    clean = clean.replace("</untrusted_code_doc>", "[filtered]").replace("<untrusted_code_doc>", "[filtered]")
    if len(clean) > max_chars:
        clean = clean[: max_chars - 3].rstrip() + "..."
    return f"<untrusted_code_doc>{clean}</untrusted_code_doc>"


@dataclass(slots=True)
class GraphNodeRecord:
    uri: str
    node_type: NodeType
    name: str
    rel_path: str = ""
    start_line: int = 0
    end_line: int = 0
    c4_level: int = 4  # 1: Context, 2: Container, 3: DomainModule, 4: Code (File/Class/Function)
    risk_level: RiskLevel = RiskLevel.LOW
    signature: str = ""
    signature_hash: str = ""
    body_hash: str = ""
    summary_ru: str = ""
    pattern_tag: str = ""
    parent_uri: str = ""
    confidence: float = 1.0
    source_module: str = "code_graph"
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GraphEdgeRecord:
    src_uri: str
    dst_uri: str
    edge_type: EdgeType
    confidence: float = 1.0
    confidence_tier: ConfidenceTier = ConfidenceTier.VERIFIED
    source_module: str = "code_graph"
    evidence: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GuardrailRuleSpec:
    rule_id: str
    title: str
    severity: str  # "blocker" | "warning" | "advisory"
    scope: str     # glob-путь ("frontend/src/components/**") или префикс URI
    predicate_type: str  # "forbidden_dependency" | "must_route_via" | "max_file_lines" | "no_cycles" | "ast_forbidden_regex" | "advisory_only"
    predicate_params: dict[str, Any]
    rationale_ru: str
    remediation_ru: str
    exclude_scope: str = ""


@dataclass(slots=True)
class GuardrailViolation:
    rule_id: str
    title: str
    severity: str
    matched_scope: str
    target_uri_or_path: str
    line_number: int
    evidence: str
    why_violated_ru: str
    how_to_fix_ru: str
