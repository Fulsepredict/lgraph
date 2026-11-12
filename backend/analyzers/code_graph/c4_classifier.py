"""
Классификатор архитектурных уровней C1–C3, светофора рисков и карточек IT-паттернов.

Почему этот модуль ключевой для владельца проекта:
Вместо того чтобы заставлять человека разбираться в сотнях мелких файлов и функций (уровень C4),
этот классификатор автоматически собирает файлы в смысловые районы (C3 — Бизнес-модули)
и здания (C2 — Контейнеры), присваивая каждому блоку понятную роль на русском языке,
индикатор риска (🔴/🟡/🟢) и короткую обучающую карточку архитектурного приёма.
"""

from __future__ import annotations

from backend.core.models import (
    ConfidenceTier,
    EdgeType,
    GraphEdgeRecord,
    GraphNodeRecord,
    NodeType,
    RiskLevel,
    normalize_rel_path,
)

# Справочник архитектурных паттернов простым языком («Учусь IT на своём проекте»)
PATTERN_CARDS_RU: dict[str, tuple[str, str]] = {
    "gateway": (
        "Шлюз / Контракт API (Gateway)",
        "Работает как пропускной пункт на входе в здание: проверяет права запроса и переводит команды между окном интерфейса и сервером.",
    ),
    "orchestrator": (
        "Оркестратор / Планировщик (Orchestrator)",
        "Работает как дирижёр оркестра: управляет очередью фоновых задач и потоков, чтобы они не мешали друг другу и не перегружали систему.",
    ),
    "repository": (
        "Слой хранения и БД (Repository / ORM)",
        "Работает как архивариус с картотекой: отвечает за безопасное чтение, запись и целостность таблиц базы данных на диске.",
    ),
    "security": (
        "Контур защиты и изоляции (Security / Guard)",
        "Работает как бронедверь и сейф: отвечает за шифрование секретов, токены доступа, прокси-изоляцию и проверку прав.",
    ),
    "state_store": (
        "Хранилище состояния экрана (State Store)",
        "Общая оперативная доска объявлений интерфейса: когда данные обновляются здесь, все связанные кнопки и таблицы перерисовываются сами.",
    ),
    "ui_component": (
        "Визуальный модуль интерфейса (UI View)",
        "Отвечает за то, что видит пользователь на экране, и передаёт нажатия кнопок в сервисный слой (не обращаясь к БД напрямую).",
    ),
    "domain_service": (
        "Сервис бизнес-логики (Domain Service)",
        "Выполняет главные рабочие правила продукта, координируя проверки данных, расчёты и вызовы внешних систем.",
    ),
}

_CRITICAL_KEYWORDS: tuple[str, ...] = (
    "security", "auth", "dpapi", "crypto", "secret", "token",
    "proxy", "socks", "session_manager", "ipcgateway", "guard", "ledger",
)
_MEDIUM_KEYWORDS: tuple[str, ...] = (
    "api", "route", "service", "controller", "orchestrator", "autopilot",
    "warmup", "checker", "db", "storage", "repository", "model", "store",
    "linker", "analyzer", "scanner", "parser", "evaluator", "builder", "watcher",
)


def classify_risk_and_pattern(rel_path: str) -> tuple[RiskLevel, str, str]:
    """
    Определяет по пути и назначению модуля:
    1) уровень критичности (🔴 critical / 🟡 medium / 🟢 low),
    2) название архитектурного паттерна,
    3) понятное русскоязычное пояснение роли блока.
    """
    lower = normalize_rel_path(rel_path).lower()

    if any(k in lower for k in ("ipcgateway", "preload", "/api/", "routes_", "api.ts", "mcp_server")):
        pat_title, pat_desc = PATTERN_CARDS_RU["gateway"]
    elif any(k in lower for k in ("orchestrator", "autopilot", "scheduler", "worker", "limiter")):
        pat_title, pat_desc = PATTERN_CARDS_RU["orchestrator"]
    elif any(k in lower for k in ("database", "/db/", "storage", "repository", "models.py", "schema")):
        pat_title, pat_desc = PATTERN_CARDS_RU["repository"]
    elif any(k in lower for k in ("security", "dpapi", "auth", "proxy", "guard", "crypto")):
        pat_title, pat_desc = PATTERN_CARDS_RU["security"]
    elif any(k in lower for k in ("/store/", "zustand", "context")):
        pat_title, pat_desc = PATTERN_CARDS_RU["state_store"]
    elif any(k in lower for k in ("components/", "views/", ".tsx", ".jsx")):
        pat_title, pat_desc = PATTERN_CARDS_RU["ui_component"]
    else:
        pat_title, pat_desc = PATTERN_CARDS_RU["domain_service"]

    if any(k in lower for k in _CRITICAL_KEYWORDS):
        risk = RiskLevel.CRITICAL
    elif any(k in lower for k in _MEDIUM_KEYWORDS):
        risk = RiskLevel.MEDIUM
    else:
        risk = RiskLevel.LOW

    return risk, pat_title, pat_desc


def resolve_container_and_domain(rel_path: str) -> tuple[tuple[str, str], tuple[str, str]]:
    """
    Сопоставляет путь файла с Контейнером (Уровень C2) и Бизнес-модулем (Уровень C3).
    Возвращает ((container_uri, container_title), (domain_uri, domain_title)).
    """
    norm = normalize_rel_path(rel_path)
    parts = [p for p in norm.split("/") if p]

    if not parts:
        return ("c2://container/root", "Корневой контур"), ("c3://domain/root", "Корневые файлы")

    top = parts[0].lower()
    second = parts[1].lower() if len(parts) > 1 else "root"

    if top == "frontend":
        if second == "electron":
            c2 = ("c2://container/desktop_shell", "Десктоп-оболочка и IPC (Electron)")
            c3 = ("c3://domain/frontend/electron", "Мост окон и безопасности (Electron Main/IPC)")
            return c2, c3
        c2 = ("c2://container/frontend_ui", "Клиентский интерфейс (React / TS)")
        if second == "src" and len(parts) > 2:
            sub = parts[2]
            if sub == "components" and len(parts) > 3 and "." not in parts[3]:
                comp_group = parts[3]
                return c2, (f"c3://domain/frontend/components/{comp_group.lower()}", f"Экран: {comp_group}")
            stem = sub.rsplit(".", 1)[0]
            return c2, (f"c3://domain/frontend/{stem.lower()}", f"Фронтенд: {stem}")
        return c2, ("c3://domain/frontend/core", "Конфигурация фронтенда")

    if top == "backend":
        c2 = ("c2://container/backend_core", "Серверное ядро (Python / FastAPI)")
        if len(parts) == 2:
            return c2, ("c3://domain/backend/entry", "Точка запуска сервера")
        if second == "analyzers" and len(parts) > 2 and "." not in parts[2]:
            an_name = parts[2]
            return c2, (f"c3://domain/backend/analyzers/{an_name}", f"Анализатор: {an_name}")
        return c2, (f"c3://domain/backend/{second}", f"Бэкенд-модуль: {second}")

    if top in ("tests", "independent_auditor"):
        c2 = ("c2://container/quality_gate", "Контур тестирования и аудита")
        return c2, (f"c3://domain/{top}", f"Проверки: {top}")

    c2 = (f"c2://container/{top}", f"Контейнер: {parts[0]}")
    dom_key = second.rsplit(".", 1)[0] if len(parts) > 1 else top
    return c2, (f"c3://domain/{top}/{dom_key}", f"Модуль: {parts[0]}/{dom_key}")


def build_c1_to_c3_hierarchy_and_rollups(
    project_name: str,
    file_nodes: list[GraphNodeRecord],
    code_edges: list[GraphEdgeRecord],
    file_to_domain: dict[str, str],
    domain_to_container: dict[str, str],
    containers_meta: dict[str, str],
    domains_meta: dict[str, tuple[str, str]],
) -> tuple[list[GraphNodeRecord], list[GraphEdgeRecord]]:
    """
    Строит верхние уровни карты (C1 -> C2 -> C3) и агрегирует связи файлов
    в чистые стрелки между Бизнес-модулями (C3) и Контейнерами (C2).
    """
    extra_nodes: list[GraphNodeRecord] = []
    extra_edges: list[GraphEdgeRecord] = []

    proj_uri = "c1://project/self"
    extra_nodes.append(
        GraphNodeRecord(
            uri=proj_uri,
            node_type=NodeType.PROJECT,
            name=project_name,
            c4_level=1,
            risk_level=RiskLevel.MEDIUM,
            summary_ru=f"Целевая программная система «{project_name}» целиком (вид сверху).",
            pattern_tag="Система целиком (C1 System Context)",
        )
    )

    for c2_uri, c2_title in containers_meta.items():
        risk, pat_title, pat_desc = classify_risk_and_pattern(c2_uri)
        extra_nodes.append(
            GraphNodeRecord(
                uri=c2_uri,
                node_type=NodeType.CONTAINER,
                name=c2_title,
                c4_level=2,
                risk_level=risk,
                summary_ru=pat_desc,
                pattern_tag=pat_title,
                parent_uri=proj_uri,
            )
        )
        extra_edges.append(
            GraphEdgeRecord(src_uri=proj_uri, dst_uri=c2_uri, edge_type=EdgeType.CONTAINS)
        )

    # Рассчитываем максимальный риск файлов внутри каждого бизнес-модуля C3
    domain_risk_rank: dict[str, RiskLevel] = {}
    rank_order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.CRITICAL: 2}
    for fnode in file_nodes:
        d_uri = file_to_domain.get(fnode.uri)
        if d_uri:
            cur = domain_risk_rank.get(d_uri, RiskLevel.LOW)
            if rank_order[fnode.risk_level] > rank_order[cur]:
                domain_risk_rank[d_uri] = fnode.risk_level

    for d_uri, (d_title, sample_rel_path) in domains_meta.items():
        c2_uri = domain_to_container[d_uri]
        norm_sample = normalize_rel_path(sample_rel_path)
        inferred_risk, pat_title, pat_desc = classify_risk_and_pattern(norm_sample)
        effective_risk = domain_risk_rank.get(d_uri, inferred_risk)
        has_subdir = "/" in norm_sample
        c3_rel = norm_sample.rsplit("/", 1)[0] if has_subdir else norm_sample
        extra_nodes.append(
            GraphNodeRecord(
                uri=d_uri,
                node_type=NodeType.DOMAIN_MODULE,
                name=d_title,
                rel_path=c3_rel,
                c4_level=3,
                risk_level=effective_risk,
                summary_ru=pat_desc,
                pattern_tag=pat_title,
                parent_uri=c2_uri,
                meta={"target_kind": "directory" if has_subdir else "file"},
            )
        )
        extra_edges.append(
            GraphEdgeRecord(src_uri=c2_uri, dst_uri=d_uri, edge_type=EdgeType.CONTAINS)
        )

    # Поднимаем связи уровня кода (IMPORTS / CALLS / BRIDGES_TO) на уровень модулей C3 и контейнеров C2
    seen_rollup_pairs: set[tuple[str, str, EdgeType]] = set()
    for edge in code_edges:
        if edge.edge_type not in (EdgeType.IMPORTS, EdgeType.BRIDGES_TO, EdgeType.CALLS):
            continue
        src_file = edge.src_uri.split("#", 1)[0]
        dst_file = edge.dst_uri.split("#", 1)[0]
        d_src = file_to_domain.get(src_file)
        d_dst = file_to_domain.get(dst_file)
        if not d_src or not d_dst or d_src == d_dst:
            continue
        rollup_type = EdgeType.BRIDGES_TO if edge.edge_type == EdgeType.BRIDGES_TO else EdgeType.IMPORTS
        key_c3 = (d_src, d_dst, rollup_type)
        if key_c3 not in seen_rollup_pairs:
            seen_rollup_pairs.add(key_c3)
            extra_edges.append(
                GraphEdgeRecord(
                    src_uri=d_src,
                    dst_uri=d_dst,
                    edge_type=rollup_type,
                    confidence=edge.confidence,
                    confidence_tier=ConfidenceTier.VERIFIED if rollup_type == EdgeType.IMPORTS else edge.confidence_tier,
                    source_module="c4_rollup",
                    evidence=edge.evidence or f"{src_file} -> {dst_file}",
                )
            )
        c2_src = domain_to_container.get(d_src)
        c2_dst = domain_to_container.get(d_dst)
        if c2_src and c2_dst and c2_src != c2_dst:
            key_c2 = (c2_src, c2_dst, rollup_type)
            if key_c2 not in seen_rollup_pairs:
                seen_rollup_pairs.add(key_c2)
                extra_edges.append(
                    GraphEdgeRecord(
                        src_uri=c2_src,
                        dst_uri=c2_dst,
                        edge_type=rollup_type,
                        confidence=edge.confidence,
                        confidence_tier=edge.confidence_tier,
                        source_module="c4_rollup",
                        evidence=edge.evidence or f"{d_src} -> {d_dst}",
                    )
                )

    return extra_nodes, extra_edges
