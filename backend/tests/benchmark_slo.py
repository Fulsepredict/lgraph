"""
Инструментальный замер целевых показателей производительности (Target SLO Benchmark).

Почему все стенды работают в полной изоляции (`tempfile.TemporaryDirectory`):
1. Честно замеряются `Cold Index`, `Warm SHA-256 Cache (p50/p95)`, `ContextPack (p50/p95)` и `Peak RAM`.
2. Крупный полигон `Bench-M (120 файлов)` генерируется во временной папке, поэтому бенчмарк
   гарантированно не трогает соседние открытые проекты пользователя на диске.
"""

from __future__ import annotations

import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from backend.analyzers.code_graph.scanner import index_project_directory
from backend.context_pack.builder import build_context_pack_markdown
from backend.storage.queries import GraphQueryService
from backend.storage.repository import GraphRepository


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return round(ordered[idx], 2)


def _create_synthetic_bench_m_project(root: Path, domain_count: int = 30) -> None:
    """Генерирует реалистичный 120-файловый полиглот-проект (FastAPI + React/TS + IPC) в Temp."""
    (root / "lgraph.yaml").write_text(
        "bridge_adapters:\n  http_wrappers:\n    - caller_name: 'benchFetch'\n      prepend_prefix: '/api'\n",
        encoding="utf-8",
    )
    main_lines = ["from fastapi import FastAPI"]
    include_lines = ["app = FastAPI()"]

    for i in range(domain_count):
        mod = f"domain_{i:02d}"
        py_dir = root / "backend" / mod
        py_dir.mkdir(parents=True, exist_ok=True)
        (py_dir / "service.py").write_text(
            f"def compute_{mod}(item_id: int) -> dict:\n    return {{'id': item_id, 'domain': '{mod}'}}\n",
            encoding="utf-8",
        )
        (py_dir / "routes.py").write_text(
            f"from fastapi import APIRouter\nfrom pydantic import BaseModel\n"
            f"from backend.{mod}.service import compute_{mod}\n\n"
            f"router = APIRouter()\n\n"
            f"class Contract_{mod}(BaseModel):\n    id: int\n    domain: str\n\n"
            f"@router.post('/{{item_id}}/sync')\n"
            f"async def sync_{mod}(item_id: int) -> Contract_{mod}:\n"
            f"    return compute_{mod}(item_id)\n",
            encoding="utf-8",
        )
        main_lines.append(f"from backend.{mod}.routes import router as r_{i}")
        include_lines.append(f"app.include_router(r_{i}, prefix='/api/{mod}')")

        ts_dir = root / "frontend" / "src" / mod
        ts_dir.mkdir(parents=True, exist_ok=True)
        (ts_dir / "api.ts").write_text(
            f"export interface Contract_{mod} {{ id: number; domain: string; }}\n"
            f"export async function benchFetch(p: string, o?: unknown) {{ return fetch(p); }}\n"
            f"export async function triggerSync_{mod}(id: number): Promise<Contract_{mod}> {{\n"
            f"  const r = await benchFetch(`/{mod}/${{id}}/sync`, {{ method: 'POST' }});\n"
            f"  return r.json();\n"
            f"}}\n",
            encoding="utf-8",
        )
        (ts_dir / "View.tsx").write_text(
            f"import {{ triggerSync_{mod} }} from './api';\n"
            f"export function View_{mod}() {{ return <div onClick={{() => triggerSync_{mod}(1)}}>{mod}</div>; }}\n",
            encoding="utf-8",
        )

    (root / "backend" / "main.py").write_text("\n".join(main_lines + [""] + include_lines), encoding="utf-8")


def benchmark_single_target(label: str, target_dir: Path, warm_runs: int = 5) -> dict[str, object]:
    tracemalloc.start()
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "bench.sqlite3"
        repo = GraphRepository(db_path)
        queries = GraphQueryService(db_path)

        t0 = time.perf_counter()
        cold = index_project_directory(target_dir, repo)
        cold_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        warm_times: list[float] = []
        pack_times: list[float] = []
        for _ in range(warm_runs):
            tw = time.perf_counter()
            index_project_directory(target_dir, repo)
            warm_times.append((time.perf_counter() - tw) * 1000.0)

            tp = time.perf_counter()
            build_context_pack_markdown(cold["project_id"], queries, ["api", "sync"], token_budget=2500)
            pack_times.append((time.perf_counter() - tp) * 1000.0)

        _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "label": label,
        "files": cold["parsed_files"],
        "nodes": cold["total_nodes"],
        "edges": cold["total_edges"],
        "cold_ms": cold_ms,
        "warm_p50_ms": round(statistics.median(warm_times), 2),
        "warm_p95_ms": _percentile(warm_times, 95),
        "pack_p50_ms": round(statistics.median(pack_times), 2),
        "pack_p95_ms": _percentile(pack_times, 95),
        "peak_ram_mb": round(peak_bytes / (1024 * 1024), 2),
    }


def main() -> None:
    print("\n# Lgraph v2.4 — Empirical SLO Benchmark Report\n")
    print("| Полигон | Файлов | Узлов | Связей | Cold Index (ms) | Warm Cache p50/p95 (ms) | ContextPack p50/p95 (ms) | Peak Python RAM (MB) |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|")

    fixed_targets: list[tuple[str, Path]] = [
        ("Bench-S (Fixture: electron_ipc_gateway)", PROJECT_ROOT / "fixtures" / "electron_ipc_gateway"),
        ("Bench-Self (Lgraph Full Codebase)", PROJECT_ROOT),
    ]
    for label, path in fixed_targets:
        res = benchmark_single_target(label, path)
        print(
            f"| {res['label']} | {res['files']} | {res['nodes']} | {res['edges']} | "
            f"{res['cold_ms']} | {res['warm_p50_ms']} / {res['warm_p95_ms']} | "
            f"{res['pack_p50_ms']} / {res['pack_p95_ms']} | {res['peak_ram_mb']} |"
        )

    with tempfile.TemporaryDirectory() as synth_dir:
        synth_path = Path(synth_dir)
        _create_synthetic_bench_m_project(synth_path, domain_count=30)
        res_m = benchmark_single_target("Bench-M (Isolated 122-file Polyglot Stand)", synth_path)
        print(
            f"| {res_m['label']} | {res_m['files']} | {res_m['nodes']} | {res_m['edges']} | "
            f"{res_m['cold_ms']} | {res_m['warm_p50_ms']} / {res_m['warm_p95_ms']} | "
            f"{res_m['pack_p50_ms']} / {res_m['pack_p95_ms']} | {res_m['peak_ram_mb']} |"
        )


if __name__ == "__main__":
    import traceback

    try:
        main()
    except Exception:
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)
