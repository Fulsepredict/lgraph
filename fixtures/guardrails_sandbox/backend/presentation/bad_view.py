# Нарушает GR-LAYER-01: презентационный слой лезет напрямую в backend.db.engine
from backend.db.engine import connect_raw_sqlite


def render_dashboard() -> str:
    return connect_raw_sqlite()
