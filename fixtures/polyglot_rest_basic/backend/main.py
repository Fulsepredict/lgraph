from fastapi import FastAPI
from backend.routes_orders import router as orders_router

app = FastAPI(title="Orders Demo API")
app.include_router(orders_router, prefix="/api/orders")
