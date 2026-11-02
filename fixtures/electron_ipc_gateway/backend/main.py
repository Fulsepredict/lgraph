from fastapi import FastAPI
from backend.routes_profiles import router as profiles_router

app = FastAPI()
app.include_router(profiles_router, prefix="/api/profiles")
