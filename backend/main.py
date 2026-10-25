from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from database import init_db, SessionLocal
from models import HealthResponse
from modules.auth_module import seed_admin_if_needed
from routers.auth import router as auth_router
from routers.admin import router as admin_router
from routers.network import router as network_router
from routers.repo import router as repo_router
from routers.telegram import router as telegram_router
from routers.report import router as report_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    init_db()
    
    # Seed initial system administrator if configured
    db = SessionLocal()
    try:
        seed_admin_if_needed(db)
    finally:
        db.close()
    
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="Cybersecurity inspection backend for normal people. Plain-English account and infrastructure forensics.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS configuration allowing frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(network_router)
app.include_router(repo_router)
app.include_router(telegram_router)
app.include_router(report_router)


# ---------------------------------------------------------------------------
# Health & Root Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health", response_model=HealthResponse, tags=["System Health"])
async def health_check() -> HealthResponse:
    """Returns the operational status of the API."""
    return HealthResponse(
        status="ok",
        version="2.0.0",
        environment=settings.ENVIRONMENT,
    )


@app.get("/api/status", tags=["System Health"])
async def get_status_stub():
    """Stub endpoint returning minimal status with zero credentials or setup requirements."""
    return {"status": "ok"}


@app.get("/", tags=["System Health"], include_in_schema=False)
async def root():
    return {
        "service": settings.APP_NAME,
        "tagline": "Find out if you were hacked, and how.",
        "documentation": "/docs",
        "health": "/api/health",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
