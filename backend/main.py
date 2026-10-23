from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from models import HealthResponse
from routers.network import router as network_router
from routers.repo import router as repo_router
from routers.telegram import router as telegram_router
from routers.report import router as report_router

app = FastAPI(
    title=settings.APP_NAME,
    description="Cybersecurity inspection backend for normal people. Plain-English account and infrastructure forensics.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
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
        version="1.0.0",
        environment=settings.ENVIRONMENT,
    )


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
