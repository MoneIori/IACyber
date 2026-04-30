from fastapi import FastAPI, Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from contextlib import asynccontextmanager

from core.config import settings
from routers import anomaly

api_key_header = APIKeyHeader(name="X-Internal-Token", auto_error=True)


def verify_token(token: str = Security(api_key_header)):
    if token != settings.internal_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid internal token")
    return token


@asynccontextmanager
async def lifespan(app: FastAPI):
    anomaly.load_model()
    yield


app = FastAPI(
    title="IACyber — Anomaly Detection API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.include_router(
    anomaly.router,
    prefix="/api/v1/anomaly",
    dependencies=[Security(verify_token)],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "anomaly-detection-api"}
