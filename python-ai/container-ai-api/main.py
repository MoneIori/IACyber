from fastapi import FastAPI, Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from contextlib import asynccontextmanager

from core.config import settings
from routers import enrichment, risk_scorer

api_key_header = APIKeyHeader(name="X-Internal-Token", auto_error=True)


def verify_token(token: str = Security(api_key_header)):
    if token != settings.internal_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return token


@asynccontextmanager
async def lifespan(app: FastAPI):
    risk_scorer.load_model()
    yield


app = FastAPI(
    title="IACyber — Container AI API",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(
    enrichment.router,
    prefix="/api/v1/container",
    dependencies=[Security(verify_token)],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "container-ai-api"}
