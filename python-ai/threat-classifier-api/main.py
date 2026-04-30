from fastapi import FastAPI, Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from contextlib import asynccontextmanager

from core.config import settings
from routers import classify

api_key_header = APIKeyHeader(name="X-Internal-Token", auto_error=True)


def verify_token(token: str = Security(api_key_header)):
    if token != settings.internal_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid internal token")
    return token


@asynccontextmanager
async def lifespan(app: FastAPI):
    classify.load_model()
    yield


app = FastAPI(
    title="IACyber — Threat Classifier API",
    version="1.0.0",
    description="Classifica eventi nelle tattiche/tecniche MITRE ATT&CK for Containers usando XGBoost.",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.include_router(
    classify.router,
    prefix="/api/v1/classify",
    dependencies=[Security(verify_token)],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "threat-classifier-api"}
