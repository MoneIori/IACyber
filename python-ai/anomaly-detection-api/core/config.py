from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    internal_token: str = "iacyber-internal-dev-token"
    model_path: str = "models/isolation_forest.joblib"
    log_level: str = "INFO"
    port: int = 9001

    class Config:
        env_file = ".env"


settings = Settings()
