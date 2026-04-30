from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    internal_token: str = "iacyber-internal-dev-token"
    model_path: str = "models/mitre_classifier.joblib"
    log_level: str = "INFO"
    port: int = 9002

    class Config:
        env_file = ".env"


settings = Settings()
