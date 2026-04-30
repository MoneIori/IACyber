from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    internal_token: str = "iacyber-internal-dev-token"
    anthropic_api_key: str = ""
    log_level: str = "INFO"
    port: int = 9006

    class Config:
        env_file = ".env"


settings = Settings()
