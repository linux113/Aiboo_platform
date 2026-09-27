import logging
import os
from dataclasses import dataclass


@dataclass
class AgentConfig:
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8001"))
    api_key: str = os.getenv("AGENT_API_KEY", "dev-key-change-in-production")
    internal_key: str = os.getenv("INTERNAL_API_KEY", "internal-dev-key")
    backend_url: str = os.getenv("NODE_BACKEND", "http://localhost:4000")
    backend_email: str = os.getenv("BACKEND_EMAIL", "admin@example.com")
    backend_password: str = os.getenv("BACKEND_PASSWORD", "admin123")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    db_type: str = os.getenv("DB_TYPE", "memory")
    db_url: str = os.getenv("DATABASE_URL", "")
    event_ttl: int = int(os.getenv("EVENT_TTL_SECONDS", "3600"))
    max_dict_size: int = int(os.getenv("MAX_DICT_SIZE", "10000"))
    request_timeout: int = int(os.getenv("REQUEST_TIMEOUT", "30"))
    llm_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    llm_model: str = os.getenv("LLM_MODEL", "claude-3-haiku-20240307")
    rate_limit: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))


config = AgentConfig()

if config.api_key == "dev-key-change-in-production":
    logging.warning(
        "AGENT_API_KEY is set to the development default 'dev-key-change-in-production' — "
        "CHANGE IT in production!"
    )
if config.internal_key == "internal-dev-key":
    logging.warning(
        "INTERNAL_API_KEY is set to the development default 'internal-dev-key' — "
        "CHANGE IT in production!"
    )
