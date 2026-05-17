"""Централизованные настройки через pydantic-settings."""

import logging
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Настройки SecAgent. Переопределяются через ENV с префиксом SECAGENT_."""

    model_config = SettingsConfigDict(env_prefix="SECAGENT_", env_file=".env")

    # Ollama
    ollama_host: str = "http://localhost:11434"
    llm_model: str = "qwen2.5-coder:7b"
    embedding_model: str = "nomic-embed-text"
    llm_temperature: float = 0.1
    llm_seed: int = 42
    llm_max_tokens: int = 2048

    # RAG
    chroma_path: Path = Path("./data/chroma")
    collection_name: str = "security_knowledge"
    retrieval_top_k: int = 5

    # Парсинг
    max_chunk_lines: int = 200
    supported_languages: list[str] = [
        "python", "javascript", "typescript",
        "java", "go", "c", "cpp",
    ]

    # Валидация
    cwe_ids_path: Path = Path("./data/cwe_ids.json")
    min_confidence: float = 0.5

    # Логирование
    log_level: str = "INFO"


def setup_logging(level: str = "INFO") -> None:
    """Настроить корневой логгер."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# Глобальный синглтон — импортируй отовсюду
settings = Settings()