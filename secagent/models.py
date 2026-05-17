"""Все DTO-модели проекта SecAgent."""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class CodeFile(BaseModel):
    """Исходный файл, загруженный с диска."""

    path: Path
    language: str
    content: str
    size_bytes: int


class CodeChunk(BaseModel):
    """Семантический фрагмент кода (функция, класс и т.д.)."""

    file_path: Path
    language: str
    chunk_type: Literal["function", "method", "class", "module"]
    name: str
    code: str
    line_start: int
    line_end: int


class KnowledgeChunk(BaseModel):
    """Фрагмент базы знаний из CWE / OWASP / Semgrep."""

    source: Literal["cwe", "owasp", "semgrep"]
    cwe_id: str | None = None
    title: str
    text: str
    examples: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class Finding(BaseModel):
    """Найденная уязвимость."""

    cwe_id: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    line_start: int
    line_end: int
    code_snippet: str = ""
    recommendation: str
    confidence: float = Field(ge=0.0, le=1.0)
    file_path: Path

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        """Привести severity к нижнему регистру."""
        return v.lower()