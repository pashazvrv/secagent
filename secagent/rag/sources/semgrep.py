"""
Парсер Semgrep Rules.

Источник: https://github.com/semgrep/semgrep-rules

Стратегия:
  - Обходим все .yml / .yaml файлы в репозитории.
  - Каждый файл может содержать несколько rules (ключ `rules:`).
  - Берём только правила, у которых есть metadata.cwe или metadata.cwe2022-top25.
  - Одно правило → один KnowledgeChunk.

Что извлекаем:
  - pattern / patterns / pattern-either — примеры уязвимого кода
  - message — объяснение уязвимости
  - metadata.cwe — CWE-ID
  - metadata.languages / languages — список языков
  - metadata.severity — уровень серьёзности
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from secagent.models import KnowledgeChunk

logger = logging.getLogger(__name__)

# Языки Semgrep → canonical-имена SecAgent
_LANG_MAP: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "go": "go",
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "ruby": "ruby",
    "php": "php",
    "kotlin": "kotlin",
    "swift": "swift",
    "rust": "rust",
    "scala": "scala",
    "generic": "",  # generic-правила пропускаем
}

_SUPPORTED = {"python", "javascript", "typescript", "java", "go", "c", "cpp"}

# Нормализация CWE-ID из Semgrep: "CWE-89: SQL Injection" → "CWE-89"
_CWE_RE = re.compile(r"(CWE-\d+)", re.I)


def _normalize_cwe(raw: Any) -> str | None:
    """
    Нормализует CWE из метаданных Semgrep.
    Может быть строкой "CWE-89: SQL Injection", списком, числом, None.
    """
    if raw is None:
        return None
    if isinstance(raw, list):
        # Берём первый элемент
        raw = raw[0] if raw else None
    if not isinstance(raw, str):
        raw = str(raw)
    
    # Сначала ищем "CWE-XXX" в строке (например, "CWE-89: SQL Injection")
    m = _CWE_RE.search(raw)
    if m:
        return m.group(1).upper()
    
    # Если не нашли, может быть просто число "89"?
    if raw.isdigit():
        return f"CWE-{raw}"
    
    return None


def _extract_languages(rule: dict) -> list[str]:
    """Извлекает список поддерживаемых языков из правила."""
    raw_langs = rule.get("languages", [])
    if isinstance(raw_langs, str):
        raw_langs = [raw_langs]
    langs: set[str] = set()
    for lang in raw_langs:
        canonical = _LANG_MAP.get(lang.lower(), "")
        if canonical and canonical in _SUPPORTED:
            langs.add(canonical)
    return sorted(langs)


def _extract_pattern_text(rule: dict) -> str:
    """
    Достаёт паттерн из правила в виде строки.
    Поддерживает: pattern, patterns, pattern-either.
    """
    if "pattern" in rule:
        return str(rule["pattern"])

    if "pattern-either" in rule:
        items = rule["pattern-either"]
        if isinstance(items, list):
            parts = []
            for item in items[:3]:  # не более 3
                if isinstance(item, dict):
                    p = item.get("pattern", item.get("pattern-regex", ""))
                    if p:
                        parts.append(str(p))
            return "\n".join(parts)

    if "patterns" in rule:
        items = rule["patterns"]
        if isinstance(items, list):
            parts = []
            for item in items[:3]:
                if isinstance(item, dict):
                    p = item.get("pattern", "")
                    if p:
                        parts.append(str(p))
            return "\n".join(parts)

    return ""


def _build_chunk_text(message: str, pattern: str, severity: str) -> str:
    """Формирует финальный текст чанка."""
    parts = []
    if message:
        parts.append(f"Description: {message[:600]}")
    if severity:
        parts.append(f"Severity: {severity}")
    if pattern:
        parts.append(f"Vulnerable pattern:\n{pattern[:400]}")
    return "\n\n".join(parts)[:2000]


def _parse_yaml_file(yaml_path: Path) -> list[KnowledgeChunk]:
    """Парсит один YAML-файл Semgrep и возвращает список чанков."""
    try:
        content = yaml_path.read_text(encoding="utf-8", errors="replace")
        data = yaml.safe_load(content)
    except Exception as e:
        logger.debug("Ошибка парсинга %s: %s", yaml_path, e)
        return []

    if not isinstance(data, dict):
        return []

    rules = data.get("rules", [])
    if not isinstance(rules, list):
        return []

    chunks: list[KnowledgeChunk] = []

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        metadata = rule.get("metadata", {}) or {}

        # Нужен CWE — иначе пропускаем
        raw_cwe = metadata.get("cwe") or metadata.get("cwe2022-top25")
        cwe_id = _normalize_cwe(raw_cwe)
        if not cwe_id:
            continue

        languages = _extract_languages(rule)
        # Если нет поддерживаемых языков — пропускаем
        # (generic/regex-правила не полезны без языковой привязки)
        if not languages:
            continue

        rule_id = rule.get("id", yaml_path.stem)
        message = str(rule.get("message", "")).strip()
        severity = str(metadata.get("severity", rule.get("severity", ""))).lower()
        pattern = _extract_pattern_text(rule)

        text = _build_chunk_text(message, pattern, severity)
        if not text.strip():
            continue

        examples = [pattern] if pattern else []

        chunk = KnowledgeChunk(
            source="semgrep",
            cwe_id=cwe_id,
            title=f"Semgrep: {rule_id}",
            text=text,
            examples=examples,
            languages=languages,
            metadata={
                "source": "semgrep",
                "cwe_id": cwe_id,
                "rule_id": rule_id,
                "severity_hint": severity or "medium",
                "languages": languages,
                "file": str(yaml_path),
            },
        )
        chunks.append(chunk)

    return chunks


def parse_semgrep_rules(semgrep_dir: Path) -> list[KnowledgeChunk]:
    """
    Рекурсивно обходит репозиторий Semgrep Rules и создаёт KnowledgeChunk
    для каждого правила с CWE-привязкой.

    Args:
        semgrep_dir: Путь к корню клонированного semgrep-rules репозитория.

    Returns:
        Список KnowledgeChunk.
    """
    if not semgrep_dir.exists():
        logger.warning("Semgrep rules dir не найден: %s", semgrep_dir)
        return []

    yaml_files = list(semgrep_dir.rglob("*.yml")) + list(semgrep_dir.rglob("*.yaml"))
    logger.info("Semgrep: найдено %d YAML файлов", len(yaml_files))

    chunks: list[KnowledgeChunk] = []
    for yaml_path in yaml_files:
        # Пропускаем тестовые файлы Semgrep.
        # Проверяем только части пути ОТНОСИТЕЛЬНО semgrep_dir,
        # чтобы не зацепить системные папки вроде pytest-temp/test_xxx/
        relative_parts = yaml_path.relative_to(semgrep_dir).parts
        if any(part.startswith("test") for part in relative_parts):
            continue
        file_chunks = _parse_yaml_file(yaml_path)
        chunks.extend(file_chunks)

    logger.info("Semgrep: создано %d чанков", len(chunks))
    return chunks