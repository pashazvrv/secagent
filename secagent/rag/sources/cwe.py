"""
Парсер CWE XML от MITRE.

Источник: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip

Что извлекаем из каждой <Weakness>:
  - ID, Name
  - Description (Extended_Description)
  - Demonstrative_Examples — примеры кода
  - Potential_Mitigations — рекомендации
  - Applicable_Platforms — языки (для фильтра в Chroma)

Формат возврата: list[KnowledgeChunk] + множество всех валидных CWE-ID.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from lxml import etree

from secagent.models import KnowledgeChunk

logger = logging.getLogger(__name__)

# Namespace в CWE XML
_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}

# Языки из <Language Name="..."> → наши canonical-названия
_LANG_MAP: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "go": "go",
    "c": "c",
    "c++": "cpp",
    "c#": "csharp",
    "php": "php",
    "ruby": "ruby",
    "rust": "rust",
    "swift": "swift",
    "kotlin": "kotlin",
}

# Языки, для которых SecAgent умеет анализировать код
_SUPPORTED = set(_LANG_MAP.values())


def _text(el: etree._Element | None) -> str:
    """Рекурсивно достаёт текст из элемента, убирает лишние пробелы."""
    if el is None:
        return ""
    parts = []
    if el.text:
        parts.append(el.text.strip())
    for child in el:
        t = _text(child)
        if t:
            parts.append(t)
        if child.tail:
            parts.append(child.tail.strip())
    return " ".join(p for p in parts if p)


def _extract_languages(weakness: etree._Element) -> list[str]:
    """Возвращает canonical-имена языков из <Applicable_Platforms>."""
    langs: list[str] = []
    for lang_el in weakness.findall(".//cwe:Language", _NS):
        name = (lang_el.get("Name") or "").lower()
        canonical = _LANG_MAP.get(name)
        if canonical and canonical in _SUPPORTED:
            langs.append(canonical)
    # Нет платформы → применимо ко всем
    return sorted(set(langs)) or ["python", "java", "javascript", "go", "c", "cpp"]


def _extract_examples(weakness: etree._Element) -> list[str]:
    """
    Возвращает текстовые примеры кода из <Demonstrative_Examples>.
    Берём только блоки <Example_Code> с плохим (Nature="bad") кодом.
    """
    examples: list[str] = []
    for ex in weakness.findall(".//cwe:Example_Code[@Nature='bad']", _NS):
        code = _text(ex).strip()
        if code:
            examples.append(code[:500])  # обрезаем слишком длинные примеры
    return examples[:3]  # не более трёх на CWE


def _build_text(
    name: str,
    description: str,
    extended: str,
    mitigations: list[str],
) -> str:
    """
    Собирает финальный текст чанка.
    Ограничиваем ~500 токенов (≈ 2000 символов), чтобы не выходить за контекст.
    """
    parts = [f"Name: {name}"]
    if description:
        parts.append(f"Description: {description}")
    if extended:
        parts.append(f"Details: {extended[:600]}")
    if mitigations:
        mit_text = " | ".join(mitigations[:3])
        parts.append(f"Mitigations: {mit_text[:400]}")
    text = "\n\n".join(parts)
    return text[:2000]  # жёсткий лимит


def parse_cwe_xml(xml_path: Path) -> tuple[list[KnowledgeChunk], set[str]]:
    """
    Парсит CWE XML-файл.

    Args:
        xml_path: Путь к cwec_latest.xml (распакованный).

    Returns:
        Кортеж (список KnowledgeChunk, множество валидных CWE-ID в формате "CWE-NNN").
    """
    if not xml_path.exists():
        raise FileNotFoundError(f"CWE XML не найден: {xml_path}")

    logger.info("Парсим CWE XML: %s", xml_path)
    tree = etree.parse(str(xml_path))
    root = tree.getroot()

    chunks: list[KnowledgeChunk] = []
    valid_ids: set[str] = set()

    weaknesses = root.findall(".//cwe:Weakness", _NS)
    logger.info("Найдено %d уязвимостей в CWE XML", len(weaknesses))

    for weakness in weaknesses:
        cwe_num = weakness.get("ID")
        if not cwe_num:
            continue

        cwe_id = f"CWE-{cwe_num}"
        valid_ids.add(cwe_id)

        name = weakness.get("Name", "")
        status = weakness.get("Status", "")

        # Пропускаем устаревшие / отозванные
        if status in ("Deprecated", "Obsolete"):
            continue

        # Описания
        desc_el = weakness.find("cwe:Description", _NS)
        ext_el = weakness.find("cwe:Extended_Description", _NS)
        description = _text(desc_el)
        extended = _text(ext_el)

        # Митигации
        mitigations: list[str] = []
        for m in weakness.findall(".//cwe:Mitigation/cwe:Description", _NS):
            t = _text(m).strip()
            if t:
                mitigations.append(t[:300])

        # Примеры кода
        examples = _extract_examples(weakness)

        # Языки
        languages = _extract_languages(weakness)

        # Severity hint из базы CWE нет — попробуем определить по имени/ключевым словам
        severity_hint = _guess_severity(name, description)

        text = _build_text(name, description, extended, mitigations)
        if not text.strip():
            continue

        chunk = KnowledgeChunk(
            source="cwe",
            cwe_id=cwe_id,
            title=f"{cwe_id}: {name}",
            text=text,
            examples=examples,
            languages=languages,
            metadata={
                "cwe_id": cwe_id,
                "source": "cwe",
                "severity_hint": severity_hint,
                "languages": languages,
            },
        )
        chunks.append(chunk)

    logger.info(
        "CWE: создано %d чанков, %d валидных ID (включая Deprecated)",
        len(chunks),
        len(valid_ids),
    )
    return chunks, valid_ids


def _guess_severity(name: str, description: str) -> str:
    """
    Эвристика: угадываем severity по ключевым словам в названии/описании.
    Используется только как hint в метаданных; LLM сам оценивает severity.
    """
    text = (name + " " + description).lower()
    critical_kw = ["remote code execution", "arbitrary code", "privilege escalation",
                   "authentication bypass", "sql injection", "command injection"]
    high_kw = ["cross-site scripting", "path traversal", "xml injection",
               "deserialization", "buffer overflow", "use after free",
               "format string", "integer overflow"]
    medium_kw = ["information disclosure", "denial of service", "cross-site request",
                 "open redirect", "session fixation"]

    for kw in critical_kw:
        if kw in text:
            return "critical"
    for kw in high_kw:
        if kw in text:
            return "high"
    for kw in medium_kw:
        if kw in text:
            return "medium"
    return "low"