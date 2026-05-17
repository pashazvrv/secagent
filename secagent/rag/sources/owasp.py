"""
Парсер OWASP Cheat Sheet Series.

Источник: https://github.com/OWASP/CheatSheetSeries (каталог cheatsheets/)

Стратегия:
  - Читаем каждый .md файл из папки cheatsheets/.
  - Разбиваем по заголовкам H2 (## ...).
  - Каждый раздел → один KnowledgeChunk.
  - Связываем с CWE-ID через эвристику по ключевым словам в названии файла/раздела.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from secagent.models import KnowledgeChunk

logger = logging.getLogger(__name__)

# Словарь: ключевые слова в имени файла → CWE-ID
# Используем для авто-маппинга. Частичное совпадение (in).
_FILENAME_TO_CWE: dict[str, str] = {
    "sql_injection": "CWE-89",
    "sqli": "CWE-89",
    "injection": "CWE-89",
    "xss": "CWE-79",
    "cross_site_scripting": "CWE-79",
    "path_traversal": "CWE-22",
    "directory_traversal": "CWE-22",
    "csrf": "CWE-352",
    "cross_site_request": "CWE-352",
    "xxe": "CWE-611",
    "xml_external": "CWE-611",
    "deserialization": "CWE-502",
    "authentication": "CWE-287",
    "session_management": "CWE-384",
    "access_control": "CWE-284",
    "cryptograph": "CWE-327",
    "password_storage": "CWE-916",
    "input_validation": "CWE-20",
    "open_redirect": "CWE-601",
    "ssrf": "CWE-918",
    "command_injection": "CWE-77",
    "ldap_injection": "CWE-90",
    "xpath_injection": "CWE-643",
    "clickjacking": "CWE-1021",
    "http_headers": "CWE-116",
    "logging": "CWE-532",
    "file_upload": "CWE-434",
    "insecure_direct": "CWE-639",
    "mass_assignment": "CWE-915",
    "prototype_pollution": "CWE-1321",
}

# Языки, упомянутые в тексте cheat sheet → canonical-имена
_LANG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bpython\b", re.I), "python"),
    (re.compile(r"\bjavascript\b|\bnode\.?js\b|\bjs\b", re.I), "javascript"),
    (re.compile(r"\btypescript\b|\bts\b", re.I), "typescript"),
    (re.compile(r"\bjava\b", re.I), "java"),
    (re.compile(r"\bgolang\b|\bgo\b", re.I), "go"),
    (re.compile(r"\bc\+\+\b|\bcpp\b", re.I), "cpp"),
    (re.compile(r"\bc\b", re.I), "c"),
    (re.compile(r"\bphp\b", re.I), "php"),
    (re.compile(r"\bruby\b|\brails\b", re.I), "ruby"),
]


def _detect_cwe(filename_stem: str) -> str | None:
    """Пытается определить CWE-ID по имени файла."""
    stem_lower = filename_stem.lower().replace("-", "_").replace(" ", "_")
    for keyword, cwe_id in _FILENAME_TO_CWE.items():
        if keyword in stem_lower:
            return cwe_id
    return None


def _detect_languages(text: str) -> list[str]:
    """Возвращает список языков, упомянутых в тексте."""
    langs: set[str] = set()
    for pattern, lang in _LANG_PATTERNS:
        if pattern.search(text):
            langs.add(lang)
    return sorted(langs)


def _split_by_h2(markdown: str) -> list[tuple[str, str]]:
    """
    Разбивает markdown по заголовкам H2 (## ...).
    Возвращает список (заголовок, содержимое).
    Первый раздел (до первого H2) — это введение.
    """
    sections: list[tuple[str, str]] = []
    # Разбиваем по ## заголовкам
    pattern = re.compile(r"^## (.+)$", re.MULTILINE)
    matches = list(pattern.finditer(markdown))

    if not matches:
        # Нет H2 — весь файл как один раздел
        h1 = re.search(r"^# (.+)$", markdown, re.MULTILINE)
        title = h1.group(1) if h1 else "Overview"
        return [(title, markdown)]

    # Введение до первого H2
    intro = markdown[: matches[0].start()].strip()
    if intro:
        h1 = re.search(r"^# (.+)$", intro, re.MULTILINE)
        intro_title = h1.group(1) if h1 else "Introduction"
        # Убираем H1 из тела
        intro_body = re.sub(r"^# .+\n?", "", intro, count=1).strip()
        if intro_body:
            sections.append((intro_title, intro_body))

    # Разделы H2
    for i, match in enumerate(matches):
        title = match.group(1).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(markdown)
        content = markdown[start:end].strip()
        if content:
            sections.append((title, content))

    return sections


def _clean_markdown(text: str) -> str:
    """
    Упрощает markdown для передачи в LLM:
    убирает HTML-теги, схлопывает лишние переносы.
    """
    # Убираем HTML-теги
    text = re.sub(r"<[^>]+>", "", text)
    # Убираем markdown-ссылки, оставляем текст
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    # Схлопываем 3+ переноса строк → 2
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def parse_owasp_cheatsheets(cheatsheets_dir: Path) -> list[KnowledgeChunk]:
    """
    Парсит все .md файлы из директории OWASP Cheat Sheet Series.

    Args:
        cheatsheets_dir: Путь к папке cheatsheets/ репозитория CheatSheetSeries.

    Returns:
        Список KnowledgeChunk — по одному на каждый H2-раздел.
    """
    if not cheatsheets_dir.exists():
        logger.warning("OWASP cheatsheets dir не найден: %s", cheatsheets_dir)
        return []

    md_files = sorted(cheatsheets_dir.glob("*.md"))
    logger.info("OWASP: найдено %d .md файлов", len(md_files))

    chunks: list[KnowledgeChunk] = []

    for md_file in md_files:
        try:
            raw = md_file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("Не удалось прочитать %s: %s", md_file, e)
            continue

        stem = md_file.stem
        file_cwe = _detect_cwe(stem)
        sections = _split_by_h2(raw)

        for section_title, section_body in sections:
            body = _clean_markdown(section_body)
            if len(body) < 50:
                # Слишком короткий раздел — пропускаем
                continue

            # Ограничиваем ~500 токенов
            body = body[:2000]

            languages = _detect_languages(body)

            # Если языков нет — оставим пустой список (применимо ко всем)
            chunk = KnowledgeChunk(
                source="owasp",
                cwe_id=file_cwe,
                title=f"OWASP: {stem.replace('_Cheat_Sheet', '').replace('_', ' ')} — {section_title}",
                text=body,
                examples=[],  # В cheat sheets примеры встроены в текст
                languages=languages,
                metadata={
                    "source": "owasp",
                    "cwe_id": file_cwe or "",
                    "file": stem,
                    "section": section_title,
                    "languages": languages,
                },
            )
            chunks.append(chunk)

    logger.info("OWASP: создано %d чанков из %d файлов", len(chunks), len(md_files))
    return chunks