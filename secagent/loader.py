# secagent/loader.py
"""Модуль загрузки файлов исходного кода из файловой системы."""

import logging
from collections.abc import Iterator
from pathlib import Path

import pathspec

from secagent.config import Settings
from secagent.models import CodeFile

logger = logging.getLogger(__name__)

# Маппинг расширений → языки
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
}

# Директории, которые всегда исключаем
_EXCLUDED_DIRS: frozenset[str] = frozenset({
    "node_modules", ".venv", "venv", ".git",
    "__pycache__", "dist", "build", ".tox",
    ".mypy_cache", ".ruff_cache", "target",
})

_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 МБ


def _load_gitignore(root: Path) -> pathspec.PathSpec | None:
    """Загружает .gitignore из корня проекта."""
    gitignore = root / ".gitignore"
    if gitignore.exists():
        patterns = gitignore.read_text(encoding="utf-8", errors="ignore").splitlines()
        return pathspec.PathSpec.from_lines("gitwildmatch", patterns)
    return None


def _detect_language(path: Path) -> str | None:
    """Определяет язык по расширению файла."""
    return _EXT_TO_LANG.get(path.suffix.lower())


def _make_code_file(path: Path, language: str) -> CodeFile | None:
    """Читает файл и создаёт CodeFile. Возвращает None при ошибке или превышении размера."""
    size = path.stat().st_size
    if size > _MAX_FILE_SIZE:
        logger.debug("Пропуск %s: размер %d байт превышает лимит", path, size)
        return None
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Не удалось прочитать %s: %s", path, exc)
        return None
    return CodeFile(path=path, language=language, content=content, size_bytes=size)


def load_files(
    root: Path,
    recursive: bool = True,
    languages: list[str] | None = None,
    settings: Settings | None = None,
) -> Iterator[CodeFile]:
    """Обходит файловую систему и возвращает CodeFile для каждого подходящего файла.

    Args:
        root: Путь к файлу или директории.
        recursive: Рекурсивный обход поддиректорий.
        languages: Фильтр по языкам (None = все поддерживаемые).
        settings: Конфигурация приложения.

    Yields:
        CodeFile для каждого найденного файла.
    """
    if settings is None:
        settings = Settings()

    allowed = frozenset(languages or settings.supported_languages)

    # Случай: одиночный файл
    if root.is_file():
        lang = _detect_language(root)
        if lang and lang in allowed:
            cf = _make_code_file(root, lang)
            if cf:
                yield cf
        return

    # Случай: директория
    gitignore = _load_gitignore(root)
    glob_pattern = "**/*" if recursive else "*"

    for path in root.glob(glob_pattern):
        if not path.is_file():
            continue

        # Проверка исключённых директорий
        if any(part in _EXCLUDED_DIRS for part in path.parts):
            continue

        # Проверка .gitignore
        if gitignore:
            rel = path.relative_to(root)
            if gitignore.match_file(str(rel)):
                logger.debug("Пропуск %s: исключён .gitignore", path)
                continue

        lang = _detect_language(path)
        if not lang or lang not in allowed:
            continue

        cf = _make_code_file(path, lang)
        if cf:
            logger.debug("Загружен файл: %s (%s)", path, lang)
            yield cf