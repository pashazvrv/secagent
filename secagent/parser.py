# secagent/parser.py
"""Семантическое чанкование кода с помощью tree-sitter."""

import logging
from pathlib import Path

from tree_sitter import Language, Node, Parser
from tree_sitter_languages import get_language, get_parser

from secagent.config import Settings
from secagent.models import CodeChunk, CodeFile

logger = logging.getLogger(__name__)

# Узлы tree-sitter, которые считаются самостоятельными чанками, по языку
_CHUNK_NODE_TYPES: dict[str, list[str]] = {
    "python": ["function_definition", "class_definition"],
    "javascript": [
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "class_declaration",
    ],
    "typescript": [
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "class_declaration",
    ],
    "java": ["method_declaration", "constructor_declaration", "class_declaration"],
    "go": ["function_declaration", "method_declaration"],
    "c": ["function_definition"],
    "cpp": ["function_definition", "class_specifier"],
}

# Имена узлов, содержащих идентификатор, по типу узла
_NAME_CHILD_FIELD = "name"


def _get_parser(language: str) -> Parser | None:
    """Получает tree-sitter парсер для заданного языка."""
    try:
        return get_parser(language)
    except Exception as exc:
        logger.warning("Не удалось загрузить парсер для %s: %s", language, exc)
        return None


def _extract_name(node: Node, source: bytes) -> str:
    """Извлекает имя функции/класса из узла AST."""
    name_node = node.child_by_field_name(_NAME_CHILD_FIELD)
    if name_node:
        return source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
    return "<anonymous>"


def _collect_chunks(
    node: Node,
    source: bytes,
    file_path: Path,
    language: str,
    target_types: list[str],
    max_lines: int,
    results: list[CodeChunk],
) -> None:
    """Рекурсивно обходит AST и собирает чанки нужных типов."""
    if node.type in target_types:
        start_line = node.start_point[0] + 1  # tree-sitter: 0-indexed → 1-indexed
        end_line = node.end_point[0] + 1
        code = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        name = _extract_name(node, source)

        chunk_lines = end_line - start_line + 1
        if chunk_lines > max_lines:
            logger.debug(
                "Большая функция %s (%d строк) в %s — помечаем как oversized",
                name, chunk_lines, file_path,
            )

        results.append(CodeChunk(
            file_path=file_path,
            language=language,
            chunk_type="function" if "function" in node.type or "method" in node.type else "class",
            name=name,
            code=code,
            line_start=start_line,
            line_end=end_line,
        ))
        # Не уходим глубже — вложенные функции внутри класса/функции
        # анализируются отдельно только на верхнем уровне
        return

    for child in node.children:
        _collect_chunks(child, source, file_path, language, target_types, max_lines, results)


def parse_file(file: CodeFile, settings: Settings | None = None) -> list[CodeChunk]:
    """Разбивает файл на семантические чанки с помощью tree-sitter.

    Args:
        file: Загруженный файл с исходным кодом.
        settings: Конфигурация приложения.

    Returns:
        Список CodeChunk. При ошибке парсинга — один chunk типа 'module'.
    """
    if settings is None:
        settings = Settings()

    target_types = _CHUNK_NODE_TYPES.get(file.language)
    if not target_types:
        logger.warning("Неподдерживаемый язык для парсинга: %s", file.language)
        return _fallback_chunk(file)

    parser = _get_parser(file.language)
    if parser is None:
        return _fallback_chunk(file)

    source = file.content.encode("utf-8")
    try:
        tree = parser.parse(source)
    except Exception as exc:
        logger.warning("Ошибка парсинга %s: %s — fallback на whole-file", file.path, exc)
        return _fallback_chunk(file)

    chunks: list[CodeChunk] = []
    _collect_chunks(
        tree.root_node,
        source,
        file.path,
        file.language,
        target_types,
        settings.max_chunk_lines,
        chunks,
    )

    if not chunks:
        logger.debug("Нет функций/классов в %s — fallback на whole-file", file.path)
        return _fallback_chunk(file)

    logger.debug("Найдено %d чанков в %s", len(chunks), file.path)
    return chunks


def _fallback_chunk(file: CodeFile) -> list[CodeChunk]:
    """Возвращает весь файл как один модульный чанк."""
    lines = file.content.splitlines()
    return [CodeChunk(
        file_path=file.path,
        language=file.language,
        chunk_type="module",
        name=file.path.name,
        code=file.content,
        line_start=1,
        line_end=max(len(lines), 1),
    )]