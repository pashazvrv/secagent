"""Analyzer: отправляет чанк кода + RAG-контекст в Ollama, парсит Finding[]."""

import json
import logging
from pathlib import Path

import ollama

from secagent.config import Settings
from secagent.models import CodeChunk, Finding, KnowledgeChunk

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load_prompt(filename: str) -> str:
    """Загружает промпт из файла.

    Args:
        filename: имя файла в директории prompts/.

    Returns:
        Содержимое файла.
    """
    return (_PROMPTS_DIR / filename).read_text(encoding="utf-8")


def _format_knowledge(chunks: list[KnowledgeChunk]) -> str:
    """Форматирует список KnowledgeChunk в текст для промпта.

    Args:
        chunks: список чанков из RAG.

    Returns:
        Многострочный текст с выжимкой знаний.
    """
    parts: list[str] = []
    for chunk in chunks:
        header = f"[{chunk.cwe_id or chunk.source.upper()}] {chunk.title}"
        body = chunk.text[:800]  # не больше ~300 токенов на чанк
        examples_str = ""
        if chunk.examples:
            examples_str = "\nExamples:\n" + "\n".join(
                f"  - {ex}" for ex in chunk.examples[:2]
            )
        parts.append(f"{header}\n{body}{examples_str}")
    return "\n\n".join(parts)


def _add_line_numbers(code: str, start_line: int = 1) -> str:
    """Добавляет номера строк к коду.

    Args:
        code: исходный код.
        start_line: номер первой строки.

    Returns:
        Код с префиксами «  N | » перед каждой строкой.
    """
    lines = code.splitlines()
    width = len(str(start_line + len(lines)))
    numbered = [
        f"{str(start_line + i).rjust(width)} | {line}"
        for i, line in enumerate(lines)
    ]
    return "\n".join(numbered)


def _parse_llm_response(
    raw: str,
    chunk: CodeChunk,
) -> list[Finding]:
    """Парсит JSON-ответ LLM в список Finding.

    Args:
        raw: сырая строка JSON от модели.
        chunk: исходный чанк (нужен для file_path и code_snippet).

    Returns:
        Список Finding (может быть пустым при ошибке парсинга).
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("Не удалось распарсить JSON от LLM: %s", exc)
        return []

    findings: list[Finding] = []
    for item in data.get("findings", []):
        try:
            line_start = int(item.get("line_start", chunk.line_start))
            line_end = int(item.get("line_end", line_start))
            # Вырезаем сниппет из кода чанка по номерам строк
            code_lines = chunk.code.splitlines()
            offset = chunk.line_start
            s = max(0, line_start - offset)
            e = max(s + 1, line_end - offset + 1)
            snippet = "\n".join(code_lines[s:e])

            finding = Finding(
                cwe_id=item["cwe_id"],
                severity=item.get("severity", "medium"),
                title=item.get("title", ""),
                description=item.get("description", ""),
                line_start=line_start,
                line_end=line_end,
                code_snippet=snippet,
                recommendation=item.get("recommendation", ""),
                confidence=float(item.get("confidence", 0.5)),
                file_path=chunk.file_path,
            )
            findings.append(finding)
        except (KeyError, ValueError) as exc:
            logger.warning("Пропускаем finding (неверный формат): %s | %s", exc, item)

    return findings


def analyze_chunk(
    chunk: CodeChunk,
    knowledge: list[KnowledgeChunk],
    settings: Settings | None = None,
) -> list[Finding]:
    """Анализирует один CodeChunk с помощью LLM + RAG-контекста.

    Args:
        chunk: чанк кода для анализа.
        knowledge: релевантные знания из RAG.
        settings: настройки (если None — загружаются по умолчанию).

    Returns:
        Список Finding. Пустой список если уязвимостей не найдено
        или LLM вернула некорректный ответ.
    """
    cfg = settings or Settings()

    system_prompt = _load_prompt("analyze_system.txt")
    user_template = _load_prompt("analyze_user.txt")

    knowledge_text = _format_knowledge(knowledge)
    code_with_numbers = _add_line_numbers(chunk.code, start_line=chunk.line_start)

    user_prompt = user_template.format(
        knowledge_chunks=knowledge_text,
        language=chunk.language,
        file_path=str(chunk.file_path),
        chunk_name=chunk.name,
        code_with_line_numbers=code_with_numbers,
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    logger.debug(
        "Анализируем чанк '%s' (%s:%d-%d)",
        chunk.name,
        chunk.file_path,
        chunk.line_start,
        chunk.line_end,
    )

    raw_response = _call_llm(messages, cfg)
    findings = _parse_llm_response(raw_response, chunk)

    if not findings:
        # Один повтор при пустом/сломанном ответе
        logger.debug("Пустой ответ, повторяем запрос для '%s'", chunk.name)
        raw_response = _call_llm(messages, cfg)
        findings = _parse_llm_response(raw_response, chunk)

    logger.info(
        "Чанк '%s': найдено %d finding(s)", chunk.name, len(findings)
    )
    return findings


def _call_llm(messages: list[dict], cfg: Settings) -> str:
    """Выполняет запрос к Ollama и возвращает сырой текст ответа.

    Args:
        messages: список сообщений в формате [{role, content}].
        cfg: настройки.

    Returns:
        Строка — тело ответа модели.
    """
    try:
        response = ollama.chat(
            model=cfg.llm_model,
            messages=messages,
            format="json",
            options={
                "temperature": cfg.llm_temperature,
                "seed": cfg.llm_seed,
                "num_predict": cfg.llm_max_tokens,
            },
        )
        return response["message"]["content"]
    except Exception as exc:
        logger.error("Ошибка вызова Ollama: %s", exc)
        return '{"findings": []}'