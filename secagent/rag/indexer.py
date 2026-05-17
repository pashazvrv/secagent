"""
Построение векторной базы знаний (ChromaDB).

Запуск: secagent index [--rebuild]

Этапы:
  1. Скачать источники, если не скачаны (CWE XML, OWASP, Semgrep).
  2. Распарсить каждый источник → list[KnowledgeChunk].
  3. Сгенерировать эмбеддинги через Ollama (nomic-embed-text).
  4. Сохранить в ChromaDB (батчами).
  5. Сохранить data/cwe_ids.json с валидными CWE-ID.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any

import chromadb
import httpx
import ollama as ollama_sdk

from secagent.config import settings
from secagent.models import KnowledgeChunk
from secagent.rag.sources.cwe import parse_cwe_xml
from secagent.rag.sources.owasp import parse_owasp_cheatsheets
from secagent.rag.sources.semgrep import parse_semgrep_rules

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Пути к исходным данным
# ─────────────────────────────────────────────

_DATA_DIR = Path("./data/knowledge_base")
_CWE_DIR = _DATA_DIR / "cwe"
_CWE_XML = _CWE_DIR / "cwec_latest.xml"
_CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

_OWASP_DIR = _DATA_DIR / "owasp"
_OWASP_CHEATSHEETS = _OWASP_DIR / "cheatsheets"
_OWASP_REPO = "https://github.com/OWASP/CheatSheetSeries"

_SEMGREP_DIR = _DATA_DIR / "semgrep"
_SEMGREP_REPO = "https://github.com/semgrep/semgrep-rules"

# Батч для эмбеддингов — не слишком большой, чтобы не перегружать Ollama
_EMBED_BATCH_SIZE = 32

# Батч для вставки в Chroma
_CHROMA_BATCH_SIZE = 100


# ─────────────────────────────────────────────
# Загрузка источников
# ─────────────────────────────────────────────

def _download_cwe() -> None:
    """Скачивает и распаковывает CWE XML."""
    if _CWE_XML.exists():
        logger.info("CWE XML уже скачан: %s", _CWE_XML)
        return

    _CWE_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = _CWE_DIR / "cwec_latest.xml.zip"

    logger.info("Скачиваем CWE XML с %s ...", _CWE_ZIP_URL)
    with httpx.stream("GET", _CWE_ZIP_URL, follow_redirects=True, timeout=120) as r:
        r.raise_for_status()
        with open(zip_path, "wb") as f:
            for chunk in r.iter_bytes(chunk_size=8192):
                f.write(chunk)

    logger.info("Распаковываем %s ...", zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        # Ищем .xml файл внутри архива
        xml_members = [m for m in zf.namelist() if m.endswith(".xml")]
        if not xml_members:
            raise RuntimeError("В архиве CWE не найден XML файл")
        zf.extract(xml_members[0], _CWE_DIR)
        # Переименовываем в стандартное имя
        extracted = _CWE_DIR / xml_members[0]
        if extracted != _CWE_XML:
            extracted.rename(_CWE_XML)

    zip_path.unlink(missing_ok=True)
    logger.info("CWE XML готов: %s", _CWE_XML)


def _clone_or_update_repo(url: str, dest: Path, name: str) -> None:
    """Клонирует репозиторий или пропускает, если он уже есть."""
    if dest.exists() and (dest / ".git").exists():
        logger.info("%s уже клонирован: %s", name, dest)
        return

    if dest.exists():
        shutil.rmtree(dest)

    dest.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Клонируем %s → %s ...", url, dest)

    # Shallow clone — быстрее
    result = subprocess.run(
        ["git", "clone", "--depth=1", url, str(dest)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone провалился: {result.stderr}")

    logger.info("%s успешно клонирован.", name)


def _ensure_sources() -> None:
    """Скачивает все источники, если их нет."""
    _download_cwe()
    _clone_or_update_repo(_OWASP_REPO, _OWASP_DIR, "OWASP CheatSheetSeries")
    _clone_or_update_repo(_SEMGREP_REPO, _SEMGREP_DIR, "Semgrep Rules")


# ─────────────────────────────────────────────
# Эмбеддинги через Ollama
# ─────────────────────────────────────────────

def _embed_texts(texts: list[str]) -> list[list[float]]:
    """
    Генерирует эмбеддинги для списка текстов батчами.
    Возвращает список векторов того же размера, что и входной список.
    """
    client = ollama_sdk.Client(host=settings.ollama_host)
    all_embeddings: list[list[float]] = []

    for i in range(0, len(texts), _EMBED_BATCH_SIZE):
        batch = texts[i : i + _EMBED_BATCH_SIZE]
        logger.debug("Эмбеддинг батч %d/%d...", i // _EMBED_BATCH_SIZE + 1,
                     (len(texts) + _EMBED_BATCH_SIZE - 1) // _EMBED_BATCH_SIZE)

        batch_embeddings: list[list[float]] = []
        for text in batch:
            try:
                resp = client.embeddings(model=settings.embedding_model, prompt=text)
                batch_embeddings.append(resp["embedding"])
            except Exception as e:
                logger.warning("Ошибка эмбеддинга, заменяем нулевым вектором: %s", e)
                # В случае ошибки вставляем нулевой вектор — он будет иметь низкое сходство
                batch_embeddings.append([0.0] * 768)  # nomic-embed-text = 768d

        all_embeddings.extend(batch_embeddings)
        time.sleep(0.05)  # небольшая пауза, чтобы не перегружать Ollama

    return all_embeddings


# ─────────────────────────────────────────────
# Построение базы знаний
# ─────────────────────────────────────────────

def _get_collection(client: chromadb.ClientAPI) -> chromadb.Collection:
    """Возвращает коллекцию ChromaDB (создаёт при необходимости)."""
    # embedding_function=None — мы вставляем эмбеддинги сами через Ollama
    return client.get_or_create_collection(
        name=settings.collection_name,
        metadata={"hnsw:space": "cosine"},  # косинусное сходство
    )


def _chunk_to_chroma_record(chunk: KnowledgeChunk, idx: int) -> dict[str, Any]:
    """
    Конвертирует KnowledgeChunk в формат Chroma.
    ID = "{source}-{cwe_id_safe}-{idx}"
    """
    cwe_safe = (chunk.cwe_id or "none").replace("-", "").lower()
    doc_id = f"{chunk.source}-{cwe_safe}-{idx}"

    # Chroma метаданные — только простые типы (str, int, float, bool)
    meta: dict[str, Any] = {
        "source": chunk.source,
        "cwe_id": chunk.cwe_id or "",
        "title": chunk.title[:200],
        "severity_hint": chunk.metadata.get("severity_hint", ""),
        # Языки хранятся как строка-список через запятую (Chroma не поддерживает list в metadata)
        "languages": ",".join(chunk.languages) if chunk.languages else "",
    }

    # Документ = полный текст для поиска
    document = chunk.text

    return {"id": doc_id, "document": document, "metadata": meta}


def _insert_chunks(
    collection: chromadb.Collection,
    chunks: list[KnowledgeChunk],
) -> int:
    """
    Генерирует эмбеддинги и вставляет чанки в Chroma батчами.
    Возвращает количество успешно вставленных чанков.
    """
    inserted = 0
    records = [_chunk_to_chroma_record(ch, i) for i, ch in enumerate(chunks)]

    for start in range(0, len(records), _CHROMA_BATCH_SIZE):
        batch_records = records[start : start + _CHROMA_BATCH_SIZE]
        batch_chunks = chunks[start : start + _CHROMA_BATCH_SIZE]

        texts = [r["document"] for r in batch_records]
        ids = [r["id"] for r in batch_records]
        metadatas = [
            {
                **r["metadata"],
                "languages": ",".join(batch_chunks[i].languages) if batch_chunks[i].languages else "",
            }
            for i, r in enumerate(batch_records)
        ]

        # Генерируем эмбеддинги для батча
        embeddings = _embed_texts(texts)

        try:
            collection.upsert(
                ids=ids,
                documents=texts,
                embeddings=embeddings,
                metadatas=metadatas,
            )
            inserted += len(batch_records)
            logger.info(
                "Вставлено %d/%d чанков в Chroma...",
                min(start + _CHROMA_BATCH_SIZE, len(records)),
                len(records),
            )
        except Exception as e:
            logger.error("Ошибка вставки батча в Chroma: %s", e)

    return inserted


def _build_chunk_text_for_test(chunk: KnowledgeChunk) -> str:
    """Вспомогательная функция для тестов — возвращает текст чанка."""
    return chunk.text


def _save_cwe_ids(valid_ids: set[str]) -> None:
    """Сохраняет множество валидных CWE-ID в JSON-файл для валидатора."""
    settings.cwe_ids_path.parent.mkdir(parents=True, exist_ok=True)
    data = sorted(valid_ids)  # сортируем для читаемости
    with open(settings.cwe_ids_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logger.info(
        "Сохранено %d валидных CWE-ID в %s", len(data), settings.cwe_ids_path
    )


# ─────────────────────────────────────────────
# Публичный API
# ─────────────────────────────────────────────

def build_knowledge_base(rebuild: bool = False) -> int:
    """
    Собирает (или пересобирает) векторную базу знаний.

    Args:
        rebuild: Если True — удаляет существующую Chroma БД перед построением.

    Returns:
        Количество добавленных чанков.
    """
    # Проверяем, что Ollama доступен
    try:
        client_check = ollama_sdk.Client(host=settings.ollama_host)
        client_check.list()
    except Exception as e:
        raise RuntimeError(
            f"Ollama недоступен по адресу {settings.ollama_host}. "
            f"Запусти `ollama serve` и убедись, что модели скачаны.\nОшибка: {e}"
        ) from e

    # Если rebuild — удаляем старую БД
    if rebuild and settings.chroma_path.exists():
        logger.warning("Удаляем старую Chroma БД: %s", settings.chroma_path)
        shutil.rmtree(settings.chroma_path)

    # Скачиваем источники
    _ensure_sources()

    # ── Парсим источники ──
    logger.info("=== Парсим CWE XML ===")
    cwe_chunks, valid_cwe_ids = parse_cwe_xml(_CWE_XML)

    logger.info("=== Парсим OWASP Cheat Sheets ===")
    owasp_chunks = parse_owasp_cheatsheets(_OWASP_CHEATSHEETS)

    logger.info("=== Парсим Semgrep Rules ===")
    semgrep_chunks = parse_semgrep_rules(_SEMGREP_DIR)

    all_chunks: list[KnowledgeChunk] = cwe_chunks + owasp_chunks + semgrep_chunks

    logger.info(
        "Всего чанков: CWE=%d, OWASP=%d, Semgrep=%d → итого=%d",
        len(cwe_chunks),
        len(owasp_chunks),
        len(semgrep_chunks),
        len(all_chunks),
    )

    if not all_chunks:
        logger.error("Нет чанков для индексации!")
        return 0

    # ── ChromaDB ──
    settings.chroma_path.mkdir(parents=True, exist_ok=True)
    chroma_client = chromadb.PersistentClient(path=str(settings.chroma_path))
    collection = _get_collection(chroma_client)

    # Если не rebuild, но коллекция уже есть — сколько там записей?
    existing = collection.count()
    if existing > 0 and not rebuild:
        logger.info(
            "Коллекция уже содержит %d записей. "
            "Используй --rebuild для полного перестроения.",
            existing,
        )
        return existing

    # ── Вставка ──
    logger.info("Вставляем %d чанков в ChromaDB...", len(all_chunks))
    inserted = _insert_chunks(collection, all_chunks)

    # ── Сохраняем CWE IDs для валидатора ──
    _save_cwe_ids(valid_cwe_ids)

    logger.info("✓ База знаний построена. Вставлено чанков: %d", inserted)
    return inserted