"""RAG retriever: поиск релевантных знаний по чанку кода через ChromaDB."""

import logging
from typing import Any

import chromadb
import ollama

from secagent.config import Settings
from secagent.models import CodeChunk, KnowledgeChunk

logger = logging.getLogger(__name__)


class Retriever:
    """Ищет top-k знаний из ChromaDB для заданного чанка кода.

    Args:
        settings: настройки приложения.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()
        self._client: chromadb.PersistentClient | None = None
        self._collection: Any = None

    def _get_collection(self) -> Any:
        """Ленивая инициализация коллекции ChromaDB."""
        if self._collection is None:
            self._client = chromadb.PersistentClient(
                path=str(self._settings.chroma_path)
            )
            self._collection = self._client.get_collection(
                name=self._settings.collection_name
            )
            logger.debug(
                "Подключились к коллекции '%s'", self._settings.collection_name
            )
        return self._collection

    def _embed(self, text: str) -> list[float]:
        """Генерирует эмбеддинг текста через Ollama.

        Args:
            text: текст для эмбеддинга.

        Returns:
            Вектор float.
        """
        response = ollama.embeddings(
            model=self._settings.embedding_model,
            prompt=text,
            options={"seed": self._settings.llm_seed},
        )
        return response["embedding"]

    def retrieve(
        self,
        code_chunk: CodeChunk,
        top_k: int | None = None,
        language_filter: bool = True,
    ) -> list[KnowledgeChunk]:
        """Возвращает top-k релевантных KnowledgeChunk для чанка кода.

        Args:
            code_chunk: анализируемый чанк кода.
            top_k: количество результатов (default из Settings).
            language_filter: фильтровать по языку.

        Returns:
            Список KnowledgeChunk, отсортированных по релевантности.
        """
        k = top_k or self._settings.retrieval_top_k
        collection = self._get_collection()

        embedding = self._embed(code_chunk.code)

        where: dict[str, Any] | None = None

        try:
            results = collection.query(
                query_embeddings=[embedding],
                n_results=k,
                where=where,
                include=["documents", "metadatas", "distances"],
            )
        except Exception:
            # Если фильтр по языку ничего не нашёл — пробуем без фильтра
            logger.warning(
                "Поиск с фильтром по языку '%s' не дал результатов, "
                "пробуем без фильтра.",
                code_chunk.language,
            )
            results = collection.query(
                query_embeddings=[embedding],
                n_results=k,
                include=["documents", "metadatas", "distances"],
            )

        chunks: list[KnowledgeChunk] = []
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]

        for doc, meta in zip(documents, metadatas):
            # Фильтруем по языку если нужно (languages хранится как строка "python,java,...")
            if language_filter:
                langs_str = meta.get("languages", "")
                if code_chunk.language not in langs_str.split(","):
                    continue
            
            chunk = KnowledgeChunk(
                source=meta.get("source", "cwe"),
                cwe_id=meta.get("cwe_id"),
                title=meta.get("title", ""),
                text=doc,
                examples=_parse_list(meta.get("examples", "")),
                languages=_parse_list(meta.get("languages", "")),
                metadata=dict(meta),
            )
            chunks.append(chunk)

        logger.debug(
            "Retriever вернул %d чанков для '%s' (%s)",
            len(chunks),
            code_chunk.name,
            code_chunk.language,
        )
        return chunks


def _parse_list(value: str | list) -> list[str]:
    """Десериализует строку-список или возвращает список как есть."""
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value:
        return [v.strip() for v in value.split(",") if v.strip()]
    return []