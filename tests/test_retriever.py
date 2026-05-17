"""Юнит-тесты для rag/retriever.py с моком ChromaDB и Ollama."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secagent.models import CodeChunk, KnowledgeChunk
from secagent.rag.retriever import Retriever, _parse_list
from secagent.config import Settings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings(
        chroma_path=tmp_path / "chroma",
        collection_name="test_collection",
        retrieval_top_k=3,
        embedding_model="nomic-embed-text",
    )


@pytest.fixture()
def sql_chunk() -> CodeChunk:
    return CodeChunk(
        file_path=Path("app/db.py"),
        language="python",
        chunk_type="function",
        name="get_user",
        code='def get_user(uid):\n    query = "SELECT * FROM users WHERE id = " + uid\n    return cursor.execute(query)',
        line_start=1,
        line_end=3,
    )


def _make_chroma_results(n: int = 2) -> dict:
    """Возвращает фейковые результаты ChromaDB-запроса."""
    return {
        "documents": [
            [f"Description of vulnerability {i}" for i in range(n)]
        ],
        "metadatas": [
            [
                {
                    "source": "cwe",
                    "cwe_id": f"CWE-{89 + i}",
                    "title": f"Vulnerability {i}",
                    "languages": "python,java",
                    "examples": "cursor.execute('...' + uid)",
                }
                for i in range(n)
            ]
        ],
        "distances": [[0.1 * i for i in range(n)]],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRetriever:
    @patch("secagent.rag.retriever.ollama.embeddings")
    @patch("secagent.rag.retriever.chromadb.PersistentClient")
    def test_returns_knowledge_chunks(
        self, mock_chroma_cls, mock_embeddings, settings, sql_chunk
    ):
        """Retriever возвращает список KnowledgeChunk нужной длины."""
        mock_embeddings.return_value = {"embedding": [0.1] * 768}

        mock_collection = MagicMock()
        mock_collection.query.return_value = _make_chroma_results(2)
        mock_chroma_cls.return_value.get_collection.return_value = mock_collection

        retriever = Retriever(settings=settings)
        results = retriever.retrieve(sql_chunk, top_k=2)

        assert len(results) == 2
        assert all(isinstance(r, KnowledgeChunk) for r in results)

    @patch("secagent.rag.retriever.ollama.embeddings")
    @patch("secagent.rag.retriever.chromadb.PersistentClient")
    def test_correct_cwe_ids(
        self, mock_chroma_cls, mock_embeddings, settings, sql_chunk
    ):
        """CWE-ID из метаданных Chroma корректно попадают в KnowledgeChunk."""
        mock_embeddings.return_value = {"embedding": [0.0] * 768}

        mock_collection = MagicMock()
        mock_collection.query.return_value = _make_chroma_results(2)
        mock_chroma_cls.return_value.get_collection.return_value = mock_collection

        retriever = Retriever(settings=settings)
        results = retriever.retrieve(sql_chunk)

        assert results[0].cwe_id == "CWE-89"
        assert results[1].cwe_id == "CWE-90"

    @patch("secagent.rag.retriever.ollama.embeddings")
    @patch("secagent.rag.retriever.chromadb.PersistentClient")
    def test_language_filter_passed(
        self, mock_chroma_cls, mock_embeddings, settings, sql_chunk
    ):
        """При language_filter=True в Chroma передаётся where-фильтр."""
        mock_embeddings.return_value = {"embedding": [0.0] * 768}

        mock_collection = MagicMock()
        mock_collection.query.return_value = _make_chroma_results(1)
        mock_chroma_cls.return_value.get_collection.return_value = mock_collection

        retriever = Retriever(settings=settings)
        retriever.retrieve(sql_chunk, language_filter=True)

        call_kwargs = mock_collection.query.call_args.kwargs
        assert "where" in call_kwargs
        assert call_kwargs["where"] is not None

    @patch("secagent.rag.retriever.ollama.embeddings")
    @patch("secagent.rag.retriever.chromadb.PersistentClient")
    def test_no_language_filter(
        self, mock_chroma_cls, mock_embeddings, settings, sql_chunk
    ):
        """При language_filter=False where=None."""
        mock_embeddings.return_value = {"embedding": [0.0] * 768}

        mock_collection = MagicMock()
        mock_collection.query.return_value = _make_chroma_results(1)
        mock_chroma_cls.return_value.get_collection.return_value = mock_collection

        retriever = Retriever(settings=settings)
        retriever.retrieve(sql_chunk, language_filter=False)

        call_kwargs = mock_collection.query.call_args.kwargs
        assert call_kwargs.get("where") is None

    @patch("secagent.rag.retriever.ollama.embeddings")
    @patch("secagent.rag.retriever.chromadb.PersistentClient")
    def test_fallback_without_filter_on_error(
        self, mock_chroma_cls, mock_embeddings, settings, sql_chunk
    ):
        """При ошибке с language_filter делается повторный запрос без фильтра."""
        mock_embeddings.return_value = {"embedding": [0.0] * 768}

        mock_collection = MagicMock()
        # Первый вызов с where — кидает исключение, второй без — ок
        mock_collection.query.side_effect = [
            Exception("no results"),
            _make_chroma_results(1),
        ]
        mock_chroma_cls.return_value.get_collection.return_value = mock_collection

        retriever = Retriever(settings=settings)
        results = retriever.retrieve(sql_chunk, language_filter=True)

        assert len(results) == 1
        assert mock_collection.query.call_count == 2


class TestParseList:
    def test_string_input(self):
        assert _parse_list("python,java") == ["python", "java"]

    def test_list_input(self):
        assert _parse_list(["go", "c"]) == ["go", "c"]

    def test_empty_string(self):
        assert _parse_list("") == []

    def test_spaces(self):
        assert _parse_list("python, java , go") == ["python", "java", "go"]