"""
Тесты для rag/indexer.py

Используем моки, чтобы не требовать реального Ollama и ChromaDB.

Запуск: pytest tests/test_indexer.py -v
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from secagent.models import KnowledgeChunk
from secagent.rag.indexer import (
    _chunk_to_chroma_record,
    _save_cwe_ids,
    build_knowledge_base,
)


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

def make_chunk(
    source: str = "cwe",
    cwe_id: str = "CWE-89",
    title: str = "CWE-89: SQL Injection",
    text: str = "Description: SQL injection",
    languages: list[str] | None = None,
) -> KnowledgeChunk:
    return KnowledgeChunk(
        source=source,
        cwe_id=cwe_id,
        title=title,
        text=text,
        examples=["cursor.execute('SELECT * FROM users WHERE id=' + uid)"],
        languages=languages or ["python", "java"],
        metadata={"source": source, "cwe_id": cwe_id, "severity_hint": "high", "languages": languages or ["python", "java"]},
    )


# ─────────────────────────────────────────────
# _chunk_to_chroma_record
# ─────────────────────────────────────────────

class TestChunkToChromaRecord:
    def test_id_format(self) -> None:
        chunk = make_chunk(source="cwe", cwe_id="CWE-89")
        record = _chunk_to_chroma_record(chunk, idx=0)
        assert record["id"].startswith("cwe-")
        assert "0" in record["id"]

    def test_document_is_text(self) -> None:
        chunk = make_chunk(text="Some vulnerability description")
        record = _chunk_to_chroma_record(chunk, idx=1)
        assert record["document"] == "Some vulnerability description"

    def test_metadata_has_required_keys(self) -> None:
        chunk = make_chunk()
        record = _chunk_to_chroma_record(chunk, idx=0)
        meta = record["metadata"]
        assert "source" in meta
        assert "cwe_id" in meta
        assert "title" in meta
        assert "languages" in meta
        assert "severity_hint" in meta

    def test_languages_as_comma_string(self) -> None:
        chunk = make_chunk(languages=["python", "java"])
        record = _chunk_to_chroma_record(chunk, idx=0)
        # Chroma не поддерживает list в метаданных → строка через запятую
        assert isinstance(record["metadata"]["languages"], str)
        assert "python" in record["metadata"]["languages"]
        assert "java" in record["metadata"]["languages"]

    def test_title_truncated_to_200(self) -> None:
        long_title = "X" * 300
        chunk = make_chunk(title=long_title)
        record = _chunk_to_chroma_record(chunk, idx=0)
        assert len(record["metadata"]["title"]) <= 200

    def test_none_cwe_id_becomes_empty_string(self) -> None:
        chunk = make_chunk(cwe_id=None)
        record = _chunk_to_chroma_record(chunk, idx=0)
        assert record["metadata"]["cwe_id"] == ""

    def test_unique_ids_for_different_indices(self) -> None:
        chunk = make_chunk()
        r1 = _chunk_to_chroma_record(chunk, idx=0)
        r2 = _chunk_to_chroma_record(chunk, idx=1)
        assert r1["id"] != r2["id"]


# ─────────────────────────────────────────────
# _save_cwe_ids
# ─────────────────────────────────────────────

class TestSaveCweIds:
    def test_saves_json(self, tmp_path: Path) -> None:
        with patch("secagent.rag.indexer.settings") as mock_settings:
            mock_settings.cwe_ids_path = tmp_path / "cwe_ids.json"
            _save_cwe_ids({"CWE-89", "CWE-22", "CWE-79"})
            assert mock_settings.cwe_ids_path.exists()

    def test_json_is_sorted_list(self, tmp_path: Path) -> None:
        path = tmp_path / "cwe_ids.json"
        with patch("secagent.rag.indexer.settings") as mock_settings:
            mock_settings.cwe_ids_path = path
            _save_cwe_ids({"CWE-89", "CWE-22", "CWE-79"})
            data = json.loads(path.read_text())
            assert isinstance(data, list)
            assert data == sorted(data)
            assert "CWE-22" in data

    def test_creates_parent_dir(self, tmp_path: Path) -> None:
        path = tmp_path / "subdir" / "cwe_ids.json"
        with patch("secagent.rag.indexer.settings") as mock_settings:
            mock_settings.cwe_ids_path = path
            _save_cwe_ids({"CWE-89"})
            assert path.exists()


# ─────────────────────────────────────────────
# build_knowledge_base (с полными моками)
# ─────────────────────────────────────────────

class TestBuildKnowledgeBase:
    @pytest.fixture(autouse=True)
    def mock_env(self, tmp_path: Path):
        """Мокает все внешние зависимости."""
        self.tmp_path = tmp_path

        sample_chunks = [make_chunk("cwe"), make_chunk("owasp", "CWE-79", "XSS")]

        with (
            patch("secagent.rag.indexer.settings") as mock_settings,
            patch("secagent.rag.indexer._ensure_sources"),
            patch("secagent.rag.indexer.parse_cwe_xml") as mock_cwe,
            patch("secagent.rag.indexer.parse_owasp_cheatsheets") as mock_owasp,
            patch("secagent.rag.indexer.parse_semgrep_rules") as mock_semgrep,
            patch("secagent.rag.indexer._embed_texts") as mock_embed,
            patch("secagent.rag.indexer.chromadb.PersistentClient") as mock_chroma,
            patch("secagent.rag.indexer.ollama_sdk.Client") as mock_ollama,
        ):
            mock_settings.ollama_host = "http://localhost:11434"
            mock_settings.embedding_model = "nomic-embed-text"
            mock_settings.collection_name = "security_knowledge"
            mock_settings.chroma_path = tmp_path / "chroma"
            mock_settings.cwe_ids_path = tmp_path / "cwe_ids.json"

            mock_cwe.return_value = ([sample_chunks[0]], {"CWE-89"})
            mock_owasp.return_value = [sample_chunks[1]]
            mock_semgrep.return_value = []

            # Мок эмбеддинга: возвращаем вектор 768d
            mock_embed.return_value = [[0.1] * 768, [0.2] * 768]

            # Мок ChromaDB
            mock_collection = MagicMock()
            mock_collection.count.return_value = 0
            mock_chroma.return_value.get_or_create_collection.return_value = mock_collection
            self.mock_collection = mock_collection

            # Мок Ollama (для проверки доступности)
            mock_ollama.return_value.list.return_value = []

            self.mocks = {
                "settings": mock_settings,
                "cwe": mock_cwe,
                "owasp": mock_owasp,
                "semgrep": mock_semgrep,
                "embed": mock_embed,
            }
            yield

    def test_calls_all_parsers(self) -> None:
        build_knowledge_base()
        self.mocks["cwe"].assert_called_once()
        self.mocks["owasp"].assert_called_once()
        self.mocks["semgrep"].assert_called_once()

    def test_upsert_called(self) -> None:
        build_knowledge_base()
        assert self.mock_collection.upsert.called

    def test_returns_count(self) -> None:
        result = build_knowledge_base()
        assert isinstance(result, int)
        assert result >= 0

    def test_saves_cwe_ids(self) -> None:
        build_knowledge_base()
        path = self.tmp_path / "cwe_ids.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert "CWE-89" in data

    def test_existing_collection_skipped_without_rebuild(self) -> None:
        self.mock_collection.count.return_value = 1000
        result = build_knowledge_base(rebuild=False)
        # При непустой коллекции и rebuild=False — должна вернуть existing count
        assert result == 1000
        # Upsert не должен вызываться
        self.mock_collection.upsert.assert_not_called()