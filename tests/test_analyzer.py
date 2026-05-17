"""Юнит-тесты для analyzer.py с моком Ollama."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from secagent.analyzer import (
    _add_line_numbers,
    _format_knowledge,
    _parse_llm_response,
    analyze_chunk,
)
from secagent.config import Settings
from secagent.models import CodeChunk, Finding, KnowledgeChunk


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def settings() -> Settings:
    return Settings(llm_temperature=0.1, llm_seed=42)


@pytest.fixture()
def sql_chunk() -> CodeChunk:
    return CodeChunk(
        file_path=Path("app/db.py"),
        language="python",
        chunk_type="function",
        name="get_user",
        code='def get_user(uid):\n    query = "SELECT * FROM users WHERE id = " + uid\n    return cursor.execute(query)',
        line_start=10,
        line_end=12,
    )


@pytest.fixture()
def knowledge() -> list[KnowledgeChunk]:
    return [
        KnowledgeChunk(
            source="cwe",
            cwe_id="CWE-89",
            title="SQL Injection",
            text="The software constructs SQL using externally-influenced input.",
            examples=["cursor.execute('SELECT * FROM users WHERE id = ' + uid)"],
            languages=["python", "java"],
            metadata={},
        )
    ]


def _make_llm_response(findings: list[dict]) -> dict:
    """Оборачивает список findings в структуру ответа Ollama."""
    return {
        "message": {
            "content": json.dumps({"findings": findings})
        }
    }


# ---------------------------------------------------------------------------
# Tests: _add_line_numbers
# ---------------------------------------------------------------------------

class TestAddLineNumbers:
    def test_starts_from_1(self):
        code = "a = 1\nb = 2"
        result = _add_line_numbers(code, start_line=1)
        assert result.startswith("1 | a = 1")

    def test_custom_start(self):
        code = "x = 0\ny = 1"
        result = _add_line_numbers(code, start_line=10)
        assert "10 | x = 0" in result
        assert "11 | y = 1" in result

    def test_single_line(self):
        result = _add_line_numbers("pass", start_line=5)
        assert "5 | pass" in result


# ---------------------------------------------------------------------------
# Tests: _format_knowledge
# ---------------------------------------------------------------------------

class TestFormatKnowledge:
    def test_includes_cwe_id(self, knowledge):
        result = _format_knowledge(knowledge)
        assert "CWE-89" in result

    def test_includes_title(self, knowledge):
        result = _format_knowledge(knowledge)
        assert "SQL Injection" in result

    def test_includes_example(self, knowledge):
        result = _format_knowledge(knowledge)
        assert "cursor.execute" in result

    def test_empty_list(self):
        result = _format_knowledge([])
        assert result == ""


# ---------------------------------------------------------------------------
# Tests: _parse_llm_response
# ---------------------------------------------------------------------------

class TestParseLlmResponse:
    def test_valid_finding(self, sql_chunk):
        raw = json.dumps({
            "findings": [{
                "cwe_id": "CWE-89",
                "severity": "high",
                "title": "SQL Injection",
                "description": "Опасная конкатенация строк в SQL-запросе.",
                "line_start": 11,
                "line_end": 12,
                "recommendation": "Используйте параметризованные запросы.",
                "confidence": 0.92,
            }]
        })
        findings = _parse_llm_response(raw, sql_chunk)
        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-89"
        assert findings[0].severity == "high"
        assert findings[0].confidence == pytest.approx(0.92)
        assert findings[0].file_path == sql_chunk.file_path

    def test_empty_findings(self, sql_chunk):
        raw = json.dumps({"findings": []})
        findings = _parse_llm_response(raw, sql_chunk)
        assert findings == []

    def test_broken_json(self, sql_chunk):
        findings = _parse_llm_response("NOT JSON AT ALL", sql_chunk)
        assert findings == []

    def test_missing_cwe_id_raises(self, sql_chunk):
        """Finding без cwe_id должен быть пропущен (KeyError)."""
        raw = json.dumps({
            "findings": [{
                "severity": "high",
                "title": "No CWE",
                "description": "desc",
                "line_start": 11,
                "line_end": 11,
                "recommendation": "fix",
                "confidence": 0.9,
            }]
        })
        findings = _parse_llm_response(raw, sql_chunk)
        assert findings == []

    def test_code_snippet_extracted(self, sql_chunk):
        """Проверяем, что code_snippet корректно вырезается из кода чанка."""
        raw = json.dumps({
            "findings": [{
                "cwe_id": "CWE-89",
                "severity": "high",
                "title": "SQL Injection",
                "description": "desc",
                "line_start": 11,
                "line_end": 11,
                "recommendation": "fix",
                "confidence": 0.85,
            }]
        })
        findings = _parse_llm_response(raw, sql_chunk)
        assert findings[0].code_snippet  # не пустой


# ---------------------------------------------------------------------------
# Tests: analyze_chunk (integration with mocked Ollama)
# ---------------------------------------------------------------------------

class TestAnalyzeChunk:
    @patch("secagent.analyzer.ollama.chat")
    def test_returns_findings_on_valid_response(
        self, mock_chat, sql_chunk, knowledge, settings
    ):
        mock_chat.return_value = _make_llm_response([{
            "cwe_id": "CWE-89",
            "severity": "high",
            "title": "SQL Injection",
            "description": "SQL-инъекция через конкатенацию.",
            "line_start": 11,
            "line_end": 12,
            "recommendation": "Используйте параметризованные запросы.",
            "confidence": 0.9,
        }])

        findings = analyze_chunk(sql_chunk, knowledge, settings=settings)

        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-89"

    @patch("secagent.analyzer.ollama.chat")
    def test_retries_on_empty_response(
        self, mock_chat, sql_chunk, knowledge, settings
    ):
        """При пустом первом ответе делается повтор."""
        mock_chat.side_effect = [
            _make_llm_response([]),  # первый вызов — пусто
            _make_llm_response([{   # второй — успех
                "cwe_id": "CWE-89",
                "severity": "medium",
                "title": "SQL Injection",
                "description": "desc",
                "line_start": 11,
                "line_end": 11,
                "recommendation": "fix",
                "confidence": 0.75,
            }]),
        ]

        findings = analyze_chunk(sql_chunk, knowledge, settings=settings)

        assert mock_chat.call_count == 2
        assert len(findings) == 1

    @patch("secagent.analyzer.ollama.chat")
    def test_returns_empty_on_ollama_error(
        self, mock_chat, sql_chunk, knowledge, settings
    ):
        """При ошибке Ollama возвращаем пустой список, не падаем."""
        mock_chat.side_effect = ConnectionError("Ollama not running")

        findings = analyze_chunk(sql_chunk, knowledge, settings=settings)

        assert findings == []

    @patch("secagent.analyzer.ollama.chat")
    def test_llm_called_with_json_format(
        self, mock_chat, sql_chunk, knowledge, settings
    ):
        """Проверяем, что запрос к Ollama идёт с format='json'."""
        mock_chat.return_value = _make_llm_response([])

        analyze_chunk(sql_chunk, knowledge, settings=settings)

        call_kwargs = mock_chat.call_args.kwargs
        assert call_kwargs.get("format") == "json"

    @patch("secagent.analyzer.ollama.chat")
    def test_seed_and_temperature_passed(
        self, mock_chat, sql_chunk, knowledge, settings
    ):
        """seed и temperature передаются в options."""
        mock_chat.return_value = _make_llm_response([])

        analyze_chunk(sql_chunk, knowledge, settings=settings)

        options = mock_chat.call_args.kwargs.get("options", {})
        assert options["seed"] == 42
        assert options["temperature"] == pytest.approx(0.1)