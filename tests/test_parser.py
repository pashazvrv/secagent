# tests/test_parser.py
"""Тесты модуля parser.py."""

import pytest
from pathlib import Path

from secagent.models import CodeFile
from secagent.parser import parse_file


def make_file(content: str, language: str = "python", name: str = "test.py") -> CodeFile:
    return CodeFile(
        path=Path(name),
        language=language,
        content=content,
        size_bytes=len(content.encode()),
    )


class TestPythonParser:
    def test_finds_two_functions(self):
        code = (Path(__file__).parent / "fixtures/vulnerable_sql_injection.py").read_text(encoding="utf-8")
        file = make_file(code)
        chunks = parse_file(file)
        names = [c.name for c in chunks]
        assert "get_user" in names
        assert "create_user" in names

    def test_safe_file_chunks(self):
        code = (Path(__file__).parent / "fixtures/safe_code.py").read_text(encoding="utf-8")
        chunks = parse_file(make_file(code))
        assert len(chunks) == 2

    def test_line_numbers_correct(self):
        code = "def foo():\n    pass\n\ndef bar():\n    pass\n"
        chunks = parse_file(make_file(code))
        assert chunks[0].name == "foo"
        assert chunks[0].line_start == 1
        assert chunks[1].name == "bar"
        assert chunks[1].line_start == 4

    def test_empty_file_fallback(self):
        chunks = parse_file(make_file("# just a comment\nx = 1\n"))
        assert len(chunks) == 1
        assert chunks[0].chunk_type == "module"

    def test_syntax_error_fallback(self):
        chunks = parse_file(make_file("def broken(\n    pass"))
        # tree-sitter терпимо к ошибкам, но если нет чанков — fallback
        assert len(chunks) >= 1

    def test_class_chunked(self):
        code = "class Foo:\n    def bar(self):\n        pass\n"
        chunks = parse_file(make_file(code))
        # Минимум — класс как один чанк
        assert any(c.name == "Foo" for c in chunks)

    def test_unsupported_language_fallback(self):
        file = CodeFile(
            path=Path("script.rb"),
            language="ruby",
            content="def hello; end",
            size_bytes=14,
        )
        chunks = parse_file(file)
        assert len(chunks) == 1
        assert chunks[0].chunk_type == "module"