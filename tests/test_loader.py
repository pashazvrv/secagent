# tests/test_loader.py
"""Тесты модуля loader.py."""

import pytest
from pathlib import Path

from secagent.loader import load_files
from secagent.models import CodeFile


def _write(tmp_path: Path, rel: str, content: str = "x = 1") -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


class TestSingleFile:
    def test_python_file_loaded(self, tmp_path):
        f = _write(tmp_path, "app.py")
        result = list(load_files(f))
        assert len(result) == 1
        assert result[0].language == "python"

    def test_unknown_extension_skipped(self, tmp_path):
        f = _write(tmp_path, "notes.txt")
        assert list(load_files(f)) == []

    def test_large_file_skipped(self, tmp_path, monkeypatch):
        f = _write(tmp_path, "big.py", "x = 1")
        monkeypatch.setattr("secagent.loader._MAX_FILE_SIZE", 0)
        assert list(load_files(f)) == []


class TestDirectory:
    def test_finds_multiple_languages(self, tmp_path):
        _write(tmp_path, "a.py")
        _write(tmp_path, "b.js")
        _write(tmp_path, "c.go")
        result = list(load_files(tmp_path))
        langs = {cf.language for cf in result}
        assert langs == {"python", "javascript", "go"}

    def test_excludes_node_modules(self, tmp_path):
        _write(tmp_path, "src/app.py")
        _write(tmp_path, "node_modules/lib.py")
        result = list(load_files(tmp_path))
        paths = [cf.path.name for cf in result]
        assert "app.py" in paths
        assert "lib.py" not in paths

    def test_excludes_venv(self, tmp_path):
        _write(tmp_path, "main.py")
        _write(tmp_path, ".venv/site-packages/pkg.py")
        result = list(load_files(tmp_path))
        assert len(result) == 1

    def test_language_filter(self, tmp_path):
        _write(tmp_path, "a.py")
        _write(tmp_path, "b.js")
        result = list(load_files(tmp_path, languages=["python"]))
        assert all(cf.language == "python" for cf in result)

    def test_respects_gitignore(self, tmp_path):
        (tmp_path / ".gitignore").write_text("secret.py\n")
        _write(tmp_path, "main.py")
        _write(tmp_path, "secret.py")
        result = list(load_files(tmp_path))
        names = [cf.path.name for cf in result]
        assert "main.py" in names
        assert "secret.py" not in names

    def test_non_recursive(self, tmp_path):
        _write(tmp_path, "root.py")
        _write(tmp_path, "sub/nested.py")
        result = list(load_files(tmp_path, recursive=False))
        names = [cf.path.name for cf in result]
        assert "root.py" in names
        assert "nested.py" not in names