"""
Тесты для rag/sources/owasp.py и rag/sources/semgrep.py

Запуск: pytest tests/test_knowledge_sources.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from secagent.rag.sources.owasp import parse_owasp_cheatsheets, _detect_cwe, _split_by_h2
from secagent.rag.sources.semgrep import parse_semgrep_rules, _normalize_cwe


# ─────────────────────────────────────────────────────────
# OWASP тесты
# ─────────────────────────────────────────────────────────

@pytest.fixture
def owasp_dir(tmp_path: Path) -> Path:
    """Создаёт минимальную структуру OWASP cheatsheets."""
    cheatsheets = tmp_path / "cheatsheets"
    cheatsheets.mkdir()

    # Файл с SQL Injection
    (cheatsheets / "SQL_Injection_Prevention_Cheat_Sheet.md").write_text(
        """\
# SQL Injection Prevention Cheat Sheet

## Introduction

SQL injection (SQLi) refers to an injection attack wherein an attacker can execute
malicious SQL statements that control a web application's database server.

## Defense Option 1: Prepared Statements

Prepared Statements with Parameterized Queries in Python:

```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

This approach is safe for Python and Java applications.

## Defense Option 2: Stored Procedures

Stored procedures add an extra layer of protection by encapsulating the SQL logic.
""",
        encoding="utf-8",
    )

    # Пустой файл — должен быть пропущен
    (cheatsheets / "Empty_Cheat_Sheet.md").write_text("", encoding="utf-8")

    # Файл без H2 заголовков
    (cheatsheets / "Simple_Guide.md").write_text(
        "# Simple Guide\n\nThis is a short guide without sections.",
        encoding="utf-8",
    )

    return cheatsheets


class TestOwaspParser:
    def test_returns_chunks(self, owasp_dir: Path) -> None:
        chunks = parse_owasp_cheatsheets(owasp_dir)
        assert len(chunks) > 0

    def test_source_is_owasp(self, owasp_dir: Path) -> None:
        chunks = parse_owasp_cheatsheets(owasp_dir)
        for ch in chunks:
            assert ch.source == "owasp"

    def test_sql_injection_linked_to_cwe89(self, owasp_dir: Path) -> None:
        chunks = parse_owasp_cheatsheets(owasp_dir)
        sql_chunks = [ch for ch in chunks if ch.cwe_id == "CWE-89"]
        assert len(sql_chunks) > 0, "SQL Injection cheat sheet должен быть привязан к CWE-89"

    def test_empty_file_skipped(self, owasp_dir: Path) -> None:
        chunks = parse_owasp_cheatsheets(owasp_dir)
        titles = [ch.title for ch in chunks]
        # Empty_Cheat_Sheet не должен давать чанков
        assert not any("Empty" in t for t in titles)

    def test_python_language_detected(self, owasp_dir: Path) -> None:
        chunks = parse_owasp_cheatsheets(owasp_dir)
        # Хотя бы один чанк должен определить Python
        langs_all = set()
        for ch in chunks:
            langs_all.update(ch.languages)
        assert "python" in langs_all

    def test_text_not_empty(self, owasp_dir: Path) -> None:
        chunks = parse_owasp_cheatsheets(owasp_dir)
        for ch in chunks:
            assert ch.text.strip(), f"Пустой текст: {ch.title}"

    def test_text_length_limit(self, owasp_dir: Path) -> None:
        chunks = parse_owasp_cheatsheets(owasp_dir)
        for ch in chunks:
            assert len(ch.text) <= 2000

    def test_nonexistent_dir_returns_empty(self, tmp_path: Path) -> None:
        result = parse_owasp_cheatsheets(tmp_path / "nonexistent")
        assert result == []

    def test_metadata_has_required_keys(self, owasp_dir: Path) -> None:
        chunks = parse_owasp_cheatsheets(owasp_dir)
        for ch in chunks:
            assert "source" in ch.metadata
            assert "file" in ch.metadata
            assert "section" in ch.metadata


class TestSplitByH2:
    def test_splits_correctly(self) -> None:
        md = "# Title\n\nIntro\n\n## Section 1\n\nContent 1\n\n## Section 2\n\nContent 2"
        sections = _split_by_h2(md)
        assert len(sections) == 3  # Intro + 2 sections

    def test_no_h2_returns_whole_file(self) -> None:
        md = "# Title\n\nJust some content without H2."
        sections = _split_by_h2(md)
        assert len(sections) == 1

    def test_empty_sections_skipped(self) -> None:
        md = "## Section 1\n\nContent\n\n## Empty\n\n\n\n## Section 3\n\nMore content"
        sections = _split_by_h2(md)
        # Empty section должна быть пропущена
        titles = [s[0] for s in sections]
        assert "Empty" not in titles


class TestDetectCwe:
    @pytest.mark.parametrize("stem,expected", [
        ("SQL_Injection_Prevention_Cheat_Sheet", "CWE-89"),
        ("XSS_Prevention_Cheat_Sheet", "CWE-79"),
        ("CSRF_Prevention_Cheat_Sheet", "CWE-352"),
        ("Path_Traversal_Guide", "CWE-22"),
        ("Something_Completely_Unknown", None),
    ])
    def test_detect_cwe(self, stem: str, expected: str | None) -> None:
        result = _detect_cwe(stem)
        assert result == expected


# ─────────────────────────────────────────────────────────
# Semgrep тесты
# ─────────────────────────────────────────────────────────

@pytest.fixture
def semgrep_dir(tmp_path: Path) -> Path:
    """Создаёт минимальную структуру Semgrep rules."""
    rules_dir = tmp_path / "python" / "security"
    rules_dir.mkdir(parents=True)

    # Правило с CWE → должно быть включено
    rule_with_cwe = {
        "rules": [
            {
                "id": "sql-injection-string-concat",
                "pattern": 'cursor.execute("SELECT * FROM " + $X)',
                "message": "SQL injection via string concatenation",
                "languages": ["python"],
                "severity": "ERROR",
                "metadata": {
                    "cwe": "CWE-89: Improper Neutralization of SQL Commands",
                    "confidence": "HIGH",
                    "severity": "high",
                },
            }
        ]
    }
    (rules_dir / "sqli.yml").write_text(yaml.dump(rule_with_cwe), encoding="utf-8")

    # Правило без CWE → должно быть пропущено
    rule_no_cwe = {
        "rules": [
            {
                "id": "generic-rule",
                "pattern": "eval($X)",
                "message": "Avoid eval",
                "languages": ["python"],
                "severity": "WARNING",
                "metadata": {},  # нет CWE
            }
        ]
    }
    (rules_dir / "generic.yml").write_text(yaml.dump(rule_no_cwe), encoding="utf-8")

    # Правило для неподдерживаемого языка → должно быть пропущено
    rule_unknown_lang = {
        "rules": [
            {
                "id": "ruby-sqli",
                "pattern": "ActiveRecord::Base.find($X)",
                "message": "SQLi in Ruby",
                "languages": ["ruby"],
                "severity": "ERROR",
                "metadata": {"cwe": "CWE-89"},
            }
        ]
    }
    (rules_dir / "ruby_rule.yml").write_text(yaml.dump(rule_unknown_lang), encoding="utf-8")

    # Правило с несколькими языками
    rule_multi_lang = {
        "rules": [
            {
                "id": "path-traversal",
                "pattern": "open($INPUT)",
                "message": "Potential path traversal",
                "languages": ["python", "javascript"],
                "severity": "ERROR",
                "metadata": {"cwe": "CWE-22: Path Traversal"},
            }
        ]
    }
    (rules_dir / "path.yml").write_text(yaml.dump(rule_multi_lang), encoding="utf-8")

    return rules_dir  # ← ИСПРАВЛЕНО: возвращаем rules_dir, где лежат файлы


class TestSemgrepParser:
    def test_returns_chunks(self, semgrep_dir: Path) -> None:
        chunks = parse_semgrep_rules(semgrep_dir)
        assert len(chunks) > 0

    def test_source_is_semgrep(self, semgrep_dir: Path) -> None:
        chunks = parse_semgrep_rules(semgrep_dir)
        for ch in chunks:
            assert ch.source == "semgrep"

    def test_skips_rules_without_cwe(self, semgrep_dir: Path) -> None:
        chunks = parse_semgrep_rules(semgrep_dir)
        ids = [ch.title for ch in chunks]
        assert not any("generic-rule" in t for t in ids)

    def test_skips_unsupported_languages(self, semgrep_dir: Path) -> None:
        chunks = parse_semgrep_rules(semgrep_dir)
        ids = [ch.title for ch in chunks]
        assert not any("ruby-sqli" in t for t in ids)

    def test_sql_injection_rule_included(self, semgrep_dir: Path) -> None:
        chunks = parse_semgrep_rules(semgrep_dir)
        sqli_chunks = [ch for ch in chunks if ch.cwe_id == "CWE-89"]
        assert len(sqli_chunks) > 0

    def test_languages_correct(self, semgrep_dir: Path) -> None:
        chunks = parse_semgrep_rules(semgrep_dir)
        sqli = next(ch for ch in chunks if ch.cwe_id == "CWE-89" and "sql" in ch.title.lower())
        assert "python" in sqli.languages

    def test_multiline_languages(self, semgrep_dir: Path) -> None:
        chunks = parse_semgrep_rules(semgrep_dir)
        path_chunks = [ch for ch in chunks if ch.cwe_id == "CWE-22"]
        assert any("javascript" in ch.languages for ch in path_chunks)

    def test_pattern_in_examples(self, semgrep_dir: Path) -> None:
        chunks = parse_semgrep_rules(semgrep_dir)
        sqli = next(ch for ch in chunks if ch.cwe_id == "CWE-89" and "sql" in ch.title.lower())
        assert len(sqli.examples) > 0

    def test_nonexistent_dir_returns_empty(self, tmp_path: Path) -> None:
        result = parse_semgrep_rules(tmp_path / "nonexistent")
        assert result == []

    def test_text_not_empty(self, semgrep_dir: Path) -> None:
        chunks = parse_semgrep_rules(semgrep_dir)
        for ch in chunks:
            assert ch.text.strip()

    def test_metadata_has_cwe_id(self, semgrep_dir: Path) -> None:
        chunks = parse_semgrep_rules(semgrep_dir)
        for ch in chunks:
            assert "cwe_id" in ch.metadata
            assert ch.metadata["cwe_id"] == ch.cwe_id


class TestNormalizeCwe:
    @pytest.mark.parametrize("raw,expected", [
        ("CWE-89: SQL Injection", "CWE-89"),
        ("CWE-22", "CWE-22"),
        (["CWE-79: XSS", "CWE-80"], "CWE-79"),
        (None, None),
        ("not a cwe", None),
        (89, "CWE-89"),  # числовой ID тоже обрабатываем
    ])
    def test_normalize_cwe(self, raw, expected) -> None:
        result = _normalize_cwe(raw)
        assert result == expected