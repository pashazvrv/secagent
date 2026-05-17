import pytest
from pydantic import ValidationError
from secagent.models import Finding
from pathlib import Path


def test_finding_severity_normalized():
    f = Finding(
        cwe_id="CWE-89",
        severity="HIGH",   # верхний регистр — должен нормализоваться
        title="SQL Injection",
        description="Тест",
        line_start=1,
        line_end=3,
        recommendation="Используй параметры",
        confidence=0.9,
        file_path=Path("test.py"),
    )
    assert f.severity == "high"


def test_finding_invalid_severity():
    with pytest.raises(ValidationError):
        Finding(
            cwe_id="CWE-89",
            severity="UNKNOWN",   # недопустимое значение
            title="Test",
            description="Тест",
            line_start=1,
            line_end=3,
            recommendation="Fix it",
            confidence=0.9,
            file_path=Path("test.py"),
        )


def test_finding_confidence_bounds():
    with pytest.raises(ValidationError):
        Finding(
            cwe_id="CWE-89",
            severity="high",
            title="Test",
            description="Тест",
            line_start=1,
            line_end=3,
            recommendation="Fix it",
            confidence=1.5,   # > 1.0 — недопустимо
            file_path=Path("test.py"),
        )