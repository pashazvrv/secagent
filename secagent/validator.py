# secagent/validator.py
import json
from functools import lru_cache
from pathlib import Path

from secagent.config import settings
from secagent.models import Finding

@lru_cache(maxsize=1)
def _load_valid_cwe_ids() -> frozenset[str]:
    """Загружает множество валидных CWE-ID из data/cwe_ids.json (один раз)."""
    with open(settings.cwe_ids_path) as f:
        return frozenset(json.load(f))

def validate(findings: list[Finding]) -> list[Finding]:
    """Фильтрует и нормализует findings."""
    valid_ids = _load_valid_cwe_ids()
    seen: set[tuple] = set()
    result = []

    for f in findings:
        # 1. Нормализация severity к нижнему регистру
        f = f.model_copy(update={"severity": f.severity.lower()})

        # 2. Проверка CWE-ID
        if f.cwe_id not in valid_ids:
            continue

        # 3. Порог уверенности
        if f.confidence < settings.min_confidence:
            continue

        # 4. Корректность диапазона строк
        if f.line_start <= 0 or f.line_end < f.line_start:
            continue

        # 5. Дедупликация по (cwe_id, file_path, line_start, line_end)
        key = (f.cwe_id, str(f.file_path), f.line_start, f.line_end)
        if key in seen:
            continue
        seen.add(key)

        result.append(f)

    return result