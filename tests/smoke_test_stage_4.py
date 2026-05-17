"""Smoke-тест 4 этапа: retriever + analyzer end-to-end на одном чанке.

Запускать вручную при поднятом Ollama и собранной ChromaDB:
    python smoke_test_stage4.py

Требования:
  - `secagent index --rebuild` уже выполнен (data/chroma заполнен)
  - Ollama запущен: `ollama serve`
  - Модели скачаны: qwen2.5-coder:7b и nomic-embed-text
"""

import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

# Добавляем корень проекта в путь
sys.path.insert(0, str(Path(__file__).parent))

from secagent.config import Settings
from secagent.models import CodeChunk
from secagent.rag.retriever import Retriever
from secagent.analyzer import analyze_chunk

VULNERABLE_CODE = '''\
import sqlite3

def get_user_by_name(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # УЯЗВИМОСТЬ: конкатенация пользовательского ввода в SQL
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
'''

def main() -> None:
    settings = Settings()

    chunk = CodeChunk(
        file_path=Path("app/users.py"),
        language="python",
        chunk_type="function",
        name="get_user_by_name",
        code=VULNERABLE_CODE,
        line_start=1,
        line_end=9,
    )

    print("=" * 60)
    print(f"Анализируем чанк: {chunk.name} ({chunk.file_path})")
    print("=" * 60)

    # 1. Retrieval
    print("\n[1/2] Retrieval из ChromaDB...")
    retriever = Retriever(settings=settings)
    knowledge = retriever.retrieve(chunk, top_k=3)  # False вместо True
    print(f"  Найдено {len(knowledge)} чанков знаний:")
    for k in knowledge:
        print(f"    - [{k.cwe_id}] {k.title}")

    # 2. Analysis
    print("\n[2/2] LLM-анализ...")
    findings = analyze_chunk(chunk, knowledge, settings=settings)
    print(f"\n  Результат: {len(findings)} finding(s)")
    for f in findings:
        print(f"\n  [{f.severity.upper()}] {f.cwe_id}: {f.title}")
        print(f"    Строки: {f.line_start}–{f.line_end}")
        print(f"    Уверенность: {f.confidence:.0%}")
        print(f"    Описание: {f.description}")
        print(f"    Рекомендация: {f.recommendation}")

    if findings and findings[0].cwe_id == "CWE-89":
        print("\n✅ SMOKE TEST PASSED: CWE-89 обнаружена")
    else:
        print("\n❌ SMOKE TEST FAILED: CWE-89 не найдена")
        sys.exit(1)


if __name__ == "__main__":
    main()