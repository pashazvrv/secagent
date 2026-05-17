# tests/fixtures/safe_code.py
"""Fixture: безопасный код без уязвимостей."""

import sqlite3


def get_user_safe(user_id: int) -> dict:
    """Параметризованный запрос — безопасно."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def add_numbers(a: int, b: int) -> int:
    """Чистая функция без уязвимостей."""
    return a + b