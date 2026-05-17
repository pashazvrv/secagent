# tests/fixtures/vulnerable_sql_injection.py
"""Fixture: файл с SQL-инъекцией (CWE-89). Содержит 2 функции."""

import sqlite3


def get_user(user_id: str) -> dict:
    """УЯЗВИМОСТЬ: конкатенация строки в SQL-запросе."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id  # CWE-89
    cursor.execute(query)
    return cursor.fetchone()


def create_user(username: str, password: str) -> None:
    """УЯЗВИМОСТЬ: пароль хранится в открытом виде."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # CWE-256: хранение пароля открытым текстом
    cursor.execute(f"INSERT INTO users VALUES ('{username}', '{password}')")
    conn.commit()