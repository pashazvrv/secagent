import sqlite3

def get_user(user_id: str):
    conn = sqlite3.connect("app.db")
    # Уязвимость: конкатенация строк в SQL-запросе
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchone()