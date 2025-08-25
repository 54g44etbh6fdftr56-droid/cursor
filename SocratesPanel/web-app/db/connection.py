import aiosqlite
from contextlib import asynccontextmanager
import json

DB_PATH = "./app.db"
with open("db/quotes.json", "r") as f:
    QUOTES = json.load(f)
words = list(set([word for quote in QUOTES for word in quote.split()]))


@asynccontextmanager
async def get_connection():
    conn = await aiosqlite.connect(DB_PATH)
    try:
        yield conn
    finally:
        await conn.close()

async def create_tables():
    async with get_connection() as conn:
        from config import ADMIN_PASS
        from db.utils import hash_password
        password = hash_password(ADMIN_PASS)
        await conn.executescript(f"""
                DROP TABLE IF EXISTS users;
                DROP TABLE IF EXISTS quotes;
                DROP TABLE IF EXISTS searches;
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                );
                CREATE TABLE quotes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quote TEXT UNIQUE,
                    verified BOOLEAN DEFAULT 0,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_quotes_verified ON quotes (verified);
                CREATE TABLE searches (
                    query TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO users (username, password) VALUES ('admin', '{password}');
                """)
        await conn.commit()
        
async def fill_tables():
    sql_query = ''
    for quote in QUOTES:
        sql_query += f"""INSERT INTO quotes (quote, verified) VALUES ("{quote}", 1);\n"""
    async with get_connection() as conn:
        await conn.executescript(sql_query)
        await conn.commit()
            