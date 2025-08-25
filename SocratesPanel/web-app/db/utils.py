import hashlib
from db.connection import get_connection

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
        
async def insert_user(username, password) -> bool:
    hashed_pw = hash_password(password)
    try:
        async with get_connection() as conn:
            await conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            await conn.commit()
    except Exception as e:
        return False
    return True

async def login_user(username, password) -> bool:
    async with get_connection() as conn:
        async with conn.execute("SELECT password FROM users WHERE username=?", (username,)) as cursor:
            result = await cursor.fetchone()
    return result and result[0] == hash_password(password)
    
async def insert_quote(quote, verified) -> bool:
    async with get_connection() as conn:
        try:
            await conn.execute("INSERT INTO quotes (quote, verified) VALUES (?, ?)", (quote, verified))
            await conn.commit()
        except Exception as e:
            return False
    return True
    
async def insert_search(query):
    async with get_connection() as conn:
        await conn.execute("INSERT INTO searches (query) VALUES (?)", (query,))
        await conn.commit()

async def get_searches():
    async with get_connection() as conn:
        async with conn.execute("SELECT query FROM searches ORDER BY timestamp DESC") as cursor:
            results = await cursor.fetchall()
            return [row[0] for row in results]
    
async def clean_old():
    async with get_connection() as conn:
        await conn.execute("""
            DELETE FROM searches WHERE timestamp < datetime('now', '-2 minutes')
        """)
        await conn.commit()
        
        