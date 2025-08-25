from handlers.base import BaseHandler
import tornado.web
from db.connection import get_connection
from db.utils import insert_quote

class QuotesHandler(BaseHandler):
    async def get(self):
        # Will show quotes
        # 5 per page
        page = int(self.get_argument("page", default=1))
        if page < 1:
            page = 1
            
        async with get_connection() as conn:
            cursor = await conn.execute("SELECT * FROM quotes ORDER BY timestamp ASC LIMIT 5 OFFSET ?", (5 * (page - 1),))
            quotes = await cursor.fetchall()
            await cursor.close()
            if quotes:
                quotes = [{"id": quote[0], "quote": quote[1], "verified": quote[2]} for quote in quotes]
            else:
                quotes = []            
        self.render("quotes.html", quotes=quotes, page=page)
     