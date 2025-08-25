from handlers.base import BaseHandler
from db.connection import get_connection
from db.utils import insert_search

class SearchHandler(BaseHandler):
    async def get(self):
        query = self.get_argument("query", default=None)
        if not query:
            self.render("search.html", search = None, verified_only = False, results=[])
            return
        
        await insert_search(query)
            
        verified_only = self.get_argument("verified_only", default=False)
        
        # Search for each word
        words = query.split()
        placeholders = " OR ".join(["LOWER(quote) LIKE ?"] * len(words))
        values = [f"%{word.lower()}%" for word in words]
        values = tuple(values)
        if verified_only:
            sql_query = f"SELECT quote FROM quotes WHERE verified = 1 AND ({placeholders})"
        else:
            sql_query = f"SELECT quote FROM quotes WHERE ({placeholders})"  
                                
        async with get_connection() as conn:
            async with conn.execute(sql_query, values) as cursor:
                results = await cursor.fetchall()
                results = [row[0] for row in results]
        self.render("search.html", search = query, verified_only=verified_only, results=results)
        
        

        
        