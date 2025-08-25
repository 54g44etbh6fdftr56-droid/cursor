from handlers.base import BaseHandler
from db.utils import get_searches, clean_old

class ApiPrevSearchesHandler(BaseHandler):
    async def get(self):
        await clean_old()
        results = await get_searches()
        self.write({"searches": results})    
        
        
