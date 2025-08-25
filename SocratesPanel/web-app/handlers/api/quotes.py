from handlers.base import BaseHandler
from db.utils import insert_quote
from utils.util import valid_quote

class ApiQuotesHandler(BaseHandler):
    async def post(self):
        if not self.current_user:
            self.set_status(403)
            self.write({"status": "error", "message": "Unauthorized. Please log in first."})
            return
        quote = self.get_argument("quote",default=None)
        if not quote:
            self.set_status(400)
            self.write({"status": "error", "message": "Missing quote parameter."})
            return
        
        if not valid_quote(quote):
            self.set_status(400)
            self.write({"status": "error", "message": "Please refrain from using special characters."})
            return

        if await insert_quote(quote, 0):
            self.write({"status": "success", "message": "Quote added successfully."})
        else:
            self.set_status(500)
            self.write({"status": "error", "message": "Quote already exists."})
        return