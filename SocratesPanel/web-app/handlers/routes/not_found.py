from handlers.base import BaseHandler

class NotFoundHandler(BaseHandler):
    def get(self):
        self.set_status(404)
        self.render("error.html", error="Page not found.")
        
    def post(self):
        self.set_status(404)
        self.render("error.html", error="Page not found.")