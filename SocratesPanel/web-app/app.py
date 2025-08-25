import tornado.ioloop
import tornado.web
from handlers.routes.auth import LoginHandler, RegisterHandler, LogoutHandler
from handlers.routes.not_found import NotFoundHandler
from handlers.routes.search import SearchHandler
from handlers.routes.quotes import QuotesHandler
from handlers.routes.panel import PanelHandler
from handlers.api.report import ReportHandler
from handlers.api.searches import ApiPrevSearchesHandler
from handlers.api.quotes import ApiQuotesHandler
from db.connection import create_tables,fill_tables
from os import urandom

def make_app():
    return tornado.web.Application([
        (r"/()", tornado.web.StaticFileHandler, {"path": "static", "default_filename": "index.html"}),
        (r"/quotes", QuotesHandler),
        (r"/login", LoginHandler),  
        (r"/register", RegisterHandler),
        (r"/logout", LogoutHandler),
        (r"/search", SearchHandler),
        (r"/api/prev_searches", ApiPrevSearchesHandler),
        (r"/api/report", ReportHandler),
        (r"/api/quotes", ApiQuotesHandler),
        (r"/panel", PanelHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": "static"}),
        (r"^(?!/static/).*", NotFoundHandler),  # Catch-all for 404 errors
    ], cookie_secret=urandom(20), autoescape=None, template_path="templates", login_url="/login")


if __name__ == "__main__":
    print("Server started on http://localhost:8888")
    app = make_app()
    app.listen(8888)
    loop = tornado.ioloop.IOLoop.current()
    loop.run_sync(create_tables)
    loop.run_sync(fill_tables)
    loop.start()
