import tornado.web

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("username")
    def is_admin(self):
        return self.current_user == b"admin"
        
        
