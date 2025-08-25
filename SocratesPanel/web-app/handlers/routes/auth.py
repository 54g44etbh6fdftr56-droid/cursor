from handlers.base import BaseHandler
from db.utils import hash_password, insert_user, login_user
from utils.util import valid_username

class RegisterHandler(BaseHandler):
    async def get(self):
        self.render("register.html", error=None)

    async def post(self):
        username = self.get_argument("username", default=None)
        password = self.get_argument("password", default=None)
        if not username or not password:
            self.render("register.html", error="Missing parameters.")
            return
        if not valid_username(username):
            self.render("register.html", error="Invalid username.")
            return
        if not await insert_user(username, password):
            self.render("register.html", error="User already exists.")
            return

        self.redirect("/login")


class LoginHandler(BaseHandler):
    async def get(self):
        self.render("login.html", error=None)

    async def post(self):
        username = self.get_argument("username", default=None)
        password = self.get_argument("password", default=None)
        if not username or not password:
            self.render("login.html", error="Missing parameters.")
            return
        if await login_user(username, password):
            self.set_signed_cookie("username", username, httponly=True)
            self.redirect("/quotes")
        else:
            self.render("login.html", error="Invalid credentials.")
            
class LogoutHandler(BaseHandler):
    async def get(self):
        self.clear_cookie("username")
        self.redirect("/")
        
