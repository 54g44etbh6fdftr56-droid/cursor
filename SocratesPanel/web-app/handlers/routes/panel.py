from handlers.base import BaseHandler
import tornado.web
from tornado.httpclient import AsyncHTTPClient, HTTPError

class PanelHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self):
        if not self.is_admin():
            self.set_status(403)
            self.render("error.html", error="You are not authorized to access this page.")
            return
        self.render("panel.html", error=None, result="")
     
    @tornado.web.authenticated   
    async def post(self):
        if not self.is_admin():
            self.set_status(403)
            self.render("error.html", error="You are not authorized to access this page.")
            return
        url = self.get_argument("url", default=None)
        if not url:
            self.set_status(400)
            self.render("panel.html", error="Missing URL parameter.",result="")
            return
        if not url.startswith("http"):
            self.set_status(400)
            self.render("panel.html", error="Invalid URL format.", result="")
            return
        headers = {}
        for key in self.request.arguments:
            if key != "url":
                headers[key] = self.get_argument(key)
        try:
            http_client = AsyncHTTPClient()
            response = await http_client.fetch(url, headers=headers, request_timeout=3)
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' in content_type or 'text/plain' in content_type:
                try:
                    result = response.body.decode('utf-8')
                except UnicodeDecodeError:
                    result = response.body.decode('latin-1')
            else:
                self.set_status(400)
                self.render("panel.html", error="Unsupported content type.", result="")
                return
            self.render("panel.html", error=None, result=result)
            
        except HTTPError as e:
            self.set_status(e.code)
            self.render("panel.html", error=f"HTTP Error: {str(e)}", result="")
            
        except Exception as e:
            self.set_status(500)
            self.render("panel.html", error=f"Error fetching URL: {str(e)}", result="")
        
        
        

        
        