import threading
import subprocess
from handlers.base import BaseHandler
from utils.util import rand_search
from urllib.parse import quote

def run_bot(url):
    subprocess.Popen(
        ['python3', 'utils/bot.py', url],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL
    ).wait()  # Reap the child properly


class ReportHandler(BaseHandler):
    # Simulate admin that checks that everything is ok
    async def post(self):
        url = f'http://127.0.0.1:1337/search?query={quote(rand_search(4))}'
        threading.Thread(target=run_bot, args=(url,)).start()
        self.write({"status": "success", "message": "Thanks for your report! We will review it shortly."})
