from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from time import sleep
import sys
sys.path.append('/app/')
from config import ADMIN_PASS


class Bot:
    def __init__(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--window-size=1920x1080")
        chrome_options.add_argument("disable-infobars")
        self.driver = webdriver.Chrome(options=chrome_options)
        
        
    def visit(self, url):
        self.driver.set_page_load_timeout(10)  # Timeout in seconds
        self.driver.get('http://127.0.0.1:1337/login')
        self.driver.find_element("name", "username").send_keys("admin")
        self.driver.find_element("name", "password").send_keys(ADMIN_PASS)
        self.driver.find_element("name", "submit").click()
        self.driver.get(url)
        self.driver.refresh()
        sleep(1)
        

    def close(self):
        self.driver.quit()

if __name__ == '__main__':
    import sys
    url=sys.argv[1]
    bot=Bot()
    bot.visit(url)
    bot.close() 
