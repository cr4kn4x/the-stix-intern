import time 
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
import os 
import sys


class Scraper: 
    def __init__(self, firefox_profile_path: str):
        options = Options()
        options.set_preference("browser.privatebrowsing.autostart", True)
        options.set_preference("javascript.enabled", False)
        # options.set_preference("extensions.allowPrivateBrowsingByDefault", True) # feature removed! Extension needs to be allowed in private browsing tab *manually* during installation

        # firefox profil recommendation: install uBlockOrigin and allow it in private tab - removes noisy ads etc.
        firefox_profile = FirefoxProfile(firefox_profile_path)
        options.profile = firefox_profile

        self.driver = webdriver.Firefox(options=options)


    def scrape(self, url: str, default_wait_for_page_load: int = 8):
        self.driver.get(url)
        
        # wait for page load
        time.sleep(default_wait_for_page_load)
        while self.driver.execute_script("return document.readyState") != "complete":
            time.sleep(0.2)
            pass
        
        # get html 
        html_source = self.driver.page_source
        return html_source
    

    def close(self): 
        self.driver.quit()