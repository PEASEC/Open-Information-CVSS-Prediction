import threading
import time
from queue import Queue, Empty

from loguru import logger
from selenium.webdriver.chrome.webdriver import WebDriver as ChromeWebDriver
from selenium.webdriver.firefox.webdriver import WebDriver as FirefoxWebDriver
from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver

import selenium_scraper
import soup_scraper
from mongo_handler import MongoHandler


# WorkerThread will take reference urls from the submitted queue and call the scraper routine according to the url
class WorkerThread(threading.Thread):
    queue: Queue
    thread_num: int
    stop_flag = False
    driver: ChromeWebDriver | FirefoxWebDriver | RemoteWebDriver

    def __init__(self, queue: Queue, thread: int, mongo_handler: MongoHandler):
        super(WorkerThread, self).__init__(name=f"WorkerThread{thread}")
        self.queue = queue
        self.thread_num = thread
        self.mongo_handler = mongo_handler

    def dispatch(self, url, cve_id: str) -> (bool, str):
        if "www.qualcomm.com" in url:
            return selenium_scraper.parse_qualcomm(driver=self.driver, url=url, cve_id=cve_id)
        elif "support.f5.com" in url:
            return selenium_scraper.parse_f5(driver=self.driver, url=url, cve_id=cve_id)
        elif "wpscan.com" in url:
            return selenium_scraper.parse_wpscan(driver=self.driver, url=url, cve_id=cve_id)
        elif "zerodayinitiative.com" in url:
            return selenium_scraper.parse_zerodayinitiative(driver=self.driver, url=url, cve_id=cve_id)
        elif "ibm.com" in url:
            return selenium_scraper.parse_ibm(driver=self.driver, url=url, cve_id=cve_id)
        elif "tools.cisco.com" in url:
            return selenium_scraper.parse_cisco(driver=self.driver, url=url, cve_id=cve_id)
        elif "talosintelligence.com" in url:
            return soup_scraper.parse_talos(url=url, cve_id=cve_id)
        elif "www.intel.com" in url:
            time.sleep(4)
            return soup_scraper.parse_intel(url=url, cve_id=cve_id)
        elif "snyk.io" in url:
            return selenium_scraper.parse_snyk(driver=self.driver, url=url, cve_id=cve_id)
        else:
            raise ValueError("Unsupported url")

    def run(self):
        logger.info(f"Processing references in Thread {self.thread_num} starting")
        successful_scraped = 0
        not_successful_scraped = 0
        ref: {}
        logger.info("Setting up WebDriver")
        self.driver = selenium_scraper.setup_firefox_driver()
        self.driver.set_page_load_timeout(15)
        self.driver.implicitly_wait(5)
        self.driver.set_script_timeout(3)
        logger.info("Driver created")
        while not self.stop_flag:
            try:
                ref = self.queue.get(block=False)
            except Empty:
                logger.info("Queue is empty. Stopping...")
                break

            cve_id = ref['_id']
            url = ref['url']

            logger.debug(f"Dequeued reference [{cve_id}] -> [{url}]")
            try:
                success, text = self.dispatch(url=url, cve_id=cve_id)
            except ValueError:
                logger.exception("No scraper for this url or wrong input parameters")
                continue
            except Exception as e:
                logger.exception(f'Exception caught')
                continue

            if not success:
                logger.warning("Scraper was not successful. Continue with next ref...")
                not_successful_scraped += 1
            else:
                insert_tex =  text[:50] + '...' if len(text) > 0 else ''
                logger.info(f"Scraped successfully. Text: '{insert_tex}'")
                successful_scraped += 1

            if len(text) == 0:
                logger.info("Text is 0 characters long")

            self.mongo_handler.insert_text_in_mongo(cve_id, url, text)

            ratio: float = (not_successful_scraped + successful_scraped) / \
                               (not_successful_scraped + successful_scraped + self.queue.qsize())
            logger.info(f"[successful/not successful//remaining]: {successful_scraped}/{not_successful_scraped}//"
                        f"{self.queue.qsize()} = {'{:10.4f}'.format(ratio)}")

        self.driver.quit()
        logger.info("Thread stopped, Driver destroyed")
        return successful_scraped
