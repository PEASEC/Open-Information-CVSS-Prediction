# Implementations of various web scraping routines using selenium

from __future__ import annotations

import random
from http.client import RemoteDisconnected
from typing import List

from loguru import logger
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.webdriver import WebDriver as ChromeWebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.webdriver import WebDriver as FirefoxWebDriver
from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.relative_locator import locate_with
from selenium.webdriver.support.wait import WebDriverWait
from urllib3.exceptions import ProtocolError

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",

]


def setup_driver(headless: bool = False, minimize: bool = False, random_user_agent: bool = False) -> ChromeWebDriver:
    options = ChromeOptions()
    # options.add_argument("--window-size=1920x1080")
    options.add_argument("verbose")
    options.add_argument('--ignore-ssl-errors=yes')
    options.add_argument('--ignore-certificate-errors')
    # options.add_argument('start-maximized')
    if headless:
        options.add_argument('--headless')
    if random_user_agent:
        options.add_argument(f"user_agent={random.choice(user_agents)}")
    # driver = webdriver.Chrome(options=options)
    driver = webdriver.Chrome(options=options)
    if minimize:
        driver.minimize_window()
    return driver


def setup_firefox_driver() -> FirefoxWebDriver:
    options = FirefoxOptions()
    # options.headless = True
    options.accept_insecure_certs = True
    capabilities = {
        "acceptInsecureCerts": True
    }

    driver = FirefoxWebDriver(options=options, capabilities=capabilities)
    return driver


def setup_remote_driver(executor_url: str = "http://localhost:4444/wd/hub",
                        browser_type: str = "chrome",
                        headless: bool = False) -> webdriver:
    options = ChromeOptions()
    options.add_argument("--headless")
    # options.add_argument("--whitelisted-ips")
    options.add_argument("--no-sandbox")
    options.add_argument("--verbose")
    options.add_argument('--ignore-ssl-errors=yes')
    options.add_argument('--ignore-certificate-errors')
    driver = webdriver.Remote(command_executor=executor_url,
                              desired_capabilities={"browserName": browser_type}, options=options)
    return driver


def parse_wpscan(driver: ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver, url: str, cve_id: str) -> (bool, str):
    text = None
    if driver is None or not isinstance(driver, ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver):
        raise ValueError('WebDriver invalid')

    if not url or not isinstance(url, str) or not len(url):
        raise ValueError('URL invalid')

    if not cve_id or not isinstance(cve_id, str) or not len(cve_id):
        raise ValueError('cve_id invalid')

    logger.debug(f"Requesting URL '{url}'")

    try:
        driver.get(url)
        logger.debug(f"Request was successful")
    except TimeoutException:
        logger.warning("Timeout")
        driver.execute_script("window.stop();")
    except Exception:
        logger.exception(f"Request was not successful")
        return False, text

    logger.debug(f"Parsing page")
    try:
        element = driver.find_element(By.CSS_SELECTOR, ".titleContainer_preText__uaOYR")
        text = element.text
    except Exception as e:
        logger.exception("Exception while parsing")
        return False, text

    logger.info(f"Parsing was successful, returning text of length {len(text)}")
    return True, text


def parse_zerodayinitiative(driver: ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver, url: str, cve_id: str) -> (
bool, str):
    text = None
    if driver is None or not isinstance(driver, ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver):
        raise ValueError('WebDriver invalid')

    if not url or not isinstance(url, str) or not len(url):
        raise ValueError('URL invalid')

    if not cve_id or not isinstance(cve_id, str) or not len(cve_id):
        raise ValueError('cve_id invalid')

    logger.debug(f"Requesting URL '{url}'")

    try:
        driver.get(url)
        logger.debug(f"Request was successful")
    except TimeoutException:
        logger.warning("Timeout")
        driver.execute_script("window.stop();")
    except Exception as e:
        logger.exception("Exception while parsing")
        return False, text

    logger.debug(f"Parsing page")
    try:
        header = WebDriverWait(driver, 10).until(lambda d: d.find_element(By.XPATH, "//*[contains(text(), 'VULNERABILITY DETAILS')]"))
        row = header.find_element(By.XPATH, "..")
        td2 = row.find_elements(By.XPATH, ".//*")[1]
        text = td2.text
        text = text.replace('\n', ' ')
    except Exception as e:
        logger.exception("Exception while parsing")
        return False, text

    logger.info(f"Parsing was successful, returning text of length {len(text)}")
    return True, text


def parse_ibm(driver: ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver, url: str, cve_id: str) -> (bool, str):
    text = None
    if driver is None or not isinstance(driver, ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver):
        raise ValueError('WebDriver invalid')

    if not url or not isinstance(url, str) or not len(url):
        raise ValueError('URL invalid')

    if not cve_id or not isinstance(cve_id, str) or not len(cve_id):
        raise ValueError('cve_id invalid')

    logger.debug(f"Requesting URL '{url}'")

    try:
        driver.get(url)
        logger.debug(f"Request was successful")
    except TimeoutException:
        logger.warning("Timeout")
        driver.execute_script("window.stop();")
    except Exception as e:
        logger.exception("Exception while parsing")
        return False, text

    not_found_element = driver.find_elements(By.XPATH, f"//*[contains(text(), 'We’re sorry!')]")
    if len(not_found_element):
        logger.warning("Page is 404")
        return False, text

    forbidden_element = driver.find_elements(By.XPATH, f"//*[contains(text(), 'The page you requested cannot be "
                                                       f"displayed. 403: Forbidden')]")
    if len(forbidden_element):
        logger.warning("Page is 403")
        return False, text

    try:
        block = WebDriverWait(driver, 10).until(lambda d: d.find_element(By.CSS_SELECTOR, "div.clearfix.text-formatted"))
        block_text: str = block.text
        split_block_text = block_text.split('\n')
        cve_indexs = [index for index, element in enumerate(split_block_text) if cve_id in element]
    except Exception as e:
        logger.critical(f"Unable to parse page")
        return False, text

    if len(cve_indexs) == 1:
        index = cve_indexs[0]
        text = split_block_text[index + 1]
        text = text.replace('DESCRIPTION:', '')
        text = text.strip()
        return True, text
    else:
        logger.warning(f"Could not find cve_id text on page")

    return False, text


def parse_cisco(driver: ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver, url: str, cve_id: str) -> (bool, str):
    text = None
    if driver is None or not isinstance(driver, ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver):
        raise ValueError('WebDriver invalid')

    if not url or not isinstance(url, str) or not len(url):
        raise ValueError('URL invalid')

    if not cve_id or not isinstance(cve_id, str) or not len(cve_id):
        raise ValueError('cve_id invalid')

    logger.debug(f"Requesting URL '{url}'")

    try:
        driver.get(url)
        logger.debug(f"Request was successful")
    except TimeoutException:
        logger.warning("Timeout")
        driver.execute_script("window.stop();")
    except Exception as e:
        logger.exception(f"Request was not successful")
        return False, text

    logger.debug(f"Parsing page")
    try:
        summary_field = WebDriverWait(driver, 20).until(lambda d: d.find_element(By.ID, 'summaryfield'))
        text: str = summary_field.text
        text = text.replace('\n', '')
        text = text.split('This advisory is available at the following link:')[0]
        text = text.replace('This advisory will be updated as additional information becomes available.', '')
    except Exception as e:
        logger.exception("Exception while parsing")
        return False, text

    logger.info(f"Parsing was successful, returning text of length {len(text)}")
    return True, text


def parse_qualcomm(driver: ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver, url: str, cve_id: str) -> (bool, str):
    text = None
    if driver is None or not isinstance(driver, ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver):
        raise ValueError('WebDriver invalid')

    if not url or not isinstance(url, str) or not len(url):
        raise ValueError('URL invalid')

    if not cve_id or not isinstance(cve_id, str) or not len(cve_id):
        raise ValueError('cve_id invalid')

    if not url.endswith('bulletin') and not url.endswith('bulletin/'):
        logger.warning(f"URL '{url}' does not end with 'bulletin' and is therefor invalid")
        return False, text

    logger.debug(f"Requesting URL '{url}'")

    try:
        driver.get(url)
        logger.debug(f"Request was successful")
    except TimeoutException:
        logger.warning("Timeout")
        driver.execute_script("window.stop();")
    except Exception:
        logger.exception(f"Request was not successful")
        return False, text

    logger.debug("Testing if pages is valid")
    not_found_header = driver.find_elements(By.XPATH, "//*[contains(text(), 'We could not find the page you requested')]")
    if len(not_found_header):
        logger.debug("Request returned Not-Found page")
        url_parts = url.split('/')
        identifier = url_parts[-1].split('-')
        new_url = f'https://www.qualcomm.com/company/product-security/bulletins/{identifier[0]}-{identifier[1]}-security-{identifier[2]}'
        logger.info(f"Trying new url: {new_url}")
        try:
            driver.get(new_url)
            logger.info(f'Request with new URL was successful')
        except Exception:
            logger.exception(f"Request with new URL was not successful")
            return False, text

    logger.debug(f"Parsing page")
    try:
        headers = WebDriverWait(driver, 10).until(lambda driver :driver.find_elements(By.TAG_NAME, 'h4'))
        for header_element in headers:
            if header_element.text == cve_id:
                correct_header = header_element
                tds = driver.find_elements(locate_with(By.TAG_NAME, 'td').below(correct_header))
                td = tds[2]
                text = td.text
                logger.info(f"Parsing was successful, returning text of length {len(text)}")
                return True, text

        logger.critical(f"Unable to parse page")
        return False, text
    except Exception as e:
        logger.exception("Exception while parsing")
        return False, text


def parse_f5(driver: ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver, url: str, cve_id: str) -> (bool, str):
    text = None
    if driver is None or not isinstance(driver, ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver):
        raise ValueError('WebDriver invalid')

    if not url or not isinstance(url, str):
        raise ValueError('url invalid')

    if not cve_id or not isinstance(cve_id, str):
        raise ValueError("cve_id invalid")

    logger.debug(f"Requesting URL '{url}'")
    try:
        driver.get(url)
        logger.debug(f"Request was successful")
    except TimeoutException:
        logger.warning("Timeout")
        driver.execute_script("window.stop();")
    except Exception:
        logger.exception(f"Request was not successful")
        return False, text

    logger.debug(f"Parsing page")
    try:
        section: WebElement = WebDriverWait(driver, 10).until(
            lambda d: d.find_element(By.CSS_SELECTOR, 'div.article-content.ng-binding'))
        # section: WebElement = driver.find_element(By.CSS_SELECTOR, 'div.article-content.ng-binding')
        li_elements: List[WebElement] = section.find_elements(By.TAG_NAME, 'li')
        for li_element in li_elements:
            a_elements: List[WebElement] = li_element.find_elements(By.TAG_NAME, 'a')
            if len(a_elements) and a_elements[0].text == cve_id:
                logger.warning(f'parse_f5: text not usable/identical to NVD')
                return False, text
        text: str = section.text
        text = text.replace(f'({cve_id})', '')
        text = text.replace('\nImpact\n', '')
        text = text.replace('\n', '')
        logger.info(f"Parsing was successful, returning text of length {len(text)}")
        return True, text
    except Exception as e:
        logger.exception("Exception while parsing")
        return False, text

def parse_snyk(driver: ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver, url: str, cve_id: str) -> (bool, str):
    text = ""
    if driver is None or not isinstance(driver, ChromeWebDriver | RemoteWebDriver | FirefoxWebDriver):
        raise ValueError('WebDriver invalid')

    if not url or not isinstance(url, str):
        raise ValueError('url invalid')

    if not cve_id or not isinstance(cve_id, str):
        raise ValueError("cve_id invalid")

    logger.debug(f"Requesting URL '{url}'")
    try:
        driver.get(url)
        logger.debug(f"Request was successful")
    except TimeoutException:
        logger.warning("Timeout")
        driver.execute_script("window.stop();")
    except (RemoteDisconnected, ProtocolError):
        logger.critical("Driver forced to shutdown")
        return False, text
    except Exception:
        logger.exception(f"Request was not successful")
        return False, text

    logger.debug("Checking if page is valid")
    try:
        h1s: List[WebElement] = driver.find_elements(By.TAG_NAME, "h1")
        for h1 in h1s:
            if h1.text == "Invalid vulnerability":
                logger.info("Requested Page is invalid")
                return False, text
    except:
        logger.exception("Exception while checking validity of page")
        return False, text

    logger.debug(f"Parsing page")
    try:
        markdown_sections: List[WebElement] = driver.find_elements(By.CSS_SELECTOR, "div.markdown-section")
        for sec in markdown_sections:
            overview_headers = sec.find_elements(By.XPATH, f"//*[contains(text(), 'Overview')]")
            for h in overview_headers:
                if h.is_displayed():
                    overview_text: List[WebElement] = sec.find_elements(By.TAG_NAME, "p")
                    for t in overview_text:
                        text += t.text

        logger.info(f"Parsing was successful, returning text of length {len(text)}")
        return True, text
    except (RemoteDisconnected, ProtocolError):
        logger.critical("Driver forced to shutdown")
        return False, text
    except Exception as e:
        logger.exception("Exception while parsing")
        return False, text
