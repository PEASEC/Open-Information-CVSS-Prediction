from time import sleep

import requests
from bs4 import BeautifulSoup, Tag
from loguru import logger
from requests import Timeout


def parse_talos(url: str, cve_id: str) -> (bool, str):
    text = ""
    if not url or not isinstance(url, str) or not len(url):
        raise ValueError('URL invalid')

    if not cve_id or not isinstance(cve_id, str) or not len(cve_id):
        raise ValueError('cve_id invalid')

    logger.debug(f"Requesting URL '{url}'")

    try:
        retry_count = 0
        while not retry_count >= 2:
            website = requests.get(url)
            if website.status_code == 200:
                logger.debug(f"Request was successful")
                break
            else:
                retry_count += 1
                logger.debug(f"Request was not successful, retry {retry_count}")
                sleep(1)
        if retry_count >= 2:
            logger.warning("Unable to get response")
            return False, text
    except Timeout:
        logger.warning("Timeout")
        return False, text
    except:
        logger.exception("Exception while requesting page")
        return False, text

    logger.debug(f"Parsing page")
    try:
        talos_soup = BeautifulSoup(website.content, 'html.parser')

        summary = talos_soup.find(id='summary')
        summary_parent_div = summary.parent
        summary_ps = summary_parent_div.find("p")
        text = summary_ps.text

        details: Tag = talos_soup.find(id='details')
        h4s = summary_parent_div.findAll("h4")
        stop_on_next = False
        if not details:
            if text:
                return True, text
            else:
                return False, text
        if len(h4s):
            for sib in details.next_siblings:
                if not sib == "\n":
                    if sib.text == "Timeline":
                        break
                    if sib.name == "h4" and stop_on_next:
                        break
                    if sib.name == "h4" and cve_id in sib.text:
                        stop_on_next = True
                    if sib.name == "p":
                        text += sib.text
        else:
            for sib in details.next_siblings:
                if not sib == "\n":
                    if sib.text == "Timeline":
                        break
                    if sib.name == "p":
                        text += sib.text
    except:
        logger.exception("Exception while parsing")
        # logger.verbose(talos_soup.prettify())
        return False, text

    logger.info(f"Parsing was successful, returning text of length {len(text)}")
    return True, text


def parse_intel(url: str, cve_id: str) -> (bool, str):
    text = ""
    if not url or not isinstance(url, str) or not len(url):
        raise ValueError('URL invalid')

    if not cve_id or not isinstance(cve_id, str) or not len(cve_id):
        raise ValueError('cve_id invalid')

    logger.debug(f"Requesting URL '{url}'")

    try:
        website = requests.get(url)
        logger.debug(f"Request was successful")
    except Timeout:
        logger.warning("Timeout")
        return False, text
    except:
        logger.exception("Exception while requesting page")
        return False, text

    logger.debug(f"Parsing page")
    try:
        intel_soup = BeautifulSoup(website.content, 'html.parser')

        summary_header = intel_soup.find(name='h2', text=lambda s: "Summary" in s)
        if not summary_header:
            logger.warning("Could not find summary header on page")
            return False, text
        summary_block = summary_header.findNext('p')
        text = summary_block.text
        details_header = intel_soup.find(name='h2', text=lambda s: 'Vulnerability Details' in s)
        for block in details_header.next_siblings:
            if not block == "\n":
                if block.name == "h2":
                    break
                if block.name == "p" and cve_id in block.text:
                    details_text = block.find_next("p").text.replace("Description:", "")
                    text += details_text
                    break
    except:
        logger.exception("Exception while parsing")
        return False, text

    logger.info(f"Parsing was successful, returning text of length {len(text)}")
    return True, text