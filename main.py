import random
import signal
import sys
from datetime import date
from queue import Queue
from typing import List

from loguru import logger

from mongo_handler import MongoHandler
from worker_thread import WorkerThread

threads = []


def stop_threads(signal, frame):
    logger.warning(f"Catched {signal}")
    for t in threads:
        t.stop_flag = True


if __name__ == '__main__':
    logger.remove()
    format_str = "<green>{time:MM-DD HH:mm:ss.SS}</green> | <level>{level: <8}</level> | <cyan>{thread.name}-{" \
                 "name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level> "
    logger.add(f"log_{date.today().strftime('%d-%m')}.log", format=format_str, rotation="50 MB", backtrace=True,
               diagnose=True, enqueue=True)
    logger.add(sys.stdout, colorize=True, backtrace=True, diagnose=True, enqueue=True, format=format_str)

    sources = ['zerodayinitiative.com', 'ibm.com', 'tools.cisco.com', 'support.f5.com', 'www.qualcomm.com', 'www.intel.com', 'talosintelligence.com', 'snyk.io']
    SHUFFLE_SOURCE = True
    NUMBER_OF_THREADS = 4
    # TOTAL_NUMBER_OF_REFERENCES = 1000

    logger.info("-------Script Start-------")
    logger.info(f"Sources: {sources}")

    mongo_handler: MongoHandler = MongoHandler()
    reference_urls: List = []

    for base_url in sources:
        refs: List = mongo_handler.get_reference_list_for_url(base_url, only_scraped_but_no_text=False)
        logger.info(f"Found {len(refs)} references for source {base_url}")
        reference_urls.extend(refs)

    if SHUFFLE_SOURCE:
        logger.debug("Shuffled Sources")
        random.shuffle(reference_urls)

    reference_url_queue: Queue = Queue()
    [reference_url_queue.put(e) for e in reference_urls]

    logger.info("Start Processing")

    worker_threads = []
    for i in range(NUMBER_OF_THREADS):
        t = WorkerThread(queue=reference_url_queue, thread=i, mongo_handler=mongo_handler)
        worker_threads.append(t)

    logger.info(f"Starting {NUMBER_OF_THREADS} Threads")

    for t in worker_threads:
        t.start()
        threads.append(t)

    signal.signal(signal.SIGINT, stop_threads)
    signal.signal(signal.SIGTERM, stop_threads)

    logger.info(f"Threads started")
    while len([t for t in worker_threads if t.is_alive()]):
        for t in worker_threads:
            t.join(60)
            if not t.is_alive():
                logger.info(f"Thread {t.name} joined")
    logger.info("All Threads joined.")
