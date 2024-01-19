import os
import re
import logging
import requests

class NVDDownloader:

    def __init__(self,
            directory='nvd-files',
            feeds_url='https://nvd.nist.gov/vuln/data-feeds#JSON_FEED',
            json_feed_url='https://nvd.nist.gov/feeds/json/cve/1.1'):

        self.download_directory = directory
        self.feeds_url = feeds_url
        self.json_feed_url = json_feed_url

        if not os.path.isdir(self.download_directory):
            os.makedirs(self.download_directory)

        self._request = requests.get(self.feeds_url)

    def download(self, year: int, update=False):
        year_filename = [elem for elem in self.__online_files() if str(year) in elem][0]

        if year_filename in self.__downloaded_years() and not update:
            logging.warning('%s already exists', year_filename)
            return

        file_stream = requests.get(f'{self.json_feed_url}/{year_filename}', stream=True)
        with open(os.path.join(self.download_directory, year_filename), 'wb') as myfile:
            for chunk in file_stream:
                myfile.write(chunk)
        logging.info('Sucessfully downloaded %s', year)

    def online_years(self):
        return sorted(re.findall(r'\d{4}', str(self.__online_files())))

    def __online_files(self):
        return re.findall(r'nvdcve-1\.1-\d{4}\.json\.zip', self._request.text)

    def __downloaded_years(self):
        return os.listdir(self.download_directory)
