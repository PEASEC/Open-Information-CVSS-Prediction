from datetime import datetime
import glob
import json
import logging
import os
import pathlib
import zipfile

from nvd_connector.nvd_downloader import NVDDownloader
from nvd_connector.nvd_entry import NVDEntry



class NVDFeed:
    '''
    NVDFeed
    '''
    def __init__(self, *years, directory='nvd-files'):
        self.download_directory = directory
        self.feed = {}
        self.timestamps = {}
        downloader = NVDDownloader(directory=self.download_directory)
        for year in years:
            downloader.download(year)
            entries = self.__get_dict(self.__get_file(str(year)))['CVE_Items']
            self.feed[year] = dict((e['cve']['CVE_data_meta']['ID'], e) for e in entries)
            self.timestamps[year] = self.__get_timestamp(year)

    def __getitem__(self, item):
        if str(item).isnumeric():
            return self.feed[item]
        return getattr(self, item)

    def get_cve_entry(self, cve_id):
        _, year, _ = cve_id.split('-')
        if int(year) in self.feed:
            if cve_id in self.feed[int(year)]:
                return NVDEntry(self.feed[int(year)][cve_id])
        logging.error('Can´t find entry with ID: %s', cve_id)
        return None

    def get_year(self, year):
        if year not in self.feed:
            NVDDownloader(directory=self.download_directory).download(year)
            entries = self.__get_dict(self.__get_file(str(year)))['CVE_Items']
            self.feed[year] = dict((e['cve']['CVE_data_meta']['ID'], e) for e in entries)
            self.timestamps[year] = self.__get_timestamp(year)
        return self.feed[int(year)]

    def update_all(self):
        for year in self.feed:
            self.update(year)

    def update(self, year: int):
        time_difference = datetime.now() - self.timestamps[year]
        if time_difference.days > 0:
            downloader = NVDDownloader(self.download_directory)
            downloader.download(year, True)
            logging.info('Updated %s', year)
        else:
            logging.warning('%s is up to date', year)

    def __get_timestamp(self, year: int):
        filename = self.__get_file(year)
        fname = pathlib.Path(filename)
        return datetime.fromtimestamp(fname.stat().st_mtime)

    def __get_file(self, year: int):
        # before calling, ensure the file exists. If not, download the file
        return next(glob.iglob(os.path.join(self.download_directory, f'*{year}*')))

    @staticmethod
    def __get_dict(file: str):
        if file is None:
            logging.error('Failed to load cve data.')
            return {}
        with zipfile.ZipFile(file) as myzip:
            with myzip.open(myzip.namelist()[0]) as archive_file:
                return json.load(archive_file)
