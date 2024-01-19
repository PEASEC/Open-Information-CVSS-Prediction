from datetime import datetime

from pymongo import MongoClient
from pymongo.collection import Collection


class MongoHandler:
    collection: Collection

    SCRAPED_BUT_NO_TEXT_PIPELINE_EXTENSION = {
        '$match': {
            'scraped_selenium': {
                '$exists': True
            },
            'text_selenium': {
                '$exists': False
            }
        }
    }

    def __init__(self, url: str = '127.0.0.1', db_name: str = 'nvd', collection_name: str = 'nvd_all'):
        self.collection = self.__get_mongo_colection(url, db_name, collection_name)

    def get_reference_list_for_url(self, url: str, only_scraped: bool = False, only_not_scraped: bool = False,
                                   only_scraped_but_no_text: bool = False) -> []:
        pipeline: [] = self.__get_pipeline_for_url(url)

        if only_scraped:
            pipeline.append(MongoHandler.SCRAPED_PIPELINE_EXTENSION)
        elif only_not_scraped:
            pipeline.append(MongoHandler.NOT_SCRAPED_PIPELINE_EXTENSION)
        elif only_scraped_but_no_text:
            pipeline.append(MongoHandler.SCRAPED_BUT_NO_TEXT_PIPELINE_EXTENSION)
        return list(self.collection.aggregate(pipeline))

    def __get_mongo_colection(self, url: str, db_name: str, collection_name: str) -> Collection:
        mongo_client = MongoClient(url)
        mongo_db = mongo_client[db_name]
        mongo_collection = mongo_db[collection_name]
        return mongo_collection

    SCRAPED_PIPELINE_EXTENSION = {
        '$match': {
            'scraped_selenium': {
                '$exists': True
            }
        }
    }

    NOT_SCRAPED_PIPELINE_EXTENSION = {
        '$match': {
            'scraped_selenium': {
                '$exists': False
            }
        }
    }

    def __get_pipeline_for_url(self, url: str) -> []:
        pipeline = [
            {
                '$unwind': {
                    'path': '$reference_data'
                }
            }, {
                '$replaceRoot': {
                    'newRoot': {
                        '$mergeObjects': [
                            {
                                '_id': '$_id'
                            }, '$reference_data'
                        ]
                    }
                }
            }, {
                '$match': {
                    'url': {
                        '$regex': f'.*{url}*'
                    }
                }
            }, {
                '$project': {
                    'url': True,
                    'text_selenium': True,
                    'scraped_selenium': True
                }
            }
        ]

        return pipeline

    def get_scraped_without_text(self) -> []:
        pipeline = [
            {
                '$unwind': {
                    'path': '$reference_data'
                }
            }, {
                '$replaceRoot': {
                    'newRoot': {
                        '$mergeObjects': [
                            '$$ROOT', '$reference_data'
                        ]
                    }
                }
            }, {
                '$project': {
                    'reference_data': 0,
                    'cpe': 0,
                    'cvssv2': 0,
                    'cwe': 0,
                    'references': 0
                }
            }, {
                '$match': {
                    'scraped_selenium': {
                        '$exists': True
                    },
                    'text_selenium': {
                        '$exists': False
                    }
                }
            }
        ]

        return list(self.collection.aggregate(pipeline))

    def insert_text_in_mongo(self, id: str, url: str, text: str) -> None:
        full_record = self.collection.find_one({"_id": id})

        for i, e in enumerate(full_record['reference_data']):
            if e['url'] == url:
                full_record['reference_data'][i]['scraped_selenium'] = datetime.now()
                if text and len(text):
                    full_record['reference_data'][i]['text_selenium'] = text

        self.collection.update_one({'_id': id}, {'$set': full_record})
