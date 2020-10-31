"""Read config.json file and initialize database or Tahoe Backend."""

import collections.abc
import gridfs
import json
import logging
import os
import pdb
import pymongo
import sys

import tahoe


default = {
    "analytics": { 
        "mongo_url": "mongodb://localhost:27017/",
        "db": "analytics_db",
        "coll": "instance",
    },
    "archive": { 
        "mongo_url": "mongodb://localhost:27017/",
        "db": "tahoe_db",
        "coll": "instance",
    },
    "cache": {
        "mongo_url": "mongodb://localhost:27017/",
        "db": "cache_db",
        "coll": "file_entries"
    },
    "identity": {
        "mongo_url": "mongodb://localhost:27017/",
        "db": "identity_db",
        "coll": "instance"
    },
    "report": {
        "mongo_url": "mongodb://localhost:27017/",
        "db": "report_db",
        "coll": "instance"
    },
    "tahoe": {
        "mongo_url": "mongodb://localhost:27017/",
        "db": "tahoe_db",
        "coll": "instance"
    }
}

def update(d, u):
    "Recursively update nested dictionary."
    
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = update(d.get(k, {}), v)
        elif k not in d:
            d[k] = v
    return d


def get_config(filename='config.json', db='all'):
    """Read config from file `config.json`."""
  
    try:
        this_dir = os.path.dirname(__file__)
        filename = os.path.join(this_dir, filename)
        with open(filename, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        config = default
        logging.warning("No config file found, using default config")
    except json.decoder.JSONDecodeError:
        logging.error("Bad configuration file!", exc_info=True)
        sys.exit(1)  # 1 = error in linux

    update(config, default)

    if db != 'all':
        if db not in ('api', 'archive', 'cache', 'identity',
                      'report', 'tahoe'):
            logging.error(f"Invalid db name '{db}'!", exc_info=True)
            sys.exit(1)

        config = config[db]

    return config


def get_api(filename='config.json'):
    apiconfig = get_config(filename, 'api')
    return apiconfig['url'], apiconfig['host'], \
           apiconfig['host'], apiconfig['port']


def get_cache_db(filename='config.json'):
    cacheconfig = get_config(filename, 'cache')
    mongo_url = cacheconfig['mongo_url']
    dbname = cacheconfig['db']
    collname = cacheconfig['coll']
    
    client = pymongo.MongoClient(mongo_url, connect=False)
    db = client.get_database(dbname)
    coll = db.get_collection(collname)
    fs = gridfs.GridFS(db)

    return coll, fs

def get_backend(filename='config.json', db='tahoe'):
    reportconfig = get_config(filename, db)
    mongo_url = reportconfig['mongo_url']
    dbname = reportconfig['db']
    collname = reportconfig['coll']
    backend = tahoe.MongoBackend(mongo_url, dbname, collname)
    return backend

def get_analytics_backend(filename='config.json'):
    return get_backend(filename, db='analytics')

def get_archive_backend(filename='config.json'):
    return get_backend(filename, db='archive')

def get_report_backend(filename='config.json'):
    return get_backend(filename, db='report')

def get_tahoe_backend(filename='config.json'):
    return get_backend(filename, db='tahoe')


def get_identity_backend(filename='config.json', db='identity'):
    identityconfig = get_config(filename, db)
    mongo_url = identityconfig['mongo_url']
    dbname = identityconfig['db']
    collname = identityconfig['coll']
    backend = tahoe.identity.IdentityBackend(mongo_url, dbname, collname)
    return backend



















