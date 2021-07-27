"""
Functions to initilize tahoe backends, initilize cache DB
and parse api config.

Updated: 4/13/2021 05:39
"""

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
        "db": "tahoe_db",
        "coll": "instance",
    },
    "api": {
        "url": "http://localhost:5000/",
        "token": "",
        "host" : "localhost",
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
        "coll": "instance",
        "secret": "secret"
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
    "Recursively update nested dictionary `d` with items of `u`."
    
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = update(d.get(k, {}), v)
        elif k not in d:
            d[k] = v
    return d


def get_config(filename='config.json', db='all'):
    """Read and parse config from config file."""
  
    try:
        """This block succeeds if `filename` is valid absolute path"""
        with open(filename, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        try:
            """This block succeeds if `filename` is valid relative path"""
            this_dir = os.path.dirname(__file__)
            filename = os.path.join(this_dir, filename)
            with open(filename, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            """`filename` is not valid"""
            config = default
            logging.warning("No config file found, using default config!")
        except json.decoder.JSONDecodeError:
            logging.error(f"Bad config file: {filename}", exc_info=True)
            sys.exit(1)  # 1 = error in linux
    except json.decoder.JSONDecodeError:
        logging.error(f"Bad config file: {filename}", exc_info=True)
        sys.exit(1)  # 1 = error in linux

    update(config, default)
    """
    Updates the input config file with default values.

    e.g. If only `mongo_url` is given for `archive`
    then it is assumed that `db = tahoe_db, coll = instance`.
    """

    if db != 'all':
        if db not in ('api', 'archive', 'cache', 'identity',
                      'report', 'tahoe'):
            logging.error(f"Invalid db name '{db}'!", exc_info=True)
            sys.exit(1)

        config = config[db]

    return config


def get_api(filename='config.json'):
    """
    Get API config from config file.

    Parameters
    ----------
    filename : str
        Relative or absolute path of config file.

    Returns
    -------
    url : str
        Complete URL of the API like `protocol://host:port`.
    token : str
        JWT token to authenticate with the API.
    host : str
        Hostname of the api (e.g. `localhost`).
    """
        
    apiconfig = get_config(filename, 'api')
    return apiconfig['url'], apiconfig['token'], apiconfig['host']


def get_cache_db(filename='config.json'):
    """
    Get Cache DB config from config file.

    Parameters
    ----------
    filename : str
        Relative or absolute path of config file.

    Returns
    -------
    coll : pymongo.collection.Collection
        Stores pointer to raw files and some meta info.
        Lookup pymongo collection to know more.
    fs : gridfs.GridFS
        Stores the actual raw files.
        Lookup pymongo gridfs to know more.
    """
     
    cacheconfig = get_config(filename, 'cache')
    mongo_url = cacheconfig['mongo_url']
    dbname = cacheconfig['db']
    collname = cacheconfig['coll']
    
    client = pymongo.MongoClient(mongo_url, connect=False)
    db = client.get_database(dbname)
    coll = db.get_collection(collname)
    fs = gridfs.GridFS(db)

    return coll, fs

def _get_backend(filename='config.json', db='tahoe'):
    """
    Get analytics/archive/report/tahoe backend.

    This function is used by other functions below.

    Parameters
    ----------
    filename : str
        Relative or absolute path of config file.
    db : {"analytics", "archive", "report", "tahoe"}, default="tahoe"
        

    Returns
    -------
    coll : pymongo.collection.Collection
        Stores pointer to raw files and some meta info.
        Lookup pymongo collection to know more.
    fs : gridfs.GridFS
        Stores the actual raw files.
        Lookup pymongo gridfs to know more.
    """

    if db not in {"analytics", "archive", "report", "tahoe"}:
        raise ValueError(f"Invalid db name: {db}")
    
    config = get_config(filename, db)
    mongo_url = config['mongo_url']
    dbname = config['db']
    collname = config['coll']
    backend = tahoe.MongoBackend(mongo_url, dbname, collname)
    return backend

def get_analytics_backend(filename='config.json'):
    """
    Get archive/analytics/tahoe backend.

    Archive DB is the main storage of CYBEX-P. Use a tahoe_backend
    object to interact with the archive DB. tahoe_backend is
    also known as analytics_backend and archive_backend. So it is
    important that the have the same URL in the config file. See
    the CYBEX-P system architecture diagram to know more about
    archive DB.

    Parameters
    ----------
    filename : str
        Relative or absolute path of config file.
        

    Returns
    -------
    backend : tahoe.backend.MongoBackend
        Data storage. Inherits pymongo.Collection and
        tahoe.Backend. Use an instance of this class to interact
        with the archive/tahoe/analytics/report db.
    """
    
    return _get_backend(filename, db='analytics')

def get_archive_backend(filename='config.json'):
    """
    Get archive/analytics/tahoe backend.

    Archive DB is the main storage of CYBEX-P. Use a tahoe_backend
    object to interact with the archive DB. tahoe_backend is
    also known as analytics_backend and archive_backend. So it is
    important that the have the same URL in the config file. See
    the CYBEX-P system architecture diagram to know more about
    archive DB.

    Parameters
    ----------
    filename : str
        Relative or absolute path of config file.
        

    Returns
    -------
    backend : tahoe.backend.MongoBackend
        Data storage. Inherits pymongo.Collection and
        tahoe.Backend. Use an instance of this class to interact
        with the archive/tahoe/analytics/report db.
    """
        
    return _get_backend(filename, db='archive')

def get_report_backend(filename='config.json'):
    """
    Get report backend.

    Report DB stores anonymized reports. Use a report_backend
    object to interact with the report DB. See the CYBEX-P system
    architecture diagram to know more about report DB.

    Parameters
    ----------
    filename : str
        Relative or absolute path of config file.

    Returns
    -------
    backend : tahoe.backend.MongoBackend
        Data storage. Inherits pymongo.Collection and
        tahoe.Backend. Use an instance of this class to interact
        with the archive/tahoe/analytics/report db.
    """
    
    return _get_backend(filename, db='report')

def get_tahoe_backend(filename='config.json'):
    """
    Get archive/analytics/tahoe backend.

    Archive DB is the main storage of CYBEX-P. Use a tahoe_backend
    object to interact with the archive DB. tahoe_backend is
    also known as analytics_backend and archive_backend. So it is
    important that the have the same URL in the config file. See
    the CYBEX-P system architecture diagram to know more about
    archive DB.

    Parameters
    ----------
    filename : str
        Relative or absolute path of config file.
        

    Returns
    -------
    backend : tahoe.backend.MongoBackend
        Data storage. Inherits pymongo.Collection and
        tahoe.Backend. Use an instance of this class to interact
        with the archive/tahoe/analytics/report db.
    """
    
    return _get_backend(filename, db='tahoe')


def get_identity_backend(filename='config.json'):
    """
    Get identity backend.

    Identity Backend is a different class in TAHOE than MongoBackend.
    The entire identity Module is intentionally kept separate as
    a plugin rather than a part of core TAHOE library.

    Parameters
    ----------
    filename : str
        Relative or absolute path of config file.
        

    Returns
    -------
    backend : tahoe.identity.backend.IdentityBackend
        Data storage. Inherits pymongo.Collection and
        tahoe.MongoBackend. Use an instance of this class to interact
        with the identity db.
    """
    
    idenityconfig = get_config(filename, 'identity')
    mongo_url = idenityconfig['mongo_url']
    dbname = idenityconfig['db']
    collname = idenityconfig['coll']
    backend = tahoe.identity.IdentityBackend(mongo_url, dbname, collname)

    secret = idenityconfig.get('secret', "secret")

    return backend, secret

























