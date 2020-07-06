"""api.loadconfig"""

import gridfs
import json
import logging
import pdb
import pymongo
import sys

import tahoe

# default config
default = {
    "mongo": { 
        "mongo_url" : "mongodb://localhost:27017/",
        "cache_db" : "cache_db",
        "cache_coll": "file_entries",
        "report_db" : "report_db",
        "report_coll": "instance",
        "identity_db" : "identity_db",
        "identity_coll": "instance",
        "tahoe_db" : "tahoe_db",
        "tahoe_coll": "instance",
    }
}


def get_config():
    """Read config from file `config.json`."""
  
    try: 
        with open('config.json', 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        config = default
        logging.warning("No config file found, using default config")
    except json.decoder.JSONDecodeError:
        logging.error("Bad configuration file!", exc_info=True)
        sys.exit(1) # 1 = error in linux

    for k, v in default.items():
        if k not in config:
            config[k] = v

    return config


def get_mongoconfig():
    """Configuration of Identity Backend."""
  
    config = get_config()
    mongoconfig = config['mongo']
    for k, v in default['mongo'].items():
        if k not in mongoconfig:
            mongoconfig[k] = v
    return mongoconfig
        

def get_identity_backend():
    mongoconfig = get_mongoconfig()
    mongo_url = mongoconfig['mongo_url']
    dbname = mongoconfig['identity_db']
    collname = mongoconfig['identity_coll']
    backend = tahoe.identity.IdentityBackend(mongo_url, dbname, collname)
    return backend


def get_report_backend():
    mongoconfig = get_mongoconfig()
    mongo_url = mongoconfig['mongo_url']
    dbname = mongoconfig['report_db']
    collname = mongoconfig['report_coll']
    backend = tahoe.MongoBackend(mongo_url, dbname, collname)
    return backend


def get_tahoe_backend():
    mongoconfig = get_mongoconfig()
    mongo_url = mongoconfig['mongo_url']
    dbname = mongoconfig['tahoe_db']
    collname = mongoconfig['tahoe_coll']
    backend = tahoe.MongoBackend(mongo_url, dbname, collname)
    return backend


def get_cache_db():
    mongoconfig = get_mongoconfig()
    mongo_url = mongoconfig['mongo_url']
    dbname = mongoconfig['cache_db']
    collname = mongoconfig['cache_coll']
    
    client = pymongo.MongoClient(mongo_url, connect=False)
    db = client.get_database(dbname)
    coll = db.get_collection(collname)
    fs = gridfs.GridFS(db)

    return coll, fs



  
































