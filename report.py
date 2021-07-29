"""CYBEX-P Report Module."""

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dateutil.parser import parse as parse_time
import io
from jsonschema import Draft7Validator as D7
from jsonschema.exceptions import ValidationError
import logging
import os
import pdb
import pprint
import pytz
from queue import Queue
import socket
from threading import Thread
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

from tahoe import Instance, Attribute, Object, Event, \
     Raw, Report, parse
from tahoe.identity import Identity, User
from tahoe.misc import decanonical
from tahoe.backend.dam import DamBackend

if __name__ in ["__main__", "__mp_main__", "report"]:
    from exceptions import *
else:
    from .exceptions import *

import loadconfig


# Logging
# -------
##logging.basicConfig(filename = 'report.log') 
logging.basicConfig(level=logging.DEBUG,
    format='\n\n%(asctime)s %(levelname)s: File %(filename)s,' \
        ' line %(lineno)s in %(funcName)s \n%(message)s')


# Global variables

_P = {'_id':0}

API_HOST = None


def configure(api_host, tahoe_backend, report_backend,
              identity_backend, identity_secret="secret"):

    global API_HOST

    API_HOST = api_host
    Instance._backend = tahoe_backend
    Report._backend = report_backend
    Identity._backend = identity_backend
    Identity.secret = identity_secret
    


def get_dtrange(from_=None, to=None, last=None, tzname=None):

    start = 0.0
    end = time.time()
    dtreq = False
    tz = pytz.utc
    utc = pytz.utc

    if last or from_ or to:
        dtreq = True

    if (last and from_) or (last and to):
        raise InvalidParameterValue("Don't specify both 'last' and 'from/to'!")

    def tosec(s):
        spu = {"s":1, "sec":1, "second":1, "seconds":1,
               "m":60, "min":60, "mins":60, "minute":60, "minutes":60,
               "h":3600, "hr":3600, "hrs":3600, "hour":3600, "hours":3600,
               "d":86400, "day":86400, "days":86400,
               "w":604800, "week":604800, "weeks":604800,
               "M":2629800, "month":2629800, "months":2629800,
               "Y":31557600, "year":31557600, "years":31557600}
        try:
            i, m = s.split()
        except ValueError:
            i, m = s[:-1], s[-1]
        except:
            raise InvalidParameterValue(f"Invalid 'last'={last}!")
        
        try:
            sec = int(i)*spu[m]
        except:
            raise InvalidParameterValue(f"Invalid 'last'={last}!")
        else:
            return sec
            
    if last:
        start = end - tosec(last)

    if tzname:
        try:
            tz = pytz.timezone(tzname)
        except pytz.UnknownTimeZoneError:
            raise InvalidParameterValue(f"Invalid 'tzname'={tzname}!")

    if from_:
        try:
            start = float(from_)
        except ValueError:
            start = parse_time(from_)
            start = tz.localize(start).astimezone(utc).timestamp()
        except ValueError:
            raise InvalidParameterValue(f"Invalid 'from'={from_}!")
        

    if to:
        try:
            end = float(to)
        except ValueError:
            end = parse_time(to)
            end = tz.localize(end).astimezone(utc).timestamp()
        except ValueError:
            raise InvalidParameterValue(f"Invalid 'to'={to}!")
        
    return start, end


def decrypt_file(file_in, fpriv_name="priv.pem"):
    if isinstance(file_in, bytes):
        file_in = io.BytesIO(file_in)

    this_dir = os.path.dirname(__file__)
    fpriv_name = os.path.join(this_dir, fpriv_name)

    private_key = RSA.import_key(open(fpriv_name).read())
    enc_session_key, nonce, tag, ciphertext = [
        file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
    ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return data.decode("utf-8")


schema_qdata = {
    "title": "qdata",
    "description": "Validate qdata for all qtype.",
    "type": "object",
##    "required": ["sub_type", "data"],
    "properties": {
        "sub_type": {"enum": [
            "asn",
            "body",
            "domain",
            "email_addr",
            "filename",
            "hostname",
            "sha256",
            "subject",
            "ip",
            "ipv4",
            "url"
            ]},
        "data": {"type": ["boolean", "integer", "null", "number", "string"]},
        "from": {"type": "string"},
        "to": {"type": "string"},
        "last": {"type": "string"},
        "tzname": {"type": "string"},
        "category": {"enum":["all","benign","malicious","unknown"]},
        "context": {"enum":["all","benign","malicious","unknown"]},
        "return_type": {"enum":["all","attribute","event","object","session"]},
        "level": {"type": "integer", "minimum":1, "maximum":3},
        "page": {"type": "integer", "minimum":1},
        "summary": {"type":"boolean"},
        "summary_graph": {"type":"boolean"},
        "_hash": {"type":"string", "pattern": "^[A-Fa-f0-9]{64}$"}
        },
    "additionalProperties": False
    }

validate_qdata = D7(schema_qdata).validate

schema_count = {
    "title": "count",
    "description": "Validate qdata for qtype=count.",
    "type": "object",
    "required": ["sub_type", "data"]
    }

validate_qdata_count = D7(schema_count).validate


def get_report(tdql):
    """Generate report from TDQL."""

    status = 'ready'
    rep_data = None
    current_page = 1
    next_page = 1

    try:

        canonical_qdata = eval(tdql.qdata)
        if tdql.encrypted:        
            canonical_qdata = decrypt_file(canonical_qdata)
        qdata = decanonical(canonical_qdata)

        validate_qdata(qdata)
        if tdql.qtype == 'count':
            validate_qdata_count(qdata)

        sub_type = qdata.pop('sub_type', None)
        if sub_type == 'ip':  # quick fix
            sub_type = 'ipv4'

        data = qdata.pop('data', None)
         
        from_ = qdata.pop('from', None)
        to = qdata.pop('to', None)
        last = qdata.pop('last', None)
        tzname = qdata.pop('tzname', None)

        category = qdata.pop('category', 'all')
        context = qdata.pop('context', 'all')
        return_type = qdata.pop('return_type', 'all')

        level = qdata.pop('level', 1)
        page = qdata.pop('page', 1)
        
        summary = qdata.pop('summary', True)
        summary_graph = qdata.pop('summary_graph', False)

        _hash = qdata.pop('_hash', '')
        _hash = _hash.upper()

        start, end = get_dtrange(from_, to, last, tzname)

        user = User._backend.find_user(_hash=tdql.userid, parse=True)
        if user is None:
            raise InvalidUserError("User does not exist in identity db!")
        _dam = DamBackend(user, Instance._backend)

        # Count
        if tdql.qtype == 'count':
            a = Attribute(sub_type, data)
            a._backend = _dam
            rep_data = a.count(start=start, end=end, category=category,
                               context=context, limit=100)

        # Related
        elif tdql.qtype == 'related':
            a = Attribute(sub_type, data)
            a._backend = _dam
            rep_data, current_page, next_page = \
                a.related(itype=return_type, level=level,
                          start=start, end=end, page=page,
                          category=category, context=context,
                          summary=summary, summary_graph=summary_graph)

        # ThreatRank
        elif tdql.qtype == 'threatrank':
            e = Instance._backend.find_one({'_hash': _hash}, {'_id': 0})
            e = parse(e, Event._backend, validate=False)
            rep_data = e.threatrank()

        else:
            raise InvalidParameterValue(f"Invalid query type = {tdql.qtype}!")

    except (ValidationError, InvalidParameterValue, InvalidUserError) as e:
        status = 'failed'
        rep_data = f"{repr(e)}! -- {str(e)}"
  
    except (KeyboardInterrupt, SystemExit):
            raise

    except:
        logging.exception("Exception!", exc_info=True)
        status = 'failed'
        rep_data = "Failed to generate report due to server error!"
        
    tdql.status = status
    rep = Report(tdql.qtype, tdql.userid, time.time(),
                 rep_data, current_page, next_page)
    return rep


def process_query(tdql):
    """Process one TDQL."""

    try:
        rep = get_report(tdql)
        tdql.report_id = rep._hash
            
        sock_data =  tdql.data['socket'][0]
        host = sock_data['host'][0]
        port = sock_data['port'][0]
        nonce = sock_data['nonce'][0] 

        if host in ['0.0.0.0', '127.0.0.1', 'localhost']:
            host = API_HOST

        sock = socket.socket()
        try:
            sock.connect((host, port))
            if not isinstance(nonce, bytes):
                nonce = nonce.encode()
            sock.send(nonce)
        except (ConnectionRefusedError, OSError):
            pass

    except (KeyboardInterrupt, SystemExit):
            raise

    except:
        logging.error("report", exc_info=True)
        
        status = 'failed'
        rep_data = "Failed to process query due to server error!"
        current_page = 1
        next_page = 1

        tdql.status = status
        rep = Report(tdql.qtype, tdql.userid, time.time(),
                 rep_data, current_page, next_page)
        tdql.report_id = rep._hash
        

def get_query(queue):
    while True:
        await_hash = '64d6f946a875d0fc05774ef1e1fe4eaa4b2' \
                     'f1700c71df9a1bb33b0c0cfcbad89'
        q = {'itype': 'object', 'sub_type': 'query', '_cref': await_hash}
        r = Report._backend.find(q, _P)
        for i in r:
            tdql = parse(i, backend=Report._backend, validate=False)
            tdql.status = 'processing'
            queue.put(tdql)

def main():            

    queue = Queue()

    thread_producer = Thread(target=get_query, args=(queue, ))
    
    while True:
        try:
            # Producer
            if not thread_producer.is_alive():
                thread_producer.start()

            # Consumer
            with ThreadPoolExecutor(64) as executor:
                executor.map(process_query, iter(queue.get, None))

        except (KeyboardInterrupt, SystemExit):
            raise

        except:
            logging.exception('', exc_info=True)



if __name__ == "__main__":
    api_host = loadconfig.get_api_config()['host']
    instance_backend = loadconfig.get_tahoe_backend()
    report_backend = loadconfig.get_report_backend()
    identity_backend, identity_secret = loadconfig.get_identity_backend()

    configure(api_host, instance_backend, report_backend,
              identity_backend, identity_secret)

    main()


