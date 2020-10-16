#!/usr/bin/python3

from collections import defaultdict
from dateutil.parser import parse as parse_time
import io
import logging
import os
import pdb
import pprint
import pytz
import socket
import time


from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

from tahoe import Instance, Attribute, Object, Event, Raw, Report, parse
from tahoe.misc import decanonical

import loadconfig


### Logging
##logging.basicConfig(filename = 'report.log') 
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(filename)s:%(lineno)s' \
    ' - %(funcName)() --  %(message)s'
    )



_CONF_FNAME = 'config.json'

_P = {'_id':0}
_API_URL, _API_HOST, _API_PORT, _API_PROTO = loadconfig.get_api(_CONF_FNAME)
_REPORT_BACKEND = loadconfig.get_report_backend(_CONF_FNAME)
Instance._backend = loadconfig.get_tahoe_backend(_CONF_FNAME)


def get_dtrange(from_=None, to=None, last=None, tzname=None):
    start = 0.0
    end = time.time()
    dtreq = False
    tz = pytz.utc


    if last or from_ or to:
        dtreq = True

    if (last and from_) or (last and to):
        raise ValueError

    def tosec(s):
        spu = {"s":1, #"sec":1, "second":1, "seconds":1,
               "m":60, #"min":60, "mins":60, "minute":60, "minutes":60,
               "h":3600, #"hr":3600, "hrs":3600, "hour":3600, "hours":3600
               "d":86400, #"day":86400, "days":86400,
               "w":604800, #"week":604800, "weeks":604800,
               "M":2629800, #"month":2629800, "months":2629800
               "Y":31557600} #"year":31557600, "years":31557600}
        try:
            m = spu[s[-1]]
        except KeyError:
            raise ValueError
        else:
            return int(s[:-1]) * m
            
    if last:
        start = end - tosec(last)

    if tzname:
        try:
            tz = pytz.timezone(tzname)
        except pytz.UnknownTimeZoneError:
            raise ValueError

    if from_:
        try:
            start = float(from_)
        except ValueError:
            start = parse_time(from_)
            start = tz.localize(start).astimezone(utc).timestamp()
        except ValueError:
            raise
        

    if to:
        try:
            end = float(to)
        except ValueError:
            end = parse_time(end)
            end = tz.localize(end).astimezone(utc).timestamp()
        except ValueError:
            raise
        
    return start, end


def decrypt_file(file_in, fpriv_name="priv.pem"):
    """
    decrypts the cipher text query. Checks to make sure the that the instance of the passed file is 
    in the correct format of byte values. A path to the private name file is opened and the private key
    is then pulled from there. The session key, nonce, tag, and cipher text are then pulled from the
    passed 'file_in'. The query is then decrypted with the privatte RSA and AES session keys. The data
    is then returned via a utf-8 decode.

    Parameters
    ---------
    file_in: bytes value of integers
        the encrypted query data
    fpive_name: String
        RSA private key
    
    
    """
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


while True:
    await_hash = '64d6f946a875d0fc05774ef1e1fe4eaa4b2f1700c71df' \
                 '9a1bb33b0c0cfcbad89'
    
    r = _REPORT_BACKEND.find({'itype': 'object', 'sub_type': 'query',
                              '_cref': await_hash}, _P)

    orgid = "a441b15fe9a3cf56661190a0b93b9dec7d04127288cc872509" \
            "67cf3b52894d11"
    
    for i in r:
        tdql = parse(i, backend=_REPORT_BACKEND)
        tdql.status = 'processing'
        
        ciphertext_query = eval(tdql.qdata)
        canonical_query = decrypt_file(ciphertext_query)
        query = decanonical(canonical_query)
     
        from_ = query.pop('from', None)
        to = query.pop('to', None)
        last = query.pop('last', None)
        tzname = query.pop('tzname', None)
        try:
            start, end = get_dtrange(from_, to, last, tzname)
        except e:
            rep = Object('report',
                    [Attribute('status', 'error'),
                     Attribute('error', 'invalid query')],
                    _backend=_REPORT_BACKEND)

        context = query.pop('context', 'all')
        category = query.pop('category', 'all')
        return_type = query.pop('return_type', 'all')

        try:
            if tdql.qtype == 'count':
                sub_type = query['sub_type']
                data = query['data']
                a = Attribute(sub_type, data)
                
                count = a.count(start=start, end=end,
                                category=category, context=context)
                rep = Report(tdql.qtype, tdql.userid, tdql.timestamp, count,
                             _backend=_REPORT_BACKEND)
                
            elif tdql.qtype == 'related':
                sub_type = query['sub_type']
                data = query['data']
                a = Attribute(sub_type, data)

                summary = query.pop('summary', True)
                
                page = query.pop('page', 1)
                r, curpg, nxtpg = a.related(itype=return_type,
                                            start=start, end=end, page=page)

                if summary:
                    rel = defaultdict(list)
                    for a in r:
                        if a['itype'] != 'attribute':
                            continue
                        rel[a['sub_type']].append(a['data'])
                    rel = dict(rel)
                else:
                    rel = r
                rep = Report(tdql.qtype, tdql.userid, tdql.timestamp,
                             rel, curpg, nxtpg, _backend=_REPORT_BACKEND)

            elif tdql.qtype == 'threatrank':
                itype = query['itype']
                _hash = query['hash']
                e = Instance._backend.find_one({'_hash': _hash}, {'_id': 0})
                e = parse(e, Event._backend, validate=False)
                
                tr = e.threatrank()             
                rep = Object('report', [Attribute('threatrank', tr),
                    Attribute('hash', _hash)], _backend=_REPORT_BACKEND)

            else:
                rep = Object('report',
                        [Attribute('status', 'error'),
                         Attribute('error', 'invalid query')],
                        _backend=_REPORT_BACKEND)
                query.status = 'failed'
        

            tdql.status = 'ready'
            tdql.report_id = rep._hash
                
            _socket =  i['data']['socket'][0]
            host = _socket['host'][0]
            port = _socket['port'][0]
            nonce = _socket['nonce'][0] 
            

            if host in ['0.0.0.0', '127.0.0.1', 'localhost']:
                host = _API_HOST

            sock = socket.socket()
            try:
                sock.connect((host, port))
                if not isinstance(nonce, bytes):
                    nonce = nonce.encode()
                sock.send(nonce)
            except (ConnectionRefusedError, OSError):
                pass

        except Exception as e:
            rep = Object('report',
                        [Attribute('status', 'error'),
                         Attribute('error', 'report server error')],
                        _backend=_REPORT_BACKEND)

            logging.error(f"Report failed {i['_hash']}", exc_info=True)
            tdql.status = 'failed'


        # maintain running average of query for priority queue and return
        # that to the user when the status is processing

        
    


