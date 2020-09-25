#!/usr/bin/python3

from collections import defaultdict
import io
import os
import socket
import pdb
import pprint
import pytz
import time
from dateutil.parser import parse as parse_time

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

from tahoe import Instance, Attribute, Object, Event, Raw, parse
from tahoe.misc import decanonical

import loadconfig


_CONFIG_FILENAME = 'config.json'

_REPORT_BACKEND = loadconfig.get_report_backend(_CONFIG_FILENAME)
Instance._backend = loadconfig.get_tahoe_backend(_CONFIG_FILENAME)

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
    
    r = _REPORT_BACKEND.find({'itype': 'object', 'sub_type': 'query',
                              'data.status': 'wait'})

    orgid = "a441b15fe9a3cf56661190a0b93b9dec7d04127288cc87250967cf3b52894d11"

    for i in r:
        _REPORT_BACKEND.update_one(
                {'_hash': i['_hash']},
                {
                    '$set': {
                        'status': 'wait'
                        }
                }
            )

        ciphertext_query = eval(i['data']['data'][0])
        canonical_query = decrypt_file(ciphertext_query)
        query = decanonical(canonical_query)
                
        query_type = query['type']
        query = query['data']

     
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

            if query_type == 'count':
                sub_type = query['sub_type']
                data = query['data']
                a = Attribute(sub_type, data)
                
                count = a.count(start=start, end=end,
                                category=category, context=context)
                rep = Object('report', [Attribute('count', count)],
                             _backend=_REPORT_BACKEND)
                
            elif query_type == 'related':
                sub_type = query['sub_type']
                data = query['data']
                a = Attribute(sub_type, data)

                summary = query.pop('summary', True)
                
                page = query.pop('page', 1)
                r, curpg, nxtpg = \
                    a.related(itype=return_type, start=start, end=end, page=page)

                if summary:
                    rep = defaultdict(list)
                    for a in r:
                        rep[a['sub_type']].append(a['data'])
                    rep = dict(rep)
                else:
                    rep = r
                rep = Raw('report', rep, orgid, _backend=_REPORT_BACKEND)

            elif query_type == 'threatrank':
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
        except Exception as e:
            rep = Object('report',
                        [Attribute('status', 'error'),
                         Attribute('error', 'invalid query')],
                        _backend=_REPORT_BACKEND)

            print(e) # debug


        _REPORT_BACKEND.update_one({'_hash': i['_hash']},
            {'$set': {'data.status.0': 'ready', 'report_id': rep._hash}})

            
            

        _socket =  i['data']['socket'][0]
        host = _socket['host'][0]
        port = _socket['port'][0]
        nonce = _socket['nonce'][0] 
        
        if host in ['0.0.0.0', 'localhost']:
            host = 'cici-api'

        sock = socket.socket()
        try:
            sock.connect((host, port))
            if not isinstance(nonce, bytes):
                nonce = nonce.encode()
            sock.send(nonce)
        except (ConnectionRefusedError, OSError):
            pass


        # maintain running average of query for priority queue and return
        # that to the user when the status is processing

        
    


