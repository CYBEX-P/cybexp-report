"""unittests for report.report.py"""

import builtins as B
import hashlib
import json
import pdb
import time
import unittest

import tahoe
from tahoe import TDQL
from tahoe.backend import NoBackend
from tahoe.tests.test_backend import MongoBackendTest
from tahoe.tests.identity.test_backend import setUpBackend as setUpIdBackend
from tahoe.identity import User, Org

if __name__ != 'report.tests.test_report':
    import os, sys
    J = os.path.join
    sys.path = [J('..','..',), '..'] + sys.path

from report import *


def setUpModule():
    assert API_HOST is None
    assert isinstance(Instance._backend, NoBackend)
    assert isinstance(Report._backend, NoBackend)
    
    api_host = ''
    tahoe_backend = MongoBackendTest.setUpClass(dbname='tahoe_db')
    report_backend = MongoBackendTest.setUpClass(dbname='report_db')
    identity_backend = setUpIdBackend()
    configure(api_host, tahoe_backend, report_backend, identity_backend)

    Org.set_backend(identity_backend)

    assert API_HOST is None
    assert Instance._backend is tahoe_backend
    assert Attribute._backend is tahoe_backend
    assert Event._backend is tahoe_backend
    assert Report._backend is report_backend
    assert User._backend is identity_backend
    assert Org._backend is identity_backend
    

def tearDownModule():
    MongoBackendTest.tearDownClass()


class GetDtRangeTest(unittest.TestCase):

    def test_01_none_none_none(self):
        t = time.time()
        start, end = get_dtrange()
        self.assertEqual(start, 0)
        self.assertLessEqual(end-t, .1)

    def test_02_from(self):
        t = time.time()
        start, end = get_dtrange(from_=100)
        self.assertEqual(start, 100)
        self.assertLessEqual(end-t, .1)
        
    def test_03_to(self):
        start, end = get_dtrange(to=100)
        self.assertEqual(start, 0)
        self.assertEqual(end, 100)

    def test_04_last_5s(self):
        tend = time.time()
        start, end = get_dtrange(last='5s')
        tstart = tend - 5
        self.assertLessEqual(abs(start-tstart), .1)
        self.assertLessEqual(abs(end-tend), .1)

    def test_05_last_5_s(self):
        tend = time.time()
        start, end = get_dtrange(last='5 s')
        tstart = tend - 5
        self.assertLessEqual(abs(start-tstart), .1)
        self.assertLessEqual(abs(end-tend), .1)

    def test_06_last_678s(self):
        tend = time.time()
        start, end = get_dtrange(last='678s')
        tstart = tend - 678
        self.assertLessEqual(abs(start-tstart), .1)
        self.assertLessEqual(abs(end-tend), .1)

    def test_07_last_678_sec(self):
        tend = time.time()
        start, end = get_dtrange(last='678 sec')
        tstart = tend - 678
        self.assertLessEqual(abs(start-tstart), .1)
        self.assertLessEqual(abs(end-tend), .1)

    def test_07_last_678sec_ValuError(self):
        with self.assertRaises(ValueError):
            start, end = get_dtrange(last='678sec')

    def test_08_from_to_tzname(self):
        from_ = "2020/05/21 02:00am"
        to = "2021/05/21 02:00am"
        tzname = "America/Los_Angeles"
        start, end = get_dtrange(from_, to, None, tzname)
        self.assertEqual(start, 1590051600.0)
        self.assertEqual(end, 1621587600.0)
        


class BaseReportTest(unittest.TestCase):

    @classmethod
    def json_2_canon(cls, qdata_json):
        canon_qdata = tahoe.misc.canonical(qdata_json).encode()
        qhash = hashlib.sha256(canon_qdata).hexdigest()
        return str(canon_qdata), qhash
    

class GetReportCountTest(BaseReportTest):
    @classmethod
    def setUpClass(cls):
        B.afn = Attribute('filename', 'virus.exe')
        
        B.u1 = User('user1@example.com')
        B.o1 = Org('org1', u1, u1)

        qtype = 'count'
        qdata = {"sub_type": "filename", "data": "virus.exe"}
        qdata, qhash = cls.json_2_canon(qdata)
        
        B.tdql = TDQL(qtype, qdata, qhash, u1._hash, False)

    @classmethod
    def tearDownClass(cls):
        del B.afn, B.u1, B.o1, B.tdql

    def test_01_count_one(self):
        e = Event('file_download', afn, o1._hash, 100)
        r = get_report(tdql)
        self.assertEqual(r.doc['data'], 1)

    def test_02_count_multiple(self):
        Event('file_download', afn, o1._hash, 200)
        r = get_report(tdql)
        self.assertEqual(r.doc['data'], 2)

##    def test03_start(self):
##        self.assertEqual(afn.count(start=99), 2)
##        self.assertEqual(afn.count(start=100), 2)
##        self.assertEqual(afn.count(start=101), 1)
##        self.assertEqual(afn.count(start=200), 1)
##        self.assertEqual(afn.count(start=201), 0)
##
##    def test04_end(self):
##        afn = Attribute('filename', 'virus.exe')
##        Event('file_download', afn, orgid, 100)
##        Event('file_download', afn, orgid, 200)
##        
##        self.assertEqual(afn.count(end=99), 0)
##        self.assertEqual(afn.count(end=100), 1)
##        self.assertEqual(afn.count(end=101), 1)
##        self.assertEqual(afn.count(end=200), 2)
##        self.assertEqual(afn.count(end=201), 2)
##
##    def test04_start_end(self):
##        afn = Attribute('filename', 'virus.exe')
##        Event('file_download', afn, orgid, 100)
##        Event('file_download', afn, orgid, 200)
##        Event('file_download', afn, orgid, 300)
##        
##        self.assertEqual(afn.count(start=150, end=120), 0)
##        self.assertEqual(afn.count(start=100, end=100), 1)
##        self.assertEqual(afn.count(start=100, end=101), 1)
##        self.assertEqual(afn.count(start=200, end=200), 1)
##        self.assertEqual(afn.count(start=200, end=201), 1)
##        self.assertEqual(afn.count(start=199, end=201), 1)
##
##    def test05_category(self):
##        afn = Attribute('filename', 'virus.exe')
##        e1 = Event('file_download', afn, orgid, 100)
##        e2 = Event('file_download', afn, orgid, 200)
##        e3 = Event('file_download', afn, orgid, 300)
##        e3 = Event('file_download', afn, orgid, 400)
##
##        e1.set_category('malicious')
##        e2.set_category('malicious')
##        e3.set_category('benign')
##
##        self.assertEqual(afn.count(category='malicious'), 2)
##        self.assertEqual(afn.count(category='benign'), 1)
##        self.assertEqual(afn.count(category='unknown'), 1)
##
##    def test06_context(self):
##        afn = Attribute('filename', 'virus.exe')
##        e1 = Event('file_download', afn, orgid, 100)
##        e2 = Event('file_download', afn, orgid, 200)
##        e3 = Event('file_download', afn, orgid, 300)
##        e3 = Event('file_download', afn, orgid, 400)
##
##        e1.set_context(afn, 'malicious')
##        e2.set_context(afn, 'malicious')
##        e3.set_context(afn, 'benign')
##
##        self.assertEqual(afn.count(context='malicious'), 2)
##        self.assertEqual(afn.count(context='benign'), 1)
##        self.assertEqual(afn.count(context='unknown'), 1)


##
##
##class SetBackendTest(unittest.TestCase):
##    """
##    Examples
##    --------
##    Correct Way to set default backend::
##        
##        >>> from tahoe import Instance, Attribute, MongoBackend
##        >>> _backend = MongoBackend()
##        >>> Instance.set_backend(_backend)
##
##    Wrong ways to set default backend::
##
##        >>> from tahoe import NoBackend, MongoBackend
##        >>> no_backend = NoBackend()
##        >>> no_backend
##        NoBackend()
##        
##        >>> mongo_backend = MongoBackend(dbname="test_db")
##        >>> mongo_backend
##        MongoBackend("localhost:27017", "test_db", "instance")
##        
##        >>> Attribute.set_backend(no_backend)
##        >>> Atrribute._backend
##        NoBackend()
##
##        >>> a = Attribute("test", "test")
##        >>> a._backend
##        NoBackend()
##
##        >>> Attribute.set_backend(mongo_backend)
##        >>> Attribute._backend
##        MongoBackend("localhost:27017", "test_db", "instance")
##
##        >>> a2 = Attribute("test", "test2")
##        >>> a2._backend
##        MongoBackend("localhost:27017", "test_db", "instance")
##
##        >>> a2._backend = NoBackend()
##        >>> Attribute._backend
##        NoBackend()
##    """
##    pass
##
##
##    
##class SubTypeTest(unittest.TestCase):
##    """
##    Examples
##    --------
##    `sub_type` must be valid Python identifier::
##
##        >>> Attribute(1, "test")
##        TypeError: sub_type = <class 'int'>, expected 'str'
##
##        >>> Attribute("str w space", "test")
##        ValueError: sub_type = 'str w space'
##
##        >>> Attribute("str-w-minus", "test")
##        ValueError: sub_type = 'str-w-minus'
##
##        >>> a = Attribute("test_attribute", "test")
##        >>> a.data
##        'test'
##    """
##    
##    def test_type(self):
##        self.assertRaises(TypeError, Attribute, 1, 'test')
##
##    def test_value_space(self):
##        self.assertRaises(ValueError, Attribute, 'str w space', 'test')
##
##    def test_value_minus(self):
##        self.assertRaises(ValueError, Attribute, 'str-w-minus', 'test')
##
##    def test_value_underscore(self):
##        a = Attribute('test_attribute', 'test')
##        
##

##        
##        
##
##class DataTest(unittest.TestCase):
##    """
##    Examples
##    --------
##
##    Data must be `int, float, str, bool, NoneType`::
##
##        >>> Attribute('test', [1,2,3])
##        TypeError: data = <class 'list'>, expected (int, float, str, boo
##        l, NoneType)        
##    """
##
##    def test_type(self):
##        self.assertRaises(TypeError, Attribute, 'test', [1,2,3])
##
##
##
##class DeleteTest(unittest.TestCase):
##    """
##    Examples
##    --------
##    Example of deleting an attribute::
##    
##        >>> import json
##        >>> from tahoe import MongoBackend, Attribute
##        >>> _backend = MongoBackend()
##        >>> _backend
##        MongoBackend("localhost:27017", "tahoe_db", "instance")
##        >>>
##        >>> a = Attribute("ipv4", "1.1.1.1", _backend=_backend)
##        >>> r = _backend.find_one({"_hash": a._hash}, {"_id": 0})
##        >>> print(json.dumps(r, indent=4))
##        {
##            "itype": "attribute",
##            "data": "1.1.1.1",
##            "sub_type": "ipv4",
##            "_hash": "4469d1e06fdd2b03ce89abf4dcc354df0be231b97e7293fe17
##            50232d2d3b23a6"
##        }
##        >>>
##        >>> a.delete()
##        >>> r = _backend.find_one({"_hash": a._hash}, {"_id": 0})
##        >>> r is None
##        True
##        >>> 
##    """
##    
##    @classmethod
##    def setUpClass(cls):
##        assert isinstance(Attribute._backend, (MongoBackend, MockMongoBackend))
##        Attribute._backend.drop()
##
##    def testdelete(self):
##        a = Attribute('ipv4', '1.1.1.1')
##        _backend = a._backend
##
##        r = _backend.find_one({'_hash': a._hash})
##        self.assertEqual(r['_hash'], a._hash)
##
##        a.delete()
##        r = _backend.find_one({'_hash': a._hash})
##        self.assertIsNone(r)
##        
##


        


if __name__ == '__main__':
    unittest.main()

    


