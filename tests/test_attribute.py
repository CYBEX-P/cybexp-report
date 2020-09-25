"""unittest's for tahoe.attribute.py"""

if __name__ != 'tahoe.tests.test_attribute':
    import sys
    sys.path = ['..', '../..'] + sys.path
    del sys

import pdb
import unittest

from tahoe import Instance, Attribute, Event
from tahoe.backend import MongoBackend, MockMongoBackend
from tahoe.tests.test_backend import MongoBackendTest


def setUpModule():
    _backend = MongoBackendTest.setUpClass()
    Instance.set_backend(_backend)

    import builtins
    builtins.orgid = 'a441b15fe9a3cf56661190a0b93b9dec7d041272' \
                '88cc87250967cf3b52894d11'''

def tearDownModule():
    MongoBackendTest.tearDownClass()


class SetBackendTest(unittest.TestCase):
    """
    Examples
    --------
    Correct Way to set default backend::
        
        >>> from tahoe import Instance, Attribute, MongoBackend
        >>> _backend = MongoBackend()
        >>> Instance.set_backend(_backend)

    Wrong ways to set default backend::

        >>> from tahoe import NoBackend, MongoBackend
        >>> no_backend = NoBackend()
        >>> no_backend
        NoBackend()
        
        >>> mongo_backend = MongoBackend(dbname="test_db")
        >>> mongo_backend
        MongoBackend("localhost:27017", "test_db", "instance")
        
        >>> Attribute.set_backend(no_backend)
        >>> Atrribute._backend
        NoBackend()

        >>> a = Attribute("test", "test")
        >>> a._backend
        NoBackend()

        >>> Attribute.set_backend(mongo_backend)
        >>> Attribute._backend
        MongoBackend("localhost:27017", "test_db", "instance")

        >>> a2 = Attribute("test", "test2")
        >>> a2._backend
        MongoBackend("localhost:27017", "test_db", "instance")

        >>> a2._backend = NoBackend()
        >>> Attribute._backend
        NoBackend()
    """
    pass


    
class SubTypeTest(unittest.TestCase):
    """
    Examples
    --------
    `sub_type` must be valid Python identifier::

        >>> Attribute(1, "test")
        TypeError: sub_type = <class 'int'>, expected 'str'

        >>> Attribute("str w space", "test")
        ValueError: sub_type = 'str w space'

        >>> Attribute("str-w-minus", "test")
        ValueError: sub_type = 'str-w-minus'

        >>> a = Attribute("test_attribute", "test")
        >>> a.data
        'test'
    """
    
    def test_type(self):
        self.assertRaises(TypeError, Attribute, 1, 'test')

    def test_value_space(self):
        self.assertRaises(ValueError, Attribute, 'str w space', 'test')

    def test_value_minus(self):
        self.assertRaises(ValueError, Attribute, 'str-w-minus', 'test')

    def test_value_underscore(self):
        a = Attribute('test_attribute', 'test')
        

class CountTest(unittest.TestCase):
    """
    Example
    -------
    a1 = Atribute('ip', '1.1.1.1')
    e1 = Event
    """
    
    @classmethod
    def setUpClass(cls):
        assert isinstance(Attribute._backend, (MongoBackend, MockMongoBackend))
        Attribute._backend.drop()
        assert Attribute._backend is Event._backend

    def test01_count_one(self):
        afn = Attribute('filename', 'virus.exe')
        e = Event('file_download', afn, orgid, 100)
        self.assertEqual(afn.count(), 1)

    def test02_count_multiple(self):
        afn = Attribute('filename', 'virus.exe')
        Event('file_download', afn, orgid, 100)
        Event('file_download', afn, orgid, 200)
        self.assertEqual(afn.count(), 2)

    def test03_start(self):
        afn = Attribute('filename', 'virus.exe')
        Event('file_download', afn, orgid, 100)
        Event('file_download', afn, orgid, 200)
        
        self.assertEqual(afn.count(start=99), 2)
        self.assertEqual(afn.count(start=100), 2)
        self.assertEqual(afn.count(start=101), 1)
        self.assertEqual(afn.count(start=200), 1)
        self.assertEqual(afn.count(start=201), 0)

    def test04_end(self):
        afn = Attribute('filename', 'virus.exe')
        Event('file_download', afn, orgid, 100)
        Event('file_download', afn, orgid, 200)
        
        self.assertEqual(afn.count(end=99), 0)
        self.assertEqual(afn.count(end=100), 1)
        self.assertEqual(afn.count(end=101), 1)
        self.assertEqual(afn.count(end=200), 2)
        self.assertEqual(afn.count(end=201), 2)

    def test04_start_end(self):
        afn = Attribute('filename', 'virus.exe')
        Event('file_download', afn, orgid, 100)
        Event('file_download', afn, orgid, 200)
        Event('file_download', afn, orgid, 300)
        
        self.assertEqual(afn.count(start=150, end=120), 0)
        self.assertEqual(afn.count(start=100, end=100), 1)
        self.assertEqual(afn.count(start=100, end=101), 1)
        self.assertEqual(afn.count(start=200, end=200), 1)
        self.assertEqual(afn.count(start=200, end=201), 1)
        self.assertEqual(afn.count(start=199, end=201), 1)

    def test05_category(self):
        afn = Attribute('filename', 'virus.exe')
        e1 = Event('file_download', afn, orgid, 100)
        e2 = Event('file_download', afn, orgid, 200)
        e3 = Event('file_download', afn, orgid, 300)
        e3 = Event('file_download', afn, orgid, 400)

        e1.set_category('malicious')
        e2.set_category('malicious')
        e3.set_category('benign')

        self.assertEqual(afn.count(category='malicious'), 2)
        self.assertEqual(afn.count(category='benign'), 1)
        self.assertEqual(afn.count(category='unknown'), 1)

    def test06_context(self):
        afn = Attribute('filename', 'virus.exe')
        e1 = Event('file_download', afn, orgid, 100)
        e2 = Event('file_download', afn, orgid, 200)
        e3 = Event('file_download', afn, orgid, 300)
        e3 = Event('file_download', afn, orgid, 400)

        e1.set_context(afn, 'malicious')
        e2.set_context(afn, 'malicious')
        e3.set_context(afn, 'benign')

        self.assertEqual(afn.count(context='malicious'), 2)
        self.assertEqual(afn.count(context='benign'), 1)
        self.assertEqual(afn.count(context='unknown'), 1)
        
        

class DataTest(unittest.TestCase):
    """
    Examples
    --------

    Data must be `int, float, str, bool, NoneType`::

        >>> Attribute('test', [1,2,3])
        TypeError: data = <class 'list'>, expected (int, float, str, boo
        l, NoneType)        
    """

    def test_type(self):
        self.assertRaises(TypeError, Attribute, 'test', [1,2,3])



class DeleteTest(unittest.TestCase):
    """
    Examples
    --------
    Example of deleting an attribute::
    
        >>> import json
        >>> from tahoe import MongoBackend, Attribute
        >>> _backend = MongoBackend()
        >>> _backend
        MongoBackend("localhost:27017", "tahoe_db", "instance")
        >>>
        >>> a = Attribute("ipv4", "1.1.1.1", _backend=_backend)
        >>> r = _backend.find_one({"_hash": a._hash}, {"_id": 0})
        >>> print(json.dumps(r, indent=4))
        {
            "itype": "attribute",
            "data": "1.1.1.1",
            "sub_type": "ipv4",
            "_hash": "4469d1e06fdd2b03ce89abf4dcc354df0be231b97e7293fe17
            50232d2d3b23a6"
        }
        >>>
        >>> a.delete()
        >>> r = _backend.find_one({"_hash": a._hash}, {"_id": 0})
        >>> r is None
        True
        >>> 
    """
    
    @classmethod
    def setUpClass(cls):
        assert isinstance(Attribute._backend, (MongoBackend, MockMongoBackend))
        Attribute._backend.drop()

    def testdelete(self):
        a = Attribute('ipv4', '1.1.1.1')
        _backend = a._backend

        r = _backend.find_one({'_hash': a._hash})
        self.assertEqual(r['_hash'], a._hash)

        a.delete()
        r = _backend.find_one({'_hash': a._hash})
        self.assertIsNone(r)
        



        


if __name__ == '__main__':
    unittest.main()

    


