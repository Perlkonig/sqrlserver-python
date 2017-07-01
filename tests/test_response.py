import sqrlserver
from sqrlserver.utils import pad, depad
import pytest

def test_tif():
    r = sqrlserver.Response()
    assert r._tif == 0
    r.tifOn(0x01)
    assert r._tif == 1
    r.tifOn(0x01)
    assert r._tif == 1
    r.tifOff(0x40)    
    assert r._tif == 1
    r.tifOn(0x40)    
    assert r._tif == 65
    r.tifOff(0x40)    
    assert r._tif == 1
    r.tifOff(0x01)
    assert r._tif == 0

def test_params():
    r = sqrlserver.Response()
    assert r.params == {}
    r.addParam('a', 'b')
    assert r.params == {'a': 'b'}
    r.addParam('c', 'd')
    assert r.params == {'a': 'b', 'c': 'd'}
    r.addParam('c', 'e')
    assert r.params == {'a': 'b', 'c': 'e'}

def test_compose():
    p = {'ver': 1, 'nut': 'NUT'}
    assert sqrlserver.Response._compose(p) == "ver=1\r\nnut=NUT\r\n"

def test_string():
    r = sqrlserver.Response()
    r.addParam('nut', 'NUT')
    assert r.toString() == 'dmVyPTENCm51dD1OVVQNCnRpZj0wDQo' #ver, nut, tif

def test_hmac():
    shortkey = b'\xc6\xe697\xeb\x1ao\xff\xeb\x87\xa31\xf5\xdcT'
    longkey = b'A\xe0f\xfdt\x05@\x90y\xae\x8b\xff[\xdeZ:\xa6\\\x16\x06\x1f\x9ed[\x1c\x12\xb2\xe7\xc4\xf0\x1e\x1f'
    rightkey = b'\\?\xa0\xfe\x91\x9c\x19\xe8s\xb8\x95\xfcD\xca[\xf5'

    r = sqrlserver.Response()
    r.addParam('nut', 'NUT')

    with pytest.raises(AssertionError):
        r.hmac(shortkey)

    assert r.hmac(rightkey) == 'I5wKe8McVAQ'
    assert r.hmac(longkey) == 'mXOZ9n1EeOM'


