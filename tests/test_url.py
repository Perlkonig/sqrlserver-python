import sqrlserver
import urllib
import nacl.utils
import pytest
import re

key = nacl.utils.random(32)
nut = sqrlserver.Nut(key).generate('155.6.0.126', 123)
nutstr = nut.toString('qr')

def test_minimum():
    u = sqrlserver.Url('example.com')
    s = u.generate('/auth/sqrl', nut=nut)
    assert s == 'sqrl://example.com/auth/sqrl?nut=' + urllib.parse.quote(nutstr, safe='')

def test_minimum_unsecured():
    u = sqrlserver.Url('example.com', secure=False)
    s = u.generate('/auth/sqrl', nut=nut)
    assert s == 'qrl://example.com/auth/sqrl?nut=' + urllib.parse.quote(nutstr, safe='')

def test_with_params():
    u = sqrlserver.Url('example.com')
    s = u.generate('/auth/sqrl', nut=nut, query=[('name1', 'value1'), ('name2', 'value2')])
    assert s == 'sqrl://example.com/auth/sqrl?nut=' + urllib.parse.quote(nutstr, safe='') + '&name1=value1&name2=value2'

def test_with_authority():
    u = sqrlserver.Url('user:pass@example.com:8081')
    s = u.generate('/auth/sqrl', nut=nut, query=[('name1', 'value1'), ('name2', 'value2')])
    assert s == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nutstr, safe='') + '&name1=value1&name2=value2'

# def test_weird_sfn():
#     u = sqrlserver.Url('user:pass@example.com:8081', 'Exàmple Site')
#     s = u.generate('/auth/sqrl', nut=nut, query=[('name1', 'value1'), ('name2', 'value2')])
#     assert s == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nutstr, safe='') + '&name1=value1&name2=value2'

def test_with_ext():
    u = sqrlserver.Url('user:pass@example.com:8081')
    #with extension and params
    s = u.generate('/auth/sqrl', nut=nut, query=[('name1', 'value1'), ('name2', 'value2')], ext=5)
    assert s == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nutstr, safe='') + '&x=5&name1=value1&name2=value2'

    #with extension but with no other params
    u = sqrlserver.Url('user:pass@example.com:8081')
    s = u.generate('/auth/sqrl', nut=nut, ext=5)
    assert s == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nutstr, safe='') + '&x=5'

def test_path():
    u = sqrlserver.Url('example.com')

    #not absolute
    with pytest.raises(AssertionError):
        s = u.generate('auth/sqrl', nut=nut)

    #contains ?
    with pytest.raises(AssertionError):
        s = u.generate('/auth/sqrl?test=test', nut=nut)

    #contains &
    with pytest.raises(AssertionError):
        s = u.generate('/auth/sqrl&blah', nut=nut)

def test_nutgen():
    #Can't predict what the nut will be. I can only make sure one is generated.
    re_b64u = re.compile(r'nut\=[A-Za-z0-9_-]+')
    u = sqrlserver.Url('example.com')

    #correct
    s = u.generate('/auth/sqrl', counter=1, ipaddr='1.2.3.4', key=key)
    assert re_b64u.search(s) is not None

    #missing counter
    with pytest.raises(AssertionError):
        s = u.generate('/auth/sqrl', key=key)

    #missing key
    with pytest.raises(AssertionError):
        s = u.generate('/auth/sqrl', counter=1)




