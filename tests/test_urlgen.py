import sqrlserver
import urllib
import nacl.utils

key = nacl.utils.random(32)
nut = sqrlserver.Nut(key).generate('155.6.0.126', 123).toString('qr')

def test_minimum():
    u = sqrlserver.url_generate('example.com', '/auth/sqrl', nut, 'Example Site')
    assert u == 'sqrl://example.com/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXhhbXBsZSBTaXRl'

def test_minimum_unsecured():
    u = sqrlserver.url_generate('example.com', '/auth/sqrl', nut, 'Example Site', None, None, False)
    assert u == 'qrl://example.com/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXhhbXBsZSBTaXRl'

def test_with_params():
    u = sqrlserver.url_generate('example.com', '/auth/sqrl', nut, 'Example Site', [('name1', 'value1'), ('name2', 'value2')])
    assert u == 'sqrl://example.com/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXhhbXBsZSBTaXRl&name1=value1&name2=value2'

def test_with_authority():
    u = sqrlserver.url_generate('user:pass@example.com:8081', '/auth/sqrl', nut, 'Example Site', [('name1', 'value1'), ('name2', 'value2')])
    assert u == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXhhbXBsZSBTaXRl&name1=value1&name2=value2'

def test_weird_sfn():
    u = sqrlserver.url_generate('user:pass@example.com:8081', '/auth/sqrl', nut, 'Exàmple Site', [('name1', 'value1'), ('name2', 'value2')])
    assert u == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXjDoG1wbGUgU2l0ZQ&name1=value1&name2=value2'

def test_with_ext():
    #with extension and params
    u = sqrlserver.url_generate('user:pass@example.com:8081', '/auth/sqrl', nut, 'Exàmple Site', [('name1', 'value1'), ('name2', 'value2')], 5)
    assert u == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXjDoG1wbGUgU2l0ZQ&x=5&name1=value1&name2=value2'

    #with extension but with no other params
    u = sqrlserver.url_generate('user:pass@example.com:8081', '/auth/sqrl', nut, 'Exàmple Site', None, 5)
    assert u == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXjDoG1wbGUgU2l0ZQ&x=5'