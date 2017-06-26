# the inclusion of the tests module is not meant to offer best practices for
# testing in general, but rather to support the `find_packages` example in
# setup.py that excludes installing the "tests" package

import sqrlserver
import nacl.utils
import nacl.exceptions
import time
import urllib.parse
import pytest

nuts = {}
key = nacl.utils.random(32)
counter = 123

def test_nutgen():
    nut = sqrlserver.Nut(key)
    #unsecured
    nut = nut.generate('0.0.0.0', counter)
    nutqr = nut.toString('qr')
    nutlink = nut.toString('link')
    assert nutqr != nutlink
    nuts['unsecured-qr'] = nutqr
    nuts['unsecured-link'] = nutlink

    #real ipv4
    nut = nut.generate('155.6.0.126', counter)
    nutqr = nut.toString('qr')
    nutlink = nut.toString('link')
    assert nutqr != nutlink
    nuts['ipv4-qr'] = nutqr
    nuts['ipv4-link'] = nutlink

    #real ipv6
    nut = nut.generate('2001:db8:a0b:12f0::1', counter)
    nutqr = nut.toString('qr')
    nutlink = nut.toString('link')
    assert nutqr != nutlink
    nuts['ipv6-qr'] = nutqr
    nuts['ipv6-link'] = nutlink

def test_nutval():
    #first test that all nuts are valid as they stand
    nut = sqrlserver.Nut(key)
    nut = nut.load(nuts['unsecured-qr']).validate('0.0.0.0', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.isqr
    assert not nut.islink

    nut = nut.load(nuts['unsecured-link']).validate('0.0.0.0', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.islink
    assert not nut.isqr

    nut = nut.load(nuts['ipv4-qr']).validate('155.6.0.126', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.isqr
    assert not nut.islink

    nut = nut.load(nuts['ipv4-link']).validate('155.6.0.126', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.islink
    assert not nut.isqr

    nut = nut.load(nuts['ipv6-qr']).validate('2001:db8:a0b:12f0::1', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.isqr
    assert not nut.islink

    nut = nut.load(nuts['ipv6-link']).validate('2001:db8:a0b:12f0::1', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.islink
    assert not nut.isqr

    #mismatched IP addresses
    nut = nut.load(nuts['ipv4-link']).validate('155.6.0.125', 600, counter)
    assert not nut.ipmatch
    nut = nut.load(nuts['ipv6-link']).validate('2002:db8:a0b:12f0::1', 600, counter)
    assert not nut.ipmatch

    #too old
    t = time.time() - 3000
    nut = nut.generate('155.6.0.126', counter, t).validate('155.6.0.126', 600, counter)
    assert not nut.fresh

    #in the future
    t = time.time() + 3000
    nut = nut.generate('155.6.0.126', counter, t).validate('155.6.0.126', 600, counter)
    assert not nut.fresh

    #counter too small
    nut = nut.generate('155.6.0.126', 5).validate('155.6.0.126', 600, counter, counter-10)
    assert not nut.countersane

    #counter too big
    nut = nut.generate('155.6.0.126', counter + 100).validate('155.6.0.126', 600, counter)
    assert not nut.countersane

    #counter validation can be turned off
    #   Use previously generated nut with a counter value too high
    #   but omit the maxcounter from the validation call.
    nut.validate('155.6.0.126', 600)
    assert nut.countersane

    #incorrect key
    with pytest.raises(nacl.exceptions.CryptoError):
        wrongnut = sqrlserver.Nut(nacl.utils.random(32))
        wrongnut.load(nuts['ipv4-link']).validate('155.6.0.126', 600, counter)

def test_urlgen():
    nut = sqrlserver.Nut(key).generate('155.6.0.126', counter).toString('qr')
    
    #bare minimum
    u = sqrlserver.url_generate('example.com', '/auth/sqrl', nut, 'Example Site')
    assert u == 'sqrl://example.com/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXhhbXBsZSBTaXRl'

    #bare minimum unsecured
    u = sqrlserver.url_generate('example.com', '/auth/sqrl', nut, 'Example Site', None, None, False)
    assert u == 'qrl://example.com/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXhhbXBsZSBTaXRl'

    #with additional parameters
    u = sqrlserver.url_generate('example.com', '/auth/sqrl', nut, 'Example Site', [('name1', 'value1'), ('name2', 'value2')])
    assert u == 'sqrl://example.com/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXhhbXBsZSBTaXRl&name1=value1&name2=value2'

    #with authority parts
    u = sqrlserver.url_generate('user:pass@example.com:8081', '/auth/sqrl', nut, 'Example Site', [('name1', 'value1'), ('name2', 'value2')])
    assert u == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXhhbXBsZSBTaXRl&name1=value1&name2=value2'

    #SFN with weird characters
    u = sqrlserver.url_generate('user:pass@example.com:8081', '/auth/sqrl', nut, 'Exàmple Site', [('name1', 'value1'), ('name2', 'value2')])
    assert u == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXjDoG1wbGUgU2l0ZQ&name1=value1&name2=value2'

    #with extension and params
    u = sqrlserver.url_generate('user:pass@example.com:8081', '/auth/sqrl', nut, 'Exàmple Site', [('name1', 'value1'), ('name2', 'value2')], 5)
    assert u == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXjDoG1wbGUgU2l0ZQ&x=5&name1=value1&name2=value2'

    #with extension but with no other params
    u = sqrlserver.url_generate('user:pass@example.com:8081', '/auth/sqrl', nut, 'Exàmple Site', None, 5)
    assert u == 'sqrl://user:pass@example.com:8081/auth/sqrl?nut=' + urllib.parse.quote(nut, safe='') + '&sfn=RXjDoG1wbGUgU2l0ZQ&x=5'

def test_request():
    #test client parsing
    clientstr = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo'
    client = sqrlserver.Request._extract_client(clientstr)
    target = {'idk': 'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc', 'ver': '1', 'cmd': 'query', 'opt': ['cps', 'suk']}
    assert client == target

    #test server parsing
    #URL first
    serverstr = 'c3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PXhoN29BdlhfbnYyUG1aSVhyZGl1WVEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0'
    server = sqrlserver.Request._extract_server(serverstr)
    assert server == 'sqrl://www.grc.com/sqrl?nut=xh7oAvX_nv2PmZIXrdiuYQ&sfn=R1JD&can=aHR0cHM6Ly93d3cuZ3JjLmNvbS9zcXJsL2RpYWcuaHRt'
    #now name/value pairs
    serverstr = 'dmVyPTENCm51dD1qMjA0c0F5NXBtVXFvamtNOHJ6aUtnDQp0aWY9QzQNCnFyeT0vc3FybD9udXQ9ajIwNHNBeTVwbVVxb2prTThyemlLZw0Kc2luPTANCg'
    server = sqrlserver.Request._extract_server(serverstr)
    assert server == {'ver': '1', 'nut': 'j204sAy5pmUqojkM8rziKg', 'tif': 'C4', 'qry': '/sqrl?nut=j204sAy5pmUqojkM8rziKg', 'sin': '0'}
