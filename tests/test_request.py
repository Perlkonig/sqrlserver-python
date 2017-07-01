import sqrlserver
from sqrlserver.utils import pad, depad
import pytest
import nacl.utils
import nacl.hash
import time

def test_client():
    #test client parsing
    clientstr = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo'
    client = sqrlserver.Request._extract_client(clientstr)
    target = {'idk': 'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc', 'ver': '1', 'cmd': 'query', 'opt': ['cps', 'suk']}
    assert client == target

    #bad client string
    with pytest.raises(ValueError):
        clientstr = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQoa'
        client = sqrlserver.Request._extract_client(clientstr)

def test_server():
    #test server parsing
    #URL first
    serverstr = 'c3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PXhoN29BdlhfbnYyUG1aSVhyZGl1WVEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0'
    server = sqrlserver.Request._extract_server(serverstr)
    assert server == 'sqrl://www.grc.com/sqrl?nut=xh7oAvX_nv2PmZIXrdiuYQ&sfn=R1JD&can=aHR0cHM6Ly93d3cuZ3JjLmNvbS9zcXJsL2RpYWcuaHRt'
    #now name/value pairs
    serverstr = 'dmVyPTENCm51dD1qMjA0c0F5NXBtVXFvamtNOHJ6aUtnDQp0aWY9QzQNCnFyeT0vc3FybD9udXQ9ajIwNHNBeTVwbVVxb2prTThyemlLZw0Kc2luPTANCg'
    server = sqrlserver.Request._extract_server(serverstr)
    assert server == {'ver': '1', 'nut': 'j204sAy5pmUqojkM8rziKg', 'tif': 'C4', 'qry': '/sqrl?nut=j204sAy5pmUqojkM8rziKg', 'sin': '0'}

    #bad server string
    with pytest.raises(ValueError):
        serverstr = 'dmVyPTENCm51dD1qMjA0c0F5NXBtVXFvamtNOHJ6aUtnDQp0aWY9QzQNCnFyeT0vc3FybD9udXQ9ajIwNHNBeTVwbVVxb2prTThyemlLZw0Kc2luPTANCga'
        server = sqrlserver.Request._extract_server(serverstr)

def test_sig_validation():
    #signature validation
    msg = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQoc3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PVpIUVNuYllXU0REVWo1NzBtc0l1VlEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0'
    idk = 'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc'
    goodsig = 'tCTr1DoEYANtxGE_kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8DA'
    badsig = 'tCTr1DoEYANtxGE_kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8Da'
    assert sqrlserver.Request._signature_valid(msg, idk, goodsig) == True
    assert sqrlserver.Request._signature_valid(msg, idk, badsig) == False

def test_constructor():
    #no kwargs at all
    req = sqrlserver.Request(nacl.utils.random(32), {})
    assert str(req.ipaddr) == '0.0.0.0'
    assert req.ttl == 600
    assert req.mincounter == None
    assert req.maxcounter == None
    assert req.secure == True

    #valid ip address
    goodip = '1.2.3.4'
    req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=goodip)
    assert str(req.ipaddr) == goodip

    #invalid ip address
    badip = 'abcd'
    with pytest.raises(ValueError):
        req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=badip)

    #invalid mincounter
    with pytest.raises(ValueError):
        req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=goodip, mincounter='a')
    with pytest.raises(ValueError):
        req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=goodip, mincounter=-5)
    with pytest.raises(ValueError):
        req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=goodip, mincounter=3.2)

    #invalid maxcounter
    with pytest.raises(ValueError):
        req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=goodip, maxcounter='a')
    with pytest.raises(ValueError):
        req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=goodip, maxcounter=-5)
    with pytest.raises(ValueError):
        req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=goodip, maxcounter=3.2)

    #invalid ttl
    with pytest.raises(ValueError):
        req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=goodip, ttl='a')
    with pytest.raises(ValueError):
        req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=goodip, ttl=-5)
    with pytest.raises(ValueError):
        req = sqrlserver.Request(nacl.utils.random(32), {}, ipaddr=goodip, ttl=3.2)

def test_wellformed():
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100).toString('qr')
    goodparams = {
        'nut': nutstr,
        'sfn': 'R1JD',
        'can': 'aHR0cHM6Ly93d3cuZ3JjLmNvbS9zcXJsL2RpYWcuaHRt',
        'client': 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo',
        'server': 'c3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PVpIUVNuYllXU0REVWo1NzBtc0l1VlEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0',
        'ids': 'tCTr1DoEYANtxGE_        kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8DA'
    }

    #should register as well formed
    req = sqrlserver.Request(key, goodparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == True

    #missing required params
    #nut
    badparams = dict(goodparams)
    del badparams['nut']
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == False
    #client
    badparams = dict(goodparams)
    del badparams['client']
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == False
    #server
    badparams = dict(goodparams)
    del badparams['server']
    assert isinstance(badparams['client'], str)
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == False
    #ids
    badparams = dict(goodparams)
    del badparams['ids']
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == False

    #"missing" optional param (should pass)
    badparams = dict(goodparams)
    del badparams['sfn']
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == True

    #missing required client params
    #ver
    badparams = dict(goodparams)
    badparams['client'] = 'Y21kPXF1ZXJ5DQppZGs9VExweXJvd0xoV2Y5LWhkTExQUU9BLTcteHBsSTlMT3hzZkxYc3lUY2NWYw0Kb3B0PWNwc35zdWsNCg'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == False
    #cmd
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTENCmlkaz1UTHB5cm93TGhXZjktaGRMTFBRT0EtNy14cGxJOUxPeHNmTFhzeVRjY1ZjDQpvcHQ9Y3BzfnN1aw0K'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == False
    #idk
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTENCmNtZD1xdWVyeQ0Kb3B0PWNwc35zdWsNCg'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == False

    #unsupported version
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTINCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == False

    #unknown command
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTENCmNtZD1raWxsDQppZGs9VExweXJvd0xoV2Y5LWhkTExQUU9BLTcteHBsSTlMT3hzZkxYc3lUY2NWYw0Kb3B0PWNwc35zdWsNCg'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == False

    #no opt (should pass)
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCg'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == True

    #unrecognized opt
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrfmRpZQ0K'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == False

def test_validity():
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    goodparams = {
        'nut': nutstr,
        'sfn': 'R1JD',
        'can': 'aHR0cHM6Ly93d3cuZ3JjLmNvbS9zcXJsL2RpYWcuaHRt',
        'client': 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo',
        'server': 'c3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PVpIUVNuYllXU0REVWo1NzBtc0l1VlEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0',
        'ids': 'tCTr1DoEYANtxGE_        kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8DA'
    }
    goodmac = depad(nacl.hash.siphash24(goodparams['server'].encode('utf-8'), key=key[:16], encoder=nacl.encoding.URLSafeBase64Encoder).decode('utf-8'))
    badmac = goodmac + 'a'

    #Basic case should pass
    req = sqrlserver.Request(key, goodparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == True
    assert len(req._check_validity()) == 0

    #Pass with valid hmac
    req = sqrlserver.Request(key, goodparams, ipaddr='1.2.3.4', maxcounter=105, hmac=goodmac)
    assert req._check_well_formedness() == True
    assert len(req._check_validity()) == 0

    #Fail with bad hmac
    req = sqrlserver.Request(key, goodparams, ipaddr='1.2.3.4', maxcounter=105, hmac=badmac)
    assert req._check_well_formedness() == True
    errs = req._check_validity()
    assert errs == ['hmac']

    #bad signature
    badparams = dict(goodparams)
    badparams['ids'] += 'a'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == True
    errs = req._check_validity()
    assert errs == ['sigs']

    # GAP IN COVERAGE!
    # TODO: NEED TO ADD TESTS FOR pidk AND pids!

    #unreadable nut
    badparams = dict(goodparams)
    badnut = sqrlserver.Nut(nacl.utils.random(32))
    badnutstr = badnut.generate('1.2.3.4', 100).toString('qr')
    badparams['nut'] = badnutstr
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req._check_well_formedness() == True
    errs = req._check_validity()
    assert errs == ['nut']

    #nut issues
    badparams = dict(goodparams)
    #ipmismatch
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.5')
    assert req._check_well_formedness() == True
    errs = req._check_validity()
    assert errs == ['ip']
    #not fresh
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', ttl=10)
    assert req._check_well_formedness() == True
    errs = req._check_validity()
    assert errs == ['time']
    #counter too small
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', mincounter=1000)
    assert req._check_well_formedness() == True
    errs = req._check_validity()
    assert errs == ['counter']
    #counter too big
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=1)
    assert req._check_well_formedness() == True
    errs = req._check_validity()
    assert errs == ['counter']
    #how about all three?
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.5', ttl=10, maxcounter=1)
    assert req._check_well_formedness() == True
    errs = req._check_validity()
    assert errs == ['ip', 'time', 'counter']

def test_action_META():
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    params = {
        'nut': nutstr,
        'sfn': 'R1JD',
        'can': 'aHR0cHM6Ly93d3cuZ3JjLmNvbS9zcXJsL2RpYWcuaHRt',
        'client': 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo',
        'server': 'c3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PVpIUVNuYllXU0REVWo1NzBtc0l1VlEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0',
        'ids': 'tCTr1DoEYANtxGE_        kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8DA'
    }

    #Make sure an invalid action blows things up
    #First create a valid request
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [('find', ['TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc'])]

    #then mess with the action
    req.action = [('_find', ['TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc'])]
    with pytest.raises(ValueError):
        req.handle()

def test_action_confirm():
    #should trigger if the nut has issues but everything else is valid
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    params = {
        'nut': nutstr,
        'sfn': 'R1JD',
        'can': 'aHR0cHM6Ly93d3cuZ3JjLmNvbS9zcXJsL2RpYWcuaHRt',
        'client': 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo',
        'server': 'c3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PVpIUVNuYllXU0REVWo1NzBtc0l1VlEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0',
        'ids': 'tCTr1DoEYANtxGE_        kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8DA'
    }

    #Create request with ip mismatch and run the handler
    req = sqrlserver.Request(key, params, ipaddr='2.3.4.5')
    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [('confirm', ['ip'])]
    assert not req._response._tif & 0x04

    #Confirm with False
    req.handle({'confirmed': False})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x20
    assert req._response._tif & 0x40

    #Confirm with nothing (should also fail)
    req = sqrlserver.Request(key, params, ipaddr='2.3.4.5')
    req.handle()
    req.handle()
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x20
    assert req._response._tif & 0x40

    #Create request with ttl mismatch and run the handler
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4', ttl=0)
    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [('confirm', ['time'])]
    assert req._response._tif & 0x04

    #Confirm with True
    req.handle({'confirmed': True})
    assert req.state == 'ACTION'
    assert req.action == [('find', ['TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc'])]

def test_cmd_query():
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    params = {
        'nut': nutstr,
        'sfn': 'R1JD',
        'can': 'aHR0cHM6Ly93d3cuZ3JjLmNvbS9zcXJsL2RpYWcuaHRt',
        'client': 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo',
        'server': 'c3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PVpIUVNuYllXU0REVWo1NzBtc0l1VlEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0',
        'ids': 'tCTr1DoEYANtxGE_        kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8DA'
    }

    #TODO: Need coverage for previous identities

    #Create a valid request
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [('find', ['TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc'])]

    #confirm with found
    req.handle({'found': [True]})
    assert req.state == 'COMPLETE'
    assert req._response._tif == 0x01 + 0x04

    #confirm with found but disabled
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'found': [True], 'disabled': None, 'suk': 'SUK'})
    assert req.state == 'COMPLETE'
    assert req._response._tif == 0x01 + 0x04 + 0x08
    assert req._response.params['suk'] == 'SUK'

    #confirm with not found
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'found': [False]})
    assert req.state == 'COMPLETE'
    assert req._response._tif == 0x04

    #confirm with garbage
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    with pytest.raises(ValueError):
        req.handle({'found': None})

def test_cmd_ident():
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    params = {
        'nut': nutstr,
        'client': 'dmVyPTENCmNtZD1pZGVudA0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCmlucz1kOHVNZUNGTC1sVGliSkJXVFVYcWZmWW9Xdjh2eko3alFrdXMwbHZ0Q1ZBDQpvcHQ9Y3BzfnN1aw0K',
        'server': 'dmVyPTENCm51dD1YQXVYNFlXMkE5a21UMGQ2V2l3b3ZRDQp0aWY9QzUNCnFyeT0vc3FybD9udXQ9WEF1WDRZVzJBOWttVDBkNldpd292UQ0Kc3VrPVY2N280Y2IzOEtxNWY3aWphT21HUk5CTzBMTHdoVGQ1WUFubGRkVFh1UUENCnNpbj0wDQo',
        'ids': 'aM8v2eVPjtjdrgTKqVmgmSwtiOjqCeeKH4QGPO8MckX6eaXe6BMbMYnxhMtyAJQCev6762YeWWn0o8t2cXibBA'
    }
    newuserparams = {
        'nut': nutstr,
        'client': 'dmVyPTENCmNtZD1pZGVudA0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCnN1az1XNnF5Um9XOEZveTI1YW9UeDkxcFdsRlRrX3JidWsycEExVXdUOGlmVXdnDQp2dWs9YjFaZVFTVlNMaTFUdnZ6RDNMNHV5cTAyNlRZSmdqY3JEMWRoQXhqWTRvWQ0Kb3B0PWNwc35zdWsNCg',
        'server': 'dmVyPTENCm51dD0yYzN6RnNQSkNaN1NwUzRPZUlnMGNBDQp0aWY9NA0KcXJ5PS9zcXJsP251dD0yYzN6RnNQSkNaN1NwUzRPZUlnMGNBDQo',
        'ids': 'lAW6MpZoSlO3_rhfDPwEWpJYvNmbJ23METdC6WnliJSEk3qnQaYei5ADiv6ThbMitkEtSiRwAAmxfJDZxfJiCw'
    }

    #TODO: Need coverage for previous identities

    #new user
    req = sqrlserver.Request(key, newuserparams, ipaddr='1.2.3.4')
    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [
        (
            'auth', 
            'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc', 
            'W6qyRoW8Foy25aoTx91pWlFTk_rbuk2pA1UwT8ifUwg',
            'b1ZeQSVSLi1TvvzD3L4uyq026TYJgjcrD1dhAxjY4oY',
            'cps',
        ), 
        ('sqrlonly', False),
        ('hardlock', False),
        ('suk',)
    ]

    #known user
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [
        ('auth', 'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc', None, None, 'cps'), 
        ('sqrlonly', False),
        ('hardlock', False),
        ('suk',)
    ]

    #successful auth
    req.handle({'authenticated': True, 'suk': 'SUK'})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x01
    assert not req._response._tif & 0x40    #command was indeed completed
    assert req._response.params['suk'] == 'SUK'

    #successful auth with cps
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'authenticated': True, 'suk': 'SUK', 'url': '/cpsurl'})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x01
    assert not req._response._tif & 0x40    #command was indeed completed
    assert req._response.params['suk'] == 'SUK'
    assert req._response.params['url'] == '/cpsurl'


    #failed auth
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'authenticated': False})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x40
    assert req._response._tif & 0x80

    #failed auth due to disabled
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'authenticated': False, 'disabled': True, 'suk': 'SUK'})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x01
    assert req._response._tif & 0x08
    assert req._response._tif & 0x40
    assert req._response.params['suk'] == 'SUK'

    #disabled but no SUK given
    with pytest.raises(ValueError):
        req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
        req.handle()
        req.handle({'authenticated': False, 'disabled': True})

    #ignored auth
    with pytest.raises(ValueError):
        req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
        req.handle()
        req.handle()

def test_cmd_disable():
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    params = {
        'nut': nutstr,
        'client': 'dmVyPTENCmNtZD1kaXNhYmxlDQppZGs9VExweXJvd0xoV2Y5LWhkTExQUU9BLTcteHBsSTlMT3hzZkxYc3lUY2NWYw0Kb3B0PWNwc35zdWsNCg',
        'server': 'dmVyPTENCm51dD10TkdMczN3RXRoNE8xanhVY1BvYkN3DQp0aWY9NQ0KcXJ5PS9zcXJsP251dD10TkdMczN3RXRoNE8xanhVY1BvYkN3DQpzdWs9VjY3bzRjYjM4S3E1ZjdpamFPbUdSTkJPMExMd2hUZDVZQW5sZGRUWHVRQQ0K',
        'ids': 'rU_Qitm8U_GM6enUj0V8Oag5IxmCmwBHx3O-sxovwN_T59qsgjLIP8LaYFFi0ysBZqmq8E3vw9Vzm-xNM54OBw'
    }

    #Initial request
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [
        ('disable', 'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc'), 
        ('sqrlonly', False),
        ('hardlock', False),
        ('suk',)
    ]

    #Successful deactivation
    req.handle({'deactivated': True, 'suk': 'SUK', 'found': True})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x01    #user known
    assert req._response._tif & 0x08    #account disabled
    assert not req._response._tif & 0x40    #command was indeed completed

    #Failed deactivation and user not known
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'deactivated': False})
    assert req.state == 'COMPLETE'
    assert not req._response._tif & 0x01
    assert not req._response._tif & 0x08
    assert req._response._tif & 0x40    

    #Failed deactivation but user known
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'deactivated': False, 'found': True, 'suk': 'SUK'})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x01
    assert not req._response._tif & 0x08
    assert req._response._tif & 0x40    

    #Command ignored
    with pytest.raises(ValueError):
        req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
        req.handle()
        req.handle({'suk': 'SUK'})

    #suk ignored
    with pytest.raises(ValueError):
        req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
        req.handle()
        req.handle({'deactivated': True})

def test_cmd_enable():
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    params = {
        'nut': nutstr,
        'client': 'dmVyPTENCmNtZD1lbmFibGUNCmlkaz1UTHB5cm93TGhXZjktaGRMTFBRT0EtNy14cGxJOUxPeHNmTFhzeVRjY1ZjDQpvcHQ9Y3BzfnN1aw0K',
        'server': 'dmVyPTENCm51dD1SeXJCQTBIWlBSU1hWSEN1WlhIazRBDQp0aWY9RA0KcXJ5PS9zcXJsP251dD1SeXJCQTBIWlBSU1hWSEN1WlhIazRBDQpzdWs9Y3FIdkpxb3E3UHlyQkk5eUFodEdqQmtsSTMxR2s1dmtycTBhTkFXbkpCWQ0K',
        'ids': 'hcH_mt4XTxbQDXIvNPY1qFI6bAKMV3QrAJEeQ91Pl0fR89dnV11YysZA9_yPvqsKHXBen4WB3fELiBFTgCakBA',
        'urs': '8ciKHSOHX2uZh3QYVsya7wbvyq-D0MDLccOWC1yKcXtSAdsUjvseGLvvuXqUQhxBpsMVWNnpCcRFWibbwkbvAg'
    }

    #Initial request asks for VUK
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [('vuk',)]

    #Handing a valid VUK asks for enabling
    req.handle({'vuk': '3gyFVqlNogtpKscrDy7sopPk3xasMisEnAJdSniioE4'})
    assert req.state == 'ACTION'
    assert req.action == [
        ('enable', 'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc'), 
        ('sqrlonly', False),
        ('hardlock', False),
        ('suk',)
    ]

    #Enabled True
    req.handle({'activated': True})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x01
    assert not req._response._tif & 0x40

    #Enabled False, found False
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'vuk': '3gyFVqlNogtpKscrDy7sopPk3xasMisEnAJdSniioE4'})
    req.handle({'activated': False})
    assert req.state == 'COMPLETE'
    assert not req._response._tif & 0x01
    assert req._response._tif & 0x40

    #Enabled False, found True
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'vuk': '3gyFVqlNogtpKscrDy7sopPk3xasMisEnAJdSniioE4'})
    req.handle({'activated': False, 'found': True})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x01
    assert req._response._tif & 0x40

    #Enabled omitted
    with pytest.raises(ValueError):
        req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
        req.handle()
        req.handle({'vuk': '3gyFVqlNogtpKscrDy7sopPk3xasMisEnAJdSniioE4'})
        req.handle({'found': True})

    #Signature fail
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'vuk': '3gyFVqlNogtpKscrDy7sopPk3xasMisEnAJdSniioe4'})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x40
    assert req._response._tif & 0x80

def test_cmd_remove():
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    params = {
        'nut': nutstr,
        'client': 'dmVyPTENCmNtZD1yZW1vdmUNCmlkaz1UTHB5cm93TGhXZjktaGRMTFBRT0EtNy14cGxJOUxPeHNmTFhzeVRjY1ZjDQpvcHQ9Y3BzfnN1aw0K',
        'server': 'dmVyPTENCm51dD1ZcWN3d1BpSDZ6UnFFNTZqMWdsZGZBDQp0aWY9NQ0KcXJ5PS9zcXJsP251dD1ZcWN3d1BpSDZ6UnFFNTZqMWdsZGZBDQpzdWs9Y3FIdkpxb3E3UHlyQkk5eUFodEdqQmtsSTMxR2s1dmtycTBhTkFXbkpCWQ0K',
        'ids': 'af4KG_JEKyNtIQEDRvwAxlky3aTmIMaGkBd81auAr22Uc_EE2OpQttmuh5gyLNHgt3AXwVmpI-c-u3czKVYlDQ',
        'urs': 'B7wCzP2SXT7ALmUE35ymGc8fJ739_3kdx-fAEH5Hb1dggwPqOaChLXOXVruGFlVE5rqqEwbtgkbiDOVtAYmqCA'
    }

    #Initial request asks for VUK
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [('vuk',)]

    #Handing a valid VUK asks for removing
    req.handle({'vuk': '3gyFVqlNogtpKscrDy7sopPk3xasMisEnAJdSniioE4'})
    assert req.state == 'ACTION'
    assert req.action == [
        ('remove', 'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc'), 
    ]

    #Removed True
    req.handle({'removed': True})
    assert req.state == 'COMPLETE'
    assert not req._response._tif & 0x01
    assert not req._response._tif & 0x40

    #Removed False, found False
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'vuk': '3gyFVqlNogtpKscrDy7sopPk3xasMisEnAJdSniioE4'})
    req.handle({'removed': False})
    assert req.state == 'COMPLETE'
    assert not req._response._tif & 0x01
    assert req._response._tif & 0x40

    #Removed False, found True
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'vuk': '3gyFVqlNogtpKscrDy7sopPk3xasMisEnAJdSniioE4'})
    req.handle({'removed': False, 'found': True})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x01
    assert req._response._tif & 0x40

    #Removed omitted
    with pytest.raises(ValueError):
        req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
        req.handle()
        req.handle({'vuk': '3gyFVqlNogtpKscrDy7sopPk3xasMisEnAJdSniioE4'})
        req.handle({'found': True})

    #Signature fail
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'vuk': '3gyFVqlNogtpKscrDy7sopPk3xasMisEnAJdSniioe4'})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x40
    assert req._response._tif & 0x80

def test_action_canasksin():
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    params = {
        'nut': nutstr,
        'sfn': 'R1JD',
        'can': 'aHR0cHM6Ly93d3cuZ3JjLmNvbS9zcXJsL2RpYWcuaHRt',
        'client': 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo',
        'server': 'c3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PVpIUVNuYllXU0REVWo1NzBtc0l1VlEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0',
        'ids': 'tCTr1DoEYANtxGE_        kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8DA'
    }

    #TODO: Need coverage for previous identities

    #Injection of can and sin
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle({'sin': 'index', 'can': 'https://example.com:8080/sqrl?a=b&c=d'})
    assert req.state == 'ACTION'
    assert req._response.params['sin'] == 'index'
    assert req._response.params['can'] == '/sqrl?a=b&c=d'

    #TODO: Need reference hashes for returned BTN, INS, and PINS

    #Injection asks
    ask1 = {'msg': 'Simple question'}
    ask2 = {'msg': 'One button', 'buttons': (('Button 1',),)}
    ask3 = {'msg': 'One button', 'buttons': (('Button 1; fail',),)}
    ask4 = {'msg': 'Two buttons', 'buttons': (('Button 1',), ('Button 2',))}
    ask5 = {'msg': 'Two buttons w/ URLs', 'buttons': (('Button 1', '/url1'), ('Button 2', 'https://www.example.com:8080/url2#frag'))}

    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle({'ask': ask1})
    assert req._response.params['ask'] == 'U2ltcGxlIHF1ZXN0aW9u'
    assert not req._response._tif & 0x40

    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle({'ask': ask2})
    assert req._response.params['ask'] == 'T25lIGJ1dHRvbg~QnV0dG9uIDE'
    assert not req._response._tif & 0x40

    with pytest.raises(ValueError):
        req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
        req.handle({'ask': ask3})

    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle({'ask': ask4})
    assert req._response.params['ask'] == 'VHdvIGJ1dHRvbnM~QnV0dG9uIDE~QnV0dG9uIDI'
    assert not req._response._tif & 0x40

    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle({'ask': ask5})
    assert req._response.params['ask'] == 'VHdvIGJ1dHRvbnMgdy8gVVJMcw~QnV0dG9uIDE;/url1~QnV0dG9uIDI;/url2#frag'
    assert not req._response._tif & 0x40

def test_finalize():
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    params = {
        'nut': nutstr,
        'sfn': 'R1JD',
        'can': 'aHR0cHM6Ly93d3cuZ3JjLmNvbS9zcXJsL2RpYWcuaHRt',
        'client': 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo',
        'server': 'c3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PVpIUVNuYllXU0REVWo1NzBtc0l1VlEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0',
        'ids': 'tCTr1DoEYANtxGE_        kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8DA'
    }
    nextnut = nut.generate('1.2.3.4', 110)

    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle() #FIND action issued
    req.handle({'found': [True]})
    r = req.finalize(nut=nextnut)
    server = pad(r.toString())
    server = sqrlserver.Request._extract_server(server)
    assert server['nut'] == nextnut.toString('qr')
    assert server['tif'] == '5'



