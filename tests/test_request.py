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
    pass
    #Need valid hashes that include 'cps'
    key = nacl.utils.random(32)
    nut = sqrlserver.Nut(key)
    nutstr = nut.generate('1.2.3.4', 100, timestamp=time.time()-100).toString('qr')
    #TODO: Need to generate valid hashes
    params = {
        'nut': nutstr,
        'client': 'dmVyPTENCmNtZD1pZGVudA0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCmlucz1kOHVNZUNGTC1sVGliSkJXVFVYcWZmWW9Xdjh2eko3alFrdXMwbHZ0Q1ZBDQpvcHQ9Y3BzfnN1aw0K',
        'server': 'dmVyPTENCm51dD1YQXVYNFlXMkE5a21UMGQ2V2l3b3ZRDQp0aWY9QzUNCnFyeT0vc3FybD9udXQ9WEF1WDRZVzJBOWttVDBkNldpd292UQ0Kc3VrPVY2N280Y2IzOEtxNWY3aWphT21HUk5CTzBMTHdoVGQ1WUFubGRkVFh1UUENCnNpbj0wDQo',
        'ids': 'aM8v2eVPjtjdrgTKqVmgmSwtiOjqCeeKH4QGPO8MckX6eaXe6BMbMYnxhMtyAJQCev6762YeWWn0o8t2cXibBA'
    }

    #TODO: Need coverage for previous identities

    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [
        ('auth', 'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc', 'cps'), 
        ('sqrlonly', False),
        ('hardlock', False),
        ('suk',)
    ]

    #successful auth
    req.handle({'authenticated': True, 'suk': 'SUK'})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x01
    assert req._response.params['suk'] == 'SUK'

    #successful auth with cps
    req = sqrlserver.Request(key, params, ipaddr='1.2.3.4')
    req.handle()
    req.handle({'authenticated': True, 'suk': 'SUK', 'url': '/cpsurl'})
    assert req.state == 'COMPLETE'
    assert req._response._tif & 0x01
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
    #TODO: Get reference hashes for testing

    #Successful deactivation

    #Failed deactivation

    #Failed due to previously disabled

    #both deactivated and disabled

    #neither deactivated nor disabled

    #ignored suk

    pass