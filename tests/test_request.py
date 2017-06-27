import sqrlserver
import pytest
import nacl.utils
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
    assert req.check_well_formedness() == True

    #missing required params
    #nut
    badparams = dict(goodparams)
    del badparams['nut']
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == False
    #client
    badparams = dict(goodparams)
    del badparams['client']
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == False
    #server
    badparams = dict(goodparams)
    del badparams['server']
    assert isinstance(badparams['client'], str)
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == False
    #ids
    badparams = dict(goodparams)
    del badparams['ids']
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == False

    #"missing" optional param (should pass)
    badparams = dict(goodparams)
    del badparams['sfn']
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == True

    #missing required client params
    #ver
    badparams = dict(goodparams)
    badparams['client'] = 'Y21kPXF1ZXJ5DQppZGs9VExweXJvd0xoV2Y5LWhkTExQUU9BLTcteHBsSTlMT3hzZkxYc3lUY2NWYw0Kb3B0PWNwc35zdWsNCg'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == False
    #cmd
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTENCmlkaz1UTHB5cm93TGhXZjktaGRMTFBRT0EtNy14cGxJOUxPeHNmTFhzeVRjY1ZjDQpvcHQ9Y3BzfnN1aw0K'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == False
    #idk
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTENCmNtZD1xdWVyeQ0Kb3B0PWNwc35zdWsNCg'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == False

    #unsupported version
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTINCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == False

    #unknown command
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTENCmNtZD1raWxsDQppZGs9VExweXJvd0xoV2Y5LWhkTExQUU9BLTcteHBsSTlMT3hzZkxYc3lUY2NWYw0Kb3B0PWNwc35zdWsNCg'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == False

    #no opt (should pass)
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCg'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == True

    #unrecognized opt
    badparams = dict(goodparams)
    badparams['client'] = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrfmRpZQ0K'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == False

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

    #Basic case should pass
    req = sqrlserver.Request(key, goodparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == True
    assert len(req.check_validity()) == 0

    #bad signature
    badparams = dict(goodparams)
    badparams['ids'] += 'a'
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == True
    errs = req.check_validity()
    assert errs == ['sigs']

    #unreadable nut
    badparams = dict(goodparams)
    badnut = sqrlserver.Nut(nacl.utils.random(32))
    badnutstr = badnut.generate('1.2.3.4', 100).toString('qr')
    badparams['nut'] = badnutstr
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=105)
    assert req.check_well_formedness() == True
    errs = req.check_validity()
    assert errs == ['nut']

    #nut issues
    badparams = dict(goodparams)
    #ipmismatch
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.5')
    assert req.check_well_formedness() == True
    errs = req.check_validity()
    assert errs == ['ip']
    #not fresh
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', ttl=10)
    assert req.check_well_formedness() == True
    errs = req.check_validity()
    assert errs == ['time']
    #counter too small
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', mincounter=1000)
    assert req.check_well_formedness() == True
    errs = req.check_validity()
    assert errs == ['counter']
    #counter too big
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.4', maxcounter=1)
    assert req.check_well_formedness() == True
    errs = req.check_validity()
    assert errs == ['counter']
    #how about all three?
    req = sqrlserver.Request(key, badparams, ipaddr='1.2.3.5', ttl=10, maxcounter=1)
    assert req.check_well_formedness() == True
    errs = req.check_validity()
    assert errs == ['ip', 'time', 'counter']

def test_action_confirm_trigger():
    pass

def test_action_confirm_resolve():
    pass


