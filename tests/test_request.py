import sqrlserver

def test_client():
    #test client parsing
    clientstr = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQo'
    client = sqrlserver.Request._extract_client(clientstr)
    target = {'idk': 'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc', 'ver': '1', 'cmd': 'query', 'opt': ['cps', 'suk']}
    assert client == target

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

def test_sig_validation():
    #signature validation
    msg = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVRMcHlyb3dMaFdmOS1oZExMUFFPQS03LXhwbEk5TE94c2ZMWHN5VGNjVmMNCm9wdD1jcHN-c3VrDQoc3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PVpIUVNuYllXU0REVWo1NzBtc0l1VlEmc2ZuPVIxSkQmY2FuPWFIUjBjSE02THk5M2QzY3VaM0pqTG1OdmJTOXpjWEpzTDJScFlXY3VhSFJ0'
    idk = 'TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc'
    goodsig = 'tCTr1DoEYANtxGE_kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8DA'
    badsig = 'tCTr1DoEYANtxGE_kRNHgSsHa87aRG9C0vNqy7h6CaV8tH5TnBJmdW0gbDsja1JsRbSNA4ZeFVUIfOnzdEz8Da'
    assert sqrlserver.Request._signature_valid(msg, idk, goodsig) == True
    assert sqrlserver.Request._signature_valid(msg, idk, badsig) == False


