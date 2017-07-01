Examples
========

The library is pretty thoroughly unit tested. See the ``tests`` folder for those.

Here are very basic examples.

Step 1: Generate a URL::

    import sqrlserver
    import nacl.utils

    key = nacl.utils.random(32)
    url = sqrlserver.Url('example.com', 'Example Site')
    urlstr = u.generate('/auth/sqrl')
    #urlstr = 'sqrl://example.com/auth/sqrl?nut=XXXXX&sfn=RXhhbXBsZSBTaXRl'

Step 2: Receive a Request::

    req = Request(key, postparams) #let's assume a basic ``query`` command
    assert req.state == 'NEW'

Step 3: Handle the Request::

    req.handle()
    assert req.state == 'ACTION'
    assert req.action == [('find', ['TLpyrowLhWf9-hdLLPQOA-7-xplI9LOxsfLXsyTccVc'])]

    req.handle({'found': [True]})
    assert req.state == 'COMPLETE'

Step 4: Finalize & Return the Response::

    response = req.finalize(counter=101) #will use last URL for 'qry'
    #store ``response.hmac(key)`` to the session data
    #return ``response.toString()`` to the client
