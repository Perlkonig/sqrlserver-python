Usage
=====

Summary
-------

The core workflow is quite simple:

#. Create a :py:class:`.Url` to generate the URLs that point clients to your SQRL endpoints.
#. Create a :py:class:`.Request` object when a POST is made to those endpoints.
#. Call the request's :py:meth:`.Request.handle` method repeatedly until its ``state`` is ``COMPLETE``.
#. Call :py:meth:`.Request.finalize` to get a :py:class:`.Response` object.
#. Return :py:meth:`.Response.toString` to the client.

Step 1: Generate a URL
----------------------

SQRL endpoints are identified using a format detailed in the specification [LINK FORTHCOMING]. First create a :py:class:`.Url` object by passing it the authority part of the URL and your "server friendly name" or SFN.

You then :py:meth:`.Url.generate` the actual string by passing it the path, any additional query parameters your service expects, and some other data needed to produce the "nut" (what SQRL calls the nonce used with each and every interaction). The library includes a :py:class:`.Nut` class that will generate them for you and use them for validating later interactions.

Step 2: Receive a Request
-------------------------

When a request is POSTed to your endpoint, pass all that data, along with some verification information, to a new :py:class:`.Request` object.

The :py:class:`.Request` class acts as a simple state machine. Its ``state`` can be one of five strings:

- NEW (initial state, no processing has been done)
- WELLFORMED (initial well-formedness checks have been done and passed)
- VALID (initial validity tests have been done and passed; while in this state, the request will process client-submitted commands)
- ACTION (the user needs to provide additional information)
- COMPLETE (end state; finalize and return the response)

Step 3: Handle the Request
--------------------------

After the class is initialized, call :py:meth:`.Request.handle` to start the transition loop. It will never exit without the state being either ``ACTION`` or ``COMPLETE``.

- ACTION means the library needs information from the server. In this state, the object will have a payload that explains what it needs (explained further below).
- COMPLETE means that all requested processing is done. You can finalize and return the response, which will include the necessary status codes for the client.

When the :py:class:`.Request` is in an ``ACTION`` state, the server should examine the object's ``action`` attribute. It will be a list of tuples. Each should be processed in the order given. Each tuple will consist of at least one element, which will contain the verb. Depending on the verb, additional elements may be present. The server is responsible for correctly handling all the verbs. Once the server has all the requested information, it again calls the :py:meth:`.Request.handle` method, but this time passing in a dictionary containing the requested information.

The :py:class:`.Request` object will process that information and try again to move the request to a ``COMPLETE`` state. If you fail to pass required information, or pass malformed information, the class will raise an exception. If the server has correctly implemented all the verbs, this should never happen. Any errors that arise from the protocol itself will be signalled through the :py:class:`.Response` object. The server does not have to worry about this.

Verbs
^^^^^

auth
""""

Asks the server to officially authenticate the given user. 
If the user is not already recognized, then this should be
taken as a request to create a new account. In this case the
SUK and VUK *must* be present. The server saves the three
keys, creates the account, and authenticates the user.

Contains the following additional elements:

    - String (required) representing the Identity Key (IDK)
    - String or None (required) the Server Unlock Key (SUK)
    - String or None (required) the Verify Unlock Key (VUK)
    - String constant ``cps`` (optional) requesting
      that the auth be handled as a  "Client Provided
      Session"

The subsequent call to :py:meth:`.Request.handle` expects the following dictionary:

    authenticated : (required) boolean
        If present and True, the handler will signal 
        success to the client.
        If present and False, the handler will signal 
        an error.
        If not provided, the handler will throw an exception.
    url : (optional) string
        If 'cps' was set, and the server supports it, 
        it can pass a path to a pre-authenticated endpoint 
        here (path only).
    disabled : (optional) ANY
        The presence of this key (regardless of value) means 
        the primary identity is recognized but that the user 
        disabled it. It cannot be used for authentication 
        until reenabled or rekeyed.
    suk : (dependent) string
        If the account is disabled, then you must provide 
        the Server Unlock Key. Failure to do so will raise 
        an exception.

btn
"""

Means the request was accompanied by a 'btn' parameter.

Contains the following additional element:

    - String : One of '1', '2', or '3'

This action has no requirements for subsequent calls to :py:meth:`.Request.handle`.

confirm
"""""""

Means there is an issue with the nut. The server must
confirm whether they wish to proceed. It's important
to let the server decide because (a) it might be
expected that the IPs don't match (cross-device login)
and (b) the "counter" part of the nut could be used to
store other types of information instead.

Contains the following additional element:

    - Array of strings representing possible issues:
        - ``ip``: the ip addresses didn't match
        - ``time``: the nut is older than the specified ttl
        - ``counter``: the counter did not pass requested sanity checks

The subsequent call to :py:meth:`.Request.handle` expects the following dictionary:

    confirmed : boolean
        If present and True, the handler will process
        the request. In all other cases, the handler
        will set the appropriate error codes and
        terminate.

disable
"""""""

Tells the server to disable this SQRL identity.

Contains the following additional element:

    - String (required) representing the SQRL identity

The subsequent call to :py:meth:`.Request.handle` expects the following dictionary:

    deactivated : (required) boolean
        If present and True, the server is saying they have complied.
        If present and False, the user will be notified that the command was
        not completed. 
        If not present, an exception will be thrown.
        True implies 'found' is also True.
    suk : (depends) string
        If 'deactivated' is True , you must provide the Server 
        Unlock Key. Failure to do so will raise an exception.
    found : (optional, recommended) boolean
        Only useful if 'deactivated' is False.
        If present, signals whether the server recognizes this user.

enable
""""""

Tells the server to enable the given account. 

Contains the following additional element:

    - String (required) representing the SQRL identity

The subsequent call to :py:meth:`.Request.handle` expects the following dictionary:

    activated : (required) boolean
        If present and True, the server is saying they have complied.
        If present and False, the user will be notified 
        that the command was not completed.
        If not present, an exception will be thrown.
        True implies 'found' is also True.
    found : (optional, recommended) boolean
        Only useful if 'activated' is False.
        If present, signals whether the server recognizes this user.

find
""""

Asks the server to locate the given keys in their user database.

Contains the following additional element:

    - Array of strings representing SQRL identities.
      This array will always at least contain the
      primary identity. If a previous identities were
      given by the client, they will also appear in
      the list. The spec currently limits the number
      of previous identities to one at a time (meaning
      this array should never be longer than two
      elements), but there's no reason to enforce that
      at this level. The server should simply check
      all keys.

The subsequent call to :py:meth:`.Request.handle` expects the following dictionary:

    found : (required) array of booleans
        True indicates that the key is recognized.
        False indicates that the key is not recognized.
        The order should be the same as provided in
        the ``action`` property.
    disabled : (optional) ANY
        The presence of this key (regardless of value)
        means the primary identity is recognized but
        that the user disabled it. It cannot be used
        for authentication until reenabled or rekeyed.
    suk : (dependent) string
        If the account is disabled, then you must
        provide the Server Unlock Key. Failure to do
        so will raise an exception.

hardlock
""""""""

Tells the server whether to enable or disable 'hardlock' on 
the server side.

Contains the following additional element:

    - Boolean (required) signalling whether the option 
      should be turned on or off.

The subsequent call to :py:meth:`.Request.handle` expects the following dictionary:

    hardlock: (optional) boolean
        If present and False, the handler will hard fail. 
        It will set codes 0x10 and 0x40 and abort.
        In all other cases, the code will simply assume the 
        server has complied.

ins
"""

Means the request was accompanied by a 'ins' parameter.

Contains the following additional element:

    - String : The value of the 'ins' parameter

This action has no requirements for subsequent calls to :py:meth:`.Request.handle`.

pins
""""

Means the request was accompanied by a 'pins' parameter.

Contains the following additional element:

    - String : The value of the 'ins' parameter

This action has no requirements for subsequent calls to :py:meth:`.Request.handle`.

remove
""""""

Tells the server to remove the given account. 

Contains the following additional element:

    - String (required) representing the SQRL identity

The subsequent call to :py:meth:`.Request.handle` expects the following dictionary:

    removed : (required) boolean
        If present and True, the server is saying they have complied.
        If present and False, the user will be notified 
        that the command was not completed.
        If not present, an exception will be thrown.
        True implies 'found' is also True.
    found : (optional, recommended) boolean
        Only useful if 'removed' is False.
        If present, signals whether the server recognizes this user.

sqrlonly
""""""""

Tells the server whether to enable or disable 'sqrlonly' 
on the server side. 

Contains the following additional element:

    - Boolean (required) signalling whether the option should 
      be turned on or off.

The subsequent call to :py:meth:`.Request.handle` expects the following dictionary:

    sqrlonly : (optional) boolean
        If present and False, the handler will hard fail. 
        It will set codes 0x10 and 0x40 and abort.
        In all other cases, the code will simply assume 
        the server has complied.

suk
"""

Tells the server to send the stored Server Unlock Key.

This action contains no additional elements.

The subsequent call to :py:meth:`.Request.handle` expects the following dictionary:

    suk : (optional) string
        If the server knows this user, it must return the 
        Server Unlock Key.

vuk
"""

Tells the server to send the Verify Unlock Key. This is needed
for account recovery functions like 'enable' and 'remove'.

This action contains no additional elements.

The subsequent call to :py:meth:`.Request.handle` expects the following dictionary:

    vuk : (required) string or None
        If None, then the server is asserting it doesn't
        have the VUK. A client error will be flagged.
        Will raise an exception if 'vuk' is not present.

Requests
^^^^^^^^

Additionally, the server can proactively request information
from the client. The spec currently supports two such features,
triggered by adding the following to the ``args`` argument
when calling the handler.

ask
"""

Sends a message to the client. If the client sends a response, it will 
make it available via the 'btn' action.

The value must be a dictionary containing at least
the key ``msg`` (string), containing the message to be sent.
It may also contain the key ``buttons``, which, if present,
must consist of a tuple of one or two other tuples, each
representing a button. The first element must be the text
for the button. A second element, if present, will be 
interpreted as a URL to associate with the button. The library 
will inject a well-formed 'ask' parameter into the
finalized response.

can
"""
Injects a cancellation URL into any response.

The value must be a valid URL path, with parameters,
if desired.

sin
"""

Completes the requested command but also sends a value to
the client to be encrypted. The client would then hopefully
reply with the INS and possibly PINS
encrypted values.

The value must be a string.

Step 4: Finalize the Request
----------------------------

The :py:meth:`.Request.finalize` method does the final steps to prepare the :py:class:`.Response`. You must pass it either a :py:class:`.Nut` you manually generated or the data needed to autogenerate a new one for you. It also finalizes the URL you want the client to respond to with its next request.

This method does not affect the :py:class:`.Request` object in any way. You can safely call this method multiple times with different parameters.

it will return to you a valid :py:class:`.Response` object.

Step 5: Return the Response
---------------------------

At this point it's a simple matter of calling :py:meth:`.Response.toString` and returning that in the body of your response to the client's POST.

For optimum security, you should also store the results of :py:meth:`.Response.hmac` with the session data and pass it to the new :py:class:`.Request` object you create when the client responds.









