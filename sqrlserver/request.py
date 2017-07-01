from .utils import pad, depad, stripurl, addquery, delquery
from .response import Response
from .nut import Nut
import ipaddress
import urllib.parse
import nacl.exceptions
import nacl.signing
import nacl.encoding
import nacl.hash
from base64 import urlsafe_b64encode, urlsafe_b64decode
import json

class Request(object):
    """Class encompassing SQRL client requests

    The class acts as a simple state machine. The request can have one
    of five states:

        - NEW (initial state, no processing has been done)
        - WELLFORMED (initial well-formedness checks have been done and passed)
        - VALID (initial validity tests have been done and passed;
          while in this state, the request will process client-
          submitted commands)
        - ACTION (the user needs to provide additional information)
        - COMPLETE (end state; finalize and return the response)

    After the class is initialized, call ``handle`` to start the
    transition loop. It will never exit without the state being either
    ACTION or COMPLETE.

        - ACTION means the user needs to gather information. It is
          accompanied by a payload that explains what it needs.
        - COMPLETE means that all processing that can be done has been
          done. You can finalize and return the response, which will
          include the necessary status codes for the client.

    Note:
        Errors in the \**kwargs will result in a thrown
        ValueError. Any other errors that arise not from client
        input also result in thrown errors. All client-related
        errors are communicated through the Response object.
    
    Args:
        key (bytes) : 32-byte encryption key. Must be the same as
            what you used to encrypt the nut.

        params (dict) : All the query parameters from the query string
            and POST body. 

            The following parameters must exist:

            - nut
            - server
            - client
            - ids

            Depending on the content of these, additional parameters
            may also be needed. Missing or malformed parameters will
            result in an error response.

    Keyword Args:
        ipaddr (string) : String representation of the valid IPv4
            or IPv6 address the request came from. Defaults to
            '0.0.0.0'.
        ttl (uint) : Required. The maximum acceptable age in
            seconds of the submitted nut. Defaults to 600 (10
            minutes).
        maxcounter (uint) : The maximum acceptable counter value
            in the submitted nut. Defaults to None, which disables
            upper-limit checking of the counter.
        mincounter (uint) : The minimum acceptable counter value
            in the submitted nut. Defaults to None, which disables
            lower-limit checking of the counter.
        secure (bool) : Whether the request was received via SSL.
            Defaults to True.
        hmac (string) : The response object emits a keyed MAC.
            Because this library is stateless, the server has to be
            responsible for storing this MAC if desired (recommended).
            It would need to be stored and returned with each repeated
            query in the same client session. If present, the validity
            check will verify that the MAC is valid. It is keyed by
            the master key passed at object instantiation. Unless that
            key is relatively stable, this check may not be useful.
    """

    supported_versions = ['1']
    known_cmds = ['query', 'ident', 'disable', 'enable', 'remove']  
    supported_cmds = ['query', 'ident', 'disable', 'enable', 'remove']
    known_opts = ['sqrlonly', 'hardlock', 'cps', 'suk']
    supported_opts = ['sqrlonly', 'hardlock', 'cps', 'suk']

    def __init__(self, key, params, **kwargs):
        self.ipaddr = ipaddress.ip_address('0.0.0.0')
        if 'ipaddr' in kwargs:
            try:
                self.ipaddr = ipaddress.ip_address(kwargs['ipaddr'])
            except Exception:
                raise ValueError("You must pass a valid IPv4 or IPv6 address.")
        
        self.ttl = 600
        if 'ttl' in kwargs:
            self.ttl = kwargs['ttl']
            if ( (not isinstance(self.ttl, int)) or (self.ttl < 0) ):
                raise ValueError("TTL must be an integer >= 0")
        
        self.maxcounter = None
        if 'maxcounter' in kwargs:
            self.maxcounter = kwargs['maxcounter']
            if ( (not isinstance(self.maxcounter, int)) or (self.maxcounter < 0) ):
                raise ValueError("If given, maxcounter must be an integer >= 0")
        
        self.mincounter = None
        if 'mincounter' in kwargs:
            self.mincounter = kwargs['mincounter']
            if ( (not isinstance(self.mincounter, int)) or (self.mincounter < 0) ):
                raise ValueError("If given, mincounter must be an integer >= 0")
        
        self.secure = True
        if 'secure' in kwargs:
            self.secure = kwargs['secure']

        self.hmac = None
        if 'hmac' in kwargs:
            self.hmac = kwargs['hmac']
        
        self._response = Response()
        self.params = dict(params)
        self.key = key
        self.admin = False

        #set initial state 
        self.state = 'NEW'
        self.action = []

    def __repr__(self):
        return "<Request(key={}, ipaddr={}, ttl={}, mincounter={}, maxcounter={}, secure={}, hmac={}, params={}, state={}, action={})>".format(self.key, self.ipaddr, self.ttl, self.mincounter, self.maxcounter, self.secure, self.hmac, self.params, self.state, self.action)

    def handle(self, args={}):
        """The core request handler. 

        After each call, it will set the ``state`` property to either
        ``ACTION`` or ``COMPLETE``. The user is expected to keep
        calling ``handle`` (with appropriate ``args``) until
        ``COMPLETE``, at which point the response object can be
        finalized and returned.

        Args:
            args (dict) : Different ``action`` settings require
                different information to resolve (documented below). Pass
                that data here.

        Notes:
            The goal of this library is to generalize as much as is
            reasonable. That means this code has no idea how your
            server runs or stores data. So to fulfil the request, it
            may require additional information. That is gathered by
            setting the ``state`` to ``ACTION`` and by setting the
            ``action`` property.

            The ``action`` property, if set, will be an array of
            tuples. The actions should be resolved in the order
            provided.

            The first element of each tuple will be a keyword,
            described further below. Depending on that keyword,
            additional elements may be provided. You are expected to
            call ``handle`` again with any requested information
            passed in a single dictionary.

            *auth*

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

                The subsequent call to ``handle`` expects the following dictionary:
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

            *btn*

                Means the request was accompanied by a 'btn' parameter.

                Contains the following additional element:
                    - String : One of '1', '2', or '3'

                This action has no requirements for subsequent calls to ``handle``.

            *confirm*

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

                The subsequent call to ``handle`` expects the following dictionary:
                    confirmed : boolean
                        If present and True, the handler will process
                        the request. In all other cases, the handler
                        will set the appropriate error codes and
                        terminate.

            *disable*

                Tells the server to disable this SQRL identity.

                Contains the following additional element:
                    - String (required) representing the SQRL identity

                The subsequent call to ``handle`` expects the following dictionary:
                    deactivated : (required) boolean
                        If present and True, the server is saying they have complied.
                        If present and False, the user will be notified that the command was
                        not completed. 
                        If not present, an exception will be thrown.
                        True implies 'found' is also True.
                    suk : (dependent) string
                        If 'deactivated' is True , you must provide the Server 
                        Unlock Key. Failure to do so will raise an exception.
                    found : (optional, recommended) boolean
                        Only useful if 'deactivated' is False.
                        If present, signals whether the server recognizes this user.

            *enable*

                Tells the server to enable the given account. 

                Contains the following additional element:
                    activated : (required) boolean
                        If present and True, the server is saying they have complied.
                        If present and False, the user will be notified 
                        that the command was not completed.
                        If not present, an exception will be thrown.
                        True implies 'found' is also True.
                    found : (optional, recommended) boolean
                        Only useful if 'activated' is False.
                        If present, signals whether the server recognizes this user.

            *find*

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

                The subsequent call to ``handle`` expects the following dictionary:
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
            
            *hardlock*

                Tells the server whether to enable or disable 'hardlock' on 
                the server side.

                Contains the following additional element:
                    - Boolean (required) signalling whether the option 
                      should be turned on or off.

                The subsequent call to ``handle`` expects the following dictionary:
                    hardlock: (optional) boolean
                        If present and False, the handler will hard fail. 
                        It will set codes 0x10 and 0x40 and abort.
                        In all other cases, the code will simply assume the 
                        server has complied.

            *ins*

                Means the request was accompanied by a 'ins' parameter.

                Contains the following additional element:
                    - String : The value of the 'ins' parameter

                This action has no requirements for subsequent calls to ``handle``.

            *pins*

                Means the request was accompanied by a 'pins' parameter.

                Contains the following additional element:
                    - String : The value of the 'ins' parameter

                This action has no requirements for subsequent calls to ``handle``.

            *remove*

                Tells the server to remove the given account. 

                Contains the following additional element:
                    removed : (required) boolean
                        If present and True, the server is saying they have complied.
                        If present and False, the user will be notified 
                        that the command was not completed.
                        If not present, an exception will be thrown.
                        True implies 'found' is also True.
                    found : (optional, recommended) boolean
                        Only useful if 'removed' is False.
                        If present, signals whether the server recognizes this user.

            *sqrlonly*

                Tells the server whether to enable or disable 'sqrlonly' 
                on the server side. 

                Contains the following additional element:
                    - Boolean (required) signalling whether the option should 
                      be turned on or off.

                The subsequent call to ``handle`` expects the following dictionary:
                    sqrlonly : (optional) boolean
                        If present and False, the handler will hard fail. 
                        It will set codes 0x10 and 0x40 and abort.
                        In all other cases, the code will simply assume 
                        the server has complied.

            *suk*

                Tells the server to send the stored Server Unlock Key.

                This action contains no additional elements.

                The subsequent call to ``handle`` expects the following dictionary:
                    suk : (optional) string
                        If the server knows this user, it must return the 
                        Server Unlock Key.

            *vuk*

                Tells the server to send the Verify Unlock Key. This is needed
                for account recovery functions like 'enable' and 'remove'.

                This action contains no additional elements.

                The subsequent call to ``handle`` expects the following dictionary:
                    vuk : (required) string or None
                        If None, then the server is asserting it doesn't
                        have the VUK. A client error will be flagged.
                        Will raise an exception if 'vuk' is not present.

            Additionally, the server can proactively request information
            from the client. The spec currently supports two such features,
            triggered by adding the following to the ``args`` variable
            when calling the handler.

            *ask*

                Aborts the current command (TIF 0x40) and sends a message
                to the client. If the client sends a response, it will 
                made available via the 'btn' action.

                The value of 'ask' must be a dictionary containing at least
                the key ``msg`` (string), containing the message to be sent.
                It may also contain the key ``buttons``, which, if present,
                must consist of a tuple of one or two other tuples, each
                representing a button. The first element must be the text
                for the button. A second element, if present, will be 
                interpreted as a URL to associate with the button. The library 
                will inject a well-formed 'ask' parameter into the
                finalized response.

            *can*

                Injects a cancellation URL into any response.

                The value must be a valid URL path, with parameters,
                if desired.

            *sin*

                Completes the requested command but also sends a value to
                the client to be encrypted. The client would then hopefully
                reply with a 'query' containing the INS and possibly PINS
                encrypted values.

                The value must be a string.
        """

        #First check if we're in an ``ACTION`` state and process given data
        #Throw error if insufficient or malformed data is passed.
        #Otherwise, set appropriate state and continue.
        if self.state == 'ACTION':
            for action in self.action:
                if action[0] == 'confirm':
                    if ('confirmed' in args) and (args['confirmed'] == True ):
                        self.state = 'VALID'
                    else:
                        self._response.tifOn(0x20, 0x40)
                        self.state = 'COMPLETE'
                elif action[0] == 'find':
                    if ( ('found' in args) and (isinstance(args['found'], list)) and (len(args['found']) > 0) ):
                        if args['found'][0] == True:
                            self._response.tifOn(0x01)
                            if 'disabled' in args:
                                self._response.tifOn(0x08)
                                if ( ('suk' not in args) or (not isinstance(args['suk'], str)) or (len(args['suk']) == 0) ):
                                    raise ValueError("You must provide the Server Unlock Key if you encounter a disabled account.")
                                self._response.addParam('suk', args['suk'])
                        if (len(args['found']) > 1):
                            if args['found'][1] == True:
                                self._response.tifOn(0x02)
                        self.state = 'COMPLETE'
                    else:
                        raise ValueError("The server failed to respond adequately to the 'find' action. The handler expects a key 'found' and a value that is an array of one or more booleans.")
                elif action[0] == 'auth':
                    if ('authenticated' not in args):
                        raise ValueError("The server failed to respond adequately to the 'ident' action. The handler expects the key 'authenticated' with a boolean value.")
                    if args['authenticated']:
                        self._response.tifOn(0x01)
                        if 'url' in args:
                            self._response.addParam('url', args['url'])
                        self.state = 'COMPLETE'
                    else:
                        if 'disabled' in args:
                            self._response.tifOn(0x01, 0x08, 0x40)
                            if ( ('suk' not in args) or (not isinstance(args['suk'], str)) or (len(args['suk']) == 0) ):
                                raise ValueError("You must provide the Server Unlock Key if you encounter a disabled account.")
                            self._response.addParam('suk', args['suk'])
                        else:
                            self._response.tifOn(0x40, 0x80)
                        self.state = 'COMPLETE'
                elif action[0] == 'disable':
                    if 'deactivated' not in args:
                        raise ValueError("The server failed to respond adequately to the 'disable' action. The handler expects the key 'deactivated' with a boolean value.")
                    if args['deactivated']:
                        if ( ('suk' not in args) or (not isinstance(args['suk'], str)) or (len(args['suk']) == 0) ):
                            raise ValueError("You must provide the Server Unlock Key if you encounter a disabled account.") 
                        else:
                            self._response.addParam('suk', args['suk'])

                        self._response.tifOn(0x01, 0x08)
                        self.state = 'COMPLETE'
                    else:
                        if ( ('found' in args) and (args['found']) ):
                            self._response.tifOn(0x01)
                        self._response.tifOn(0x40)
                        self.state = 'COMPLETE'
                elif action[0] == 'sqrlonly':
                    if ( ('sqrlonly' in args) and (args['sqrlonly'] == False) ):
                        self._response.tifOn(0x10, 0x40)
                        self.state = 'COMPLETE'
                elif action[0] == 'hardlock':
                    if ( ('hardlock' in args) and (args['hardlock'] == False) ):
                        self._response.tifOn(0x10, 0x40)
                        self.state = 'COMPLETE'
                elif action[0] == 'suk':
                    if 'suk' in args:
                        self._response.addParam('suk', args['suk'])
                elif action[0] == 'vuk':
                    if 'vuk' not in args:
                        raise ValueError("The server failed to adequately respond to the 'vuk' action. The handler expects either the stored VUK or None if the user isn't recognized.")
                    if args['vuk'] is None:
                        self._response.tifOn(0x40, 0x80)
                        self.state = 'COMPLETE'
                    else:
                        if 'urs' not in self.params:
                            self._response.tifOn(0x40, 0x80)
                            self.state = 'COMPLETE'
                        else:
                            if Request._signature_valid(self._tosign, args['vuk'], self.params['urs']):
                                self.admin = True
                                self.state = 'VALID'
                            else:
                                self._response.tifOn(0x40, 0x80)
                                self.state = 'COMPLETE'
                elif action[0] == 'enable':
                    if 'activated' not in args:
                        raise ValueError("The server failed to respond adequately to the 'enable' action. The handler expects the key 'activated' with a boolean value.")
                    if args['activated']:
                        self._response.tifOn(0x01)
                        self.state = 'COMPLETE'
                    else:
                        if ( ('found' in args) and (args['found']) ):
                            self._response.tifOn(0x01)
                        self._response.tifOn(0x40)
                        self.state = 'COMPLETE'
                elif action[0] == 'remove':
                    if 'removed' not in args:
                        raise ValueError("The server failed to respond adequately to the 'remove' action. The handler expects the key 'removed' with a boolean value.")
                    if args['removed']:
                        self._response.tifOff(0x01)
                        self.state = 'COMPLETE'
                    else:
                        if ( ('found' in args) and (args['found']) ):
                            self._response.tifOn(0x01)
                        self._response.tifOn(0x40)
                        self.state = 'COMPLETE'
                else:
                    raise ValueError('Unrecognized action ({}). This should never happen!'.format(action[0]))
            self.action = []

        #Check for params not tied to specific actions and handle.
        #Includes 'sin' (with 'ins' and 'pins') and 'ask' (with 'btn')
        if 'sin' in args:
            self._response.addParam('sin', args['sin'])
        if 'can' in args:
            self._response.addParam('can', stripurl(args['can']))
        if 'ask' in args:
            if 'msg' not in args['ask']:
                raise ValueError("The server requested an ASK without specifying a message.")
            msg = depad(urlsafe_b64encode(args['ask']['msg'].encode('utf-8')).decode('utf-8'))
            if 'buttons' in args['ask']:
                for btn in args['ask']['buttons']:
                    if ';' in btn[0]:
                        raise ValueError("Semicolons may not be used in button labels.")
                    txt = depad(urlsafe_b64encode(btn[0].encode('utf-8')).decode('utf-8'))
                    if len(btn) == 2:
                        txt += ';' + stripurl(btn[1])
                    msg += '~' + txt
            self._response.addParam('ask', msg)
            self._response.tifOn(0x40)
            self.state = 'COMPLETE'
        for param in ['btn', 'ins', 'pins']:
            if param in self.params['client']:
                self.action.append((param, self.params['client'][param]))

        #Loop until we need additional information or are finished.
        #TODO: Need to prove there's no chance of an infinite loop, or rewrite.
        #      For now I have a counter.
        count = 0
        while self.state not in ['ACTION', 'COMPLETE']:
            count += 1
            if count > 5:
                raise RuntimeError("Looks like an infinite loop. Here's the request:\n{}".format(self))
            if self.state == 'NEW':
                #perform basic well-formedness checks and set state accordingly
                wf = self._check_well_formedness()
                if wf:
                    self.state = 'WELLFORMED'
                else:
                    self._response.tifOn(0x40, 0x80)
                    self.state = 'COMPLETE'
            elif self.state == 'WELLFORMED':
                #perform validity tests and set state accordingly
                errs = self._check_validity()
                #invalid signature
                if 'sigs' in errs:
                    self._response.tifOn(0x40, 0x80)
                    self.state = 'COMPLETE'
                elif 'hmac' in errs:
                    self._response.tifOn(0x40, 0x80)
                    self.state = 'COMPLETE'
                elif 'nut' in errs:
                    self._response.tifOn(0x20, 0x40)
                    self.state = 'COMPLETE'
                elif len(errs) > 0:
                    self.state = 'ACTION'
                    self.action.append(('confirm', errs))
                else:
                    self.state = 'VALID'
            elif self.state == 'VALID':
                #process the CMD
                cmd = self.params['client']['cmd']
                #Is the ``cmd`` supported?
                if (cmd not in self.supported_cmds):
                    self._response.tifOn(0x10, 0x40)
                    self.state = 'COMPLETE'
                else:
                    if cmd == 'query':
                        self.state = 'ACTION'
                        keys = [self.params['client']['idk']]
                        if 'pidk' in self.params['client']:
                            keys.append(self.params['client']['pidk'])
                        self.action.append(('find', keys))
                    elif cmd == 'ident':
                        act = ['auth', self.params['client']['idk']]
                        if 'suk' in self.params['client']:
                            act.append(self.params['client']['suk'])
                        else:
                            act.append(None)
                        if 'vuk' in self.params['client']:
                            act.append(self.params['client']['vuk'])
                        else:
                            act.append(None)
                        if 'cps' in self.params['client']['opt']:
                            act.append('cps')
                        self.action.append(tuple(act))
                        self._process_opts()
                        self.state = 'ACTION'
                    elif cmd == 'disable':
                        self.action.append(('disable', self.params['client']['idk']))
                        self._process_opts()
                        self.state = 'ACTION'
                    elif cmd == 'enable':
                        if self.admin:
                            self.action.append(('enable', self.params['client']['idk']))
                            self._process_opts()
                            self.state = 'ACTION'
                        else:
                            self.action.append(('vuk',))
                            self.state = 'ACTION'
                    elif cmd == 'remove':
                        if self.admin:
                            self.action.append(('remove', self.params['client']['idk']))
                            self.state = 'ACTION'
                        else:
                            self.action.append(('vuk',))
                            self.state = 'ACTION'
                    else:
                        raise RuntimeError("The supported command '{}' was unhandled! This should never happen! Please file a bug report!".format(cmd))
            else:
                raise ValueError('The given request state ({}) is unrecognized. This should never happen!'.format(self.state))

        #This code should never exit in a state other than ``ACTION`` or ``COMPLETE``
        assert self.state in ['ACTION', 'COMPLETE']

    def _process_opts(self):
        """Private method for extracting and acting on options.

        It will fail unless the Request is currently in the 'VALID' state.
        It should only be called at the end of a non-query CMD session.

        The 'cps' option is handled by the 'ident' CMD handler.
        """

        assert self.state == 'VALID'
        opts = self.params['client']['opt']
        if 'sqrlonly' in opts:
            self.action.append(('sqrlonly', True))
        else:
            self.action.append(('sqrlonly', False))
        
        if 'hardlock' in opts:
            self.action.append(('hardlock', True))
        else:
            self.action.append(('hardlock', False))

        if 'suk' in opts:
            self.action.append(('suk',))

    def finalize(self, **kwargs):
        """Finalizes and returns the internal Response object.

        This function has no side effects. It can be called multiple
        times without issue.

        Keyword Args:
            counter (uint) : 32-byte integer to encode as the 
                counter value in the new nut. Must be provided if you 
                want the object to generate the nut for you.
            ipaddr (string) : The IPv4 or IPv6 address you want encoded
                into the new nut. If not provided, it will use the ipaddress
                saved in the Request object.
            nut (Nut) : A pre-generated nut. If provided, this nut will
                be injected into the response. Otherwise a new nut will
                be generated and injected for you.
            params (dict) : A dictionary of name-value pairs that will be
                sent to the client, and that the client is supposed to
                return untouched. You can also encode these values into
                the ``qry``.
            qry (string) : The URL the client should respond to. If
                not provided,the last value sent will be used. This is a
                good place to also encode any state information you want
                the client to return to you (though see ``params`` below).
                The scheme and netloc parts will be stripped, if given.
                The nut (whether autogenerated or provided) will be
                inserted into ``qry`` for you.
            timestamp (uint) : Unix timestamp (seconds only) to be encoded
                into the new nut. If omitted, it will use the current 
                system time.

        Returns:
            Response : the finalized response object.
        """
        
        #choose a nut
        nut = None
        if 'nut' in kwargs:
            assert isinstance(kwargs['nut'], Nut)
            nut = kwargs['nut']
        else:
            assert 'counter' in kwargs
            nut = Nut(self.key)
            ipaddr = self.ipaddr
            if 'ipaddr' in kwargs:
                ipaddr = kwargs['ipaddr']
            timestamp = None
            if 'timestamp' in kwargs:
                timestamp = kwargs['timestamp']
            nut.generate(ipaddr, kwargs['counter'], timestamp=timestamp)
        assert nut is not None
        oldnut = Nut(self.key)
        oldnut.load(self.params['nut'])
        nutstr = nut.toString('qr')
        if oldnut.islink:
            nutstr = nut.toString('link')

        #finalize qry
        qry = None
        if 'qry' in kwargs:
            qry = kwargs['qry']
        else:
            if isinstance(self.params['server'], dict):
                qry = self.params['server']['qry']
            else:
                qry = self.params['server']
        assert qry is not None
        qry = stripurl(addquery(qry, {'nut': nutstr}))

        #get a copy of the current response
        r = Response.load(self._response)

        #add to response object
        r.addParam('nut', nutstr)
        r.addParam('qry', qry)

        #return response object
        return r

    def _check_well_formedness(self):
        """Performs basic well-formedness checks.

        Ensures that
            - the required parameters are present,
            - the ``client`` parameter can be parsed,
            - the parsed ``client`` parameter contains required and valid keys, and
            - the ``server`` parameter can be parsed.

        Returns:
            bool : Whether the Request is well formed

        Warning:
            Because of side effects, this should never be called directly
            except in unit testing
        """

        #required params
        for req in ['nut', 'client', 'server', 'ids']:
            if req not in self.params:
                return False

        self._origserver = self.params['server']
        self._tosign = self.params['client'] + self.params['server']
        
        #valid client
        try:
            self.params['client'] = Request._extract_client(self.params['client'])
        except:
            return False

        for req in ['ver', 'cmd', 'idk']:
            if req not in self.params['client']:
                return False
        if self.params['client']['ver'] not in self.supported_versions:
            return False
        if self.params['client']['cmd'] not in self.known_cmds:
            return False
        if 'opt' in self.params['client']:
            for opt in self.params['client']['opt']:
                if opt not in self.known_opts:
                    return False

        #valid server
        try:
            self.params['server'] = Request._extract_server(self.params['server'])
        except:
            return False

        return True

    def _check_validity(self):
        """Performs initial validity checks.

        Ensures that
            - all signatures are valid,
            - the hmac is valid (if provided), and
            - the nut is valid.

        Returns:
            list : List of strings representing error states. A length of zero
                means the Request is valid. Otherwise it returns one or more
                of the following codes.

        **Error Codes**

            ``sigs`` : One or more signatures were invalid.
            ``hmac`` : The HMAC didn't match.
            ``nut`` : The nut failed fundamental decryption checks.
            ``ip`` : The ip addresses didn't match. Request confirmation.
            ``time`` : The nut is stale. Request confirmation.
            ``counter`` : The counter was out of bounds (if provided). 
                Request confirmation.

        Warning:
            Because of side effects, this should never be called directly
            except in unit testing. It must also only be called *after* the 
            well-formedness check.
        """

        errs = []

        # Validate the signatures. If any of them are invalid, reject everything.
        validsigs = Request._signature_valid(self._tosign, self.params['client']['idk'], self.params['ids'])
        if ( (validsigs) and ('pidk' in self.params['client']) and ('pids' in self.params) ):
            validsigs = Request._signature_valid(self._tosign, self.params['client']['pidk'], self.params['pids'])
        if not validsigs:
            errs.append('sigs')

        if validsigs:
            #validate hmac if present
            validmac = True
            if self.hmac is not None:
                mac = depad(nacl.hash.siphash24(self._origserver.encode('utf-8'), key=self.key[:16], encoder=nacl.encoding.URLSafeBase64Encoder).decode('utf-8'))
                if self.hmac != mac:
                    validmac = False
                    errs.append('hmac')

            if validmac:
                # Validate nut 
                validnut = True
                nut = Nut(self.key)
                try:
                    nut = nut.load(self.params['nut']).validate(self.ipaddr, self.ttl, maxcounter=self.maxcounter, mincounter=self.mincounter)
                except nacl.exceptions.CryptoError:
                    validnut = False
                if not validnut:
                    errs.append('nut')

                if validnut:
                    if not nut.ipmatch:
                        errs.append('ip')
                    else:
                        self._response.tifOn(0x04)
                    if not nut.fresh:
                        errs.append('time')
                    if not nut.countersane:
                        errs.append('counter')

        return errs

    @staticmethod
    def _extract_client(s):
        """Decodes and processes client parameter from auth request

        Args:
            s (string) : The b64u-encoded string passed by the client.

        Returns:
            dict
        """

        s = urlsafe_b64decode(pad(s)).decode('utf-8').strip()

        '''
        While it would be great to be able to do the following, I can't
        because the spec currently does not require that the values be
        escaped, so on the back burner for now.

        s = s.replace('\r\n', '&')
        return urllib.parse.parse_qs(s)
        '''
        client = {}
        for line in s.split('\r\n'):
            name, value = line.split('=', 1)
            if name == 'opt':
                value = value.split('~')
            client[name] = value
        return client

    @staticmethod
    def _extract_server(s):
        """Decodes and processes server parameter from auth request

        Args:
            s (string) : The b64u-encoded string passed by the client.

        Returns:
            dict
        """

        s = urlsafe_b64decode(pad(s)).decode('utf-8').strip()
        
        #if it's a valid s/qrl URL, then return it
        u = urllib.parse.urlparse(s)
        if ( (u.scheme == 'sqrl') or (u.scheme == 'qrl') ):
            return s

        #Otherwise it's name/value pairs
        server = {}
        for line in s.split('\r\n'):
            name, value = line.split('=', 1)
            server[name] = value
        return server

    @staticmethod
    def _signature_valid(msg, key, sig):
        """Validates Ed25519 signatures

        Args:
            msg (string) : The signed message.
            key (string) : The b64u-encoded signing key.
            sig (string) : The b64u-encoded signature.

        Returns:
            bool : Whether the signature matches or not.
        """

        try:
            vk = nacl.signing.VerifyKey(pad(key), encoder=nacl.encoding.URLSafeBase64Encoder)
            vk.verify(msg.encode('utf-8'), urlsafe_b64decode(pad(sig)))
            return True
        except nacl.exceptions.BadSignatureError:
            return False



