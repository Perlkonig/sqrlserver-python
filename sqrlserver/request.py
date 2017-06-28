from .utils import pad, depad
from .response import Response
from .nut import Nut
import ipaddress
import urllib.parse
import nacl.exceptions
import nacl.signing
import nacl.encoding
import nacl.hash
from base64 import urlsafe_b64encode, urlsafe_b64decode

class Request:
    """Class encompassing SQRL client requests

    The class acts as a simple state machine. The request can have one of five states:
        - NEW (initial state, no processing has been done)
        - WELLFORMED (initial well-formedness checks have been done and passed)
        - VALID (initial validity tests have been done and passed; while in this state, the request will processing client-submitted commands)
        - ACTION (the user needs to provide additional information)
        - COMPLETE (end state; finalize and return the response)

    After the class is initialized, call ``handle`` to start the transition loop. 
    It will never exit without the state being either ACTION or COMPLETE.
        - ACTION means the user needs to gather information. It is accompanied by a payload that explains what it needs.
        - COMPLETE means that all processing that can be done has been done. You can finalize and return the response, which will include the necessary status codes for the client.
    """

    supported_versions = ['1']
    known_cmds = ['query', 'ident', 'disable', 'enable', 'remove']  
    supported_cmds = ['query', 'ident']
    known_opts = ['sqrlonly', 'hardlock', 'cps', 'suk']
    supported_opts = ['sqrlonly', 'hardlock', 'cps', 'suk']
    actions = ['confirm']

    def __init__(self, key, params, **kwargs):
        """Constructor

        Errors in the \**kwargs will result in a thrown ValueError.
        Any other errors that arise not from client input also result in thrown errors.
        All client-related errors are communicated through the Response object. 

        Parameters
        ----------
        key : byte string
            16-byte encryption key
        params : dictionary
            All the query parameters from the query string and POST body.
            The following parameters must exist:
                - nut
                - server
                - client
                - idk
                - ids
            Depending on the content of these, additional parameters may also be needed.
            Missing or malformed parameters will result in an error response.
        \**kwargs : see below

        Keyword Arguments
        -----------------
        ipaddr : string
            Required. String representation of the valid IPv4 or IPv6 address 
            the request came from. Defaults to '0.0.0.0'.
        ttl : integer
            Required. The maximum acceptable age in seconds of the submitted nut.
            Defaults to 600 (10 minutes).
        maxcounter : integer
            The maximum acceptable counter value in the submitted nut.
            Defaults to None, which disables upper-limit checking of the counter.
        mincounter : integer
            The minimum acceptable counter value in the submitted nut.
            Defaults to None, which disables lower-limit checking of the counter.
        secure : boolean
            Whether the request was received via SSL. Defaults to True.
        hmac : string
            The response object emits a keyed MAC. Because this library is stateless, the server
            has to be responsible for storing this MAC if desired (recommended). It would need to be
            stored and returned with each repeated query in the same client session. If present,
            the validity check will verify that the MAC is valid. It is keyed by the master key
            passed at object instantiation. Unless that key is relatively stable, this check may 
            not be useful.
        """
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

        #set initial state 
        self.state = 'NEW'
        self.action = []

    def handle(self, args={}):
        """The core request handler. After each call, it will set the ``state``
        property to either ``ACTION`` or ``COMPLETE``. The user is expected to keep 
        calling ``handle`` (with appropriate ``args``) until ``COMPLETE``, at which 
        point the response object can be finalized and returned.

        Parameters
        ----------
        args : dictionary
            Different ``action`` settings require different information to resolve.
            Pass that data here.

        Recognized Commands
        -------------------
        The SQRL spec [LINK] defines five commands the server should handle:
          - ``query``
          - ``ident``
          - ``disable``
          - ``enable``
          - ``remove``

        Actions
        -------
        The goal of this library is to generalize as much as is reasonable. That means
        this code has no idea how your server runs or stores data. So to fulfil the request,
        it may require additional information. That is gathered by setting the ``state`` to
        ``ACTION`` and by setting the ``action`` property.

        The ``action`` property, if set, will be an array of tuples. The actions should
        be resolved in the order provided. 

        The first element of each tuple will be a keyword, described further below. Depending 
        on that keyword, additional elements may be provided. You are expected to call ``handle``
        again with any requested information passed in a single dictionary.

        To prevent infinite loops, if the data provided to an action request is insufficient,
        a default action will be taken if appropriate (e.g., anything other than an explicit
        affirmitive response to the ``confirm`` action will be treated as rejection) or an 
        exception will be thrown.

        confirm
        ^^^^^^^
            Means there is an issue with the nut. The server must confirm whether they wish
            to proceed.

            Contains the following additional element:
                - Array of strings representing possible issues:
                    - ip: the ip addresses didn't match
                    - time: the nut is older than the specified ttl
                    - counter: the counter did not pass requested sanity checks

            The subsequent call to ``handle`` expects the following dictionary:
                'confirmed' : boolean
                    If present and True, the handler will process the request.
                    In all other cases, the handler will set the appropriate error 
                    codes and terminate.
        find
        ^^^^
            Asks the server to locate the given keys in their user database.

            Contains the following additional element:
                - Array of strings representing SQRL identities. This array will always
                at least contain the primary identity. If a previous identities were given
                by the client, they will also appear in the list. The spec currently
                limits the number of previous identities to one at a time (meaning this
                array should never be longer than two elements), but there's no reason
                to enforce that at this level. The server should simply check all keys.

            The subsequent call to ``handle`` expects the following dictionary:
                'found' : (required) array of booleans
                    True indicates that the key is recognized.
                    False indicates that the key is not recognized.
                    The order should be the same as provided in the ``action`` property.
                'disabled' : (optional) ANY
                    The presence of this key (regardless of value) means the primary identity 
                    is recognized but that the user disabled it. It cannot be used for 
                    authentication until reenabled or rekeyed.
        auth
        ^^^^
            Asks the server to officially authenticate the given user. 

            Contains the following additional elements:
                - String (required) representing the SQRL identity
                - String constant ``cps`` (optional) requesting that the auth be handled
                  as a  "Client Provided Session"

            The subsequent call to ``handle`` expects the following dictionary:
                'identified' : (required) boolean
                    If present and True, the handler will signal success to the client.
                    In all other cases, the handler will signal an error of some kind.
                'disabled' : (optional) ANY
                    The presence of this key (regardless of value) means the primary identity 
                    is recognized but that the user disabled it. It cannot be used for 
                    authentication until reenabled or rekeyed.

        sqrlonly
        ^^^^^^^^
            Tells the server whether to enable or disable 'sqrlonly' on the server side.
            The spec is unclear about what should happen if the server doesn't want or is
            unable to honour the request. Here's how the code handles it for now.

            Contains the following additional element:
                - Boolean (required) signalling whether the option should be turned on or off.

            The subsequent call to ``handle`` expects the following dictionary:
                'sqrlonly': (optional) boolean
                    If present and False, the handler will hard fail. It will set codes 0x10 and 0x40
                    and abort.
                    In all other cases, the code will simply assume the server has complied.

        hardlock
        ^^^^^^^^
            Tells the server whether to enable or disable 'hardlock' on the server side.
            The spec is unclear about what should happen if the server doesn't want or is
            unable to honour the request. Here's how the code handles it for now.

            Contains the following additional element:
                - Boolean (required) signalling whether the option should be turned on or off.

            The subsequent call to ``handle`` expects the following dictionary:
                'hardlock': (optional) boolean
                    If present and False, the handler will hard fail. It will set codes 0x10 and 0x40
                    and abort.
                    In all other cases, the code will simply assume the server has complied.

        suk
        ^^^
            Tells the server to send the stored Server Unlock Key.

            This action contains no additional elements.

            The subsequent call to ``handle`` expects the following dictionary:
                'suk': (required) string
                    The server must return the Server Unlock Key they stored with the user's identity.
                    Failure to do so will throw an error.
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
                        if (len(args['found']) > 1):
                            if args['found'][1] == True:
                                self._response.tifOn(0x02)
                        self.state = 'COMPLETE'
                    else:
                        raise ValueError("The server failed to respond adequately to the 'find' action. The handler expects a key 'found' and a value that is an array of one or more booleans.")
                elif action[0] == 'sqrlonly':
                    if ( ('sqrlonly' in args) and (args['sqrlonly'] == False) ):
                        self._response.tifOn(0x10)
                        self._response.tifOn(0x40)
                        self.state = 'COMPLETE'
                elif action[0] == 'hardlock':
                    if ( ('hardlock' in args) and (args['hardlock'] == False) ):
                        self._response.tifOn(0x10)
                        self._response.tifOn(0x40)
                        self.state = 'COMPLETE'
                elif action[0] == 'suk':
                    if ( ('suk' not in args) or (not isinstance(args['suk'], str)) or (len(args['suk'].strip()) == 0) ):
                        raise ValueError("The server failed to provide the requested Server Unlock Key.")
                    self._response.addParam('suk', args['suk'])
                else:
                    raise ValueError('Unrecognized action ({}). This should never happen!'.format(action[0]))
            self.action = []

        #Loop until we need additional information or are finished.
        #TODO: Need to prove there's no chance of an infinite loop, or rewrite.
        while self.state not in ['ACTION', 'COMPLETE']:
            if self.state == 'NEW':
                #perform basic well-formedness checks and set state accordingly
                wf = self.check_well_formedness()
                if wf:
                    self.state = 'WELLFORMED'
                else:
                    self._response.tifOn(0x40, 0x80)
                    self.state = 'COMPLETE'
            elif self.state == 'WELLFORMED':
                #perform validity tests and set state accordingly
                errs = self.check_validity()
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
                        if 'cps' in self.params['client']['opt']:
                            self.action.append(('auth', self.params['client']['idk'], 'cps'))
                        else:
                            self.action.append(('auth', self.params['client']['idk']))
                    else:
                        raise RuntimeError("The supported command '{}' was unhandled! This should never happen! Please file a bug report!".format(cmd))
            else:
                raise ValueError('The given request state ({}) is unrecognized. This should never happen!'.format(self.state))

        #This code should never exit in a state other than ``ACTION`` or ``COMPLETE``
        assert self.state in ['ACTION', 'COMPLETE']

    def _process_opts(self):
        """Private method for extracting options and appending appropriate actions
        to the queue. It will fail unless the Request is currently in the 'VALID' state.
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

    def response(self):
        """Finalizes and returns the internal Response object.

        Parameters
        ----------
        """
        pass

    def check_well_formedness(self):
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

    def check_validity(self):
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
        """Decodes and processes client parameter from auth request"""
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
        """Decodes and processes server parameter from auth request"""
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
        try:
            vk = nacl.signing.VerifyKey(pad(key), encoder=nacl.encoding.URLSafeBase64Encoder)
            vk.verify(msg.encode('utf-8'), urlsafe_b64decode(pad(sig)))
            return True
        except nacl.exceptions.BadSignatureError:
            return False



