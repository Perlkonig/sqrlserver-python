from .utils import pad, depad
from .response import Response
from .nut import Nut
import ipaddress
import urllib.parse
import nacl.exceptions
import nacl.signing
import nacl.encoding
from base64 import urlsafe_b64encode, urlsafe_b64decode

class Request:
    """Class encompassing SQRL client requests

    Anticipated workflow is as follows:
        - Construct
        - While ``action`` is None
            - Execute ``handle``, passing any arguments needed based on ``action``
        - Generate and return ``response``
    """

    supported_versions = ['1']
    known_cmds = ['query', 'ident', 'disable', 'enable', 'remove']  
    supported_cmds = ['query']
    known_opts = ['sqrlonly', 'hardlock', 'cps', 'suk']
    supported_opts = []

    def __init(self, key, params, **kwargs):
        """Constructor

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
        
        self._response = Response()
        self.params = params

        self.wellformed = True
        #required params
        if self.wellformed:
            for req in ['nut', 'client', 'server', 'idk', 'ids']:
                if req not in self.params:
                    self.wellformed = False
                    break

        self.tosign = self.params['client'] + self.params['server']
        
        #valid client
        if self.wellformed:
            try:
                self.params['client'] = Request._extract_client(self.params['client'])
            except:
                self.wellformed = False
            if self.wellformed:
                for req in ['ver', 'cmd']:
                    if req not in self.params['client']:
                        self.wellformed = False
                        break
                if self.params['client']['ver'] not in self.supported_versions:
                    self.wellformed = False
                if self.params['client']['cmd'] not in self.known_cmds:
                    self.wellformed = False
                if 'opt' in self.params['client']:
                    for opt in self.params['client']['opt']:
                        if opt not in self.known_opts:
                            self.wellformed = False
                            break

        #valid server
        if self.wellformed:
            try:
                self.params['server'] = Request._extract_server(self.params['server'])
            except:
                self.wellformed = False

        self.action = None
        #if not well formed, seed the response
        if not self.wellformed:
            self._response.tifOn(0x40, 0x80)
        #otherwise handle it
        else:
            # Validate the signatures. If any of them are invalid, reject everything.
            validsigs = Request._signature_valid(self.tosign, self.params['idk'], self.params['ids'])
            if ( (validsigs) and ('pidk' in self.params) and ('pids' in self.params) ):
                validsigs = Request._signature_valid(self.tosign, self.params['pidk'], self.params['pids'])

            if validsigs:
                # Validate nut when request is first built so later 
                # iterations of ``handle`` don't have to
                validnut = True
                self.nut = Nut(key)
                try:
                    self.nut = nut.load(self.params['nut']).validate(self.ipaddr, self.ttl)
                except nacl.exceptions.CryptoError:
                    validnut = False

                if validnut:
                    errs = []
                    if not self.nut.ipmatch:
                        errs.append('ip')
                    else:
                        self._response.tifOn(0x04)
                    if not self.nut.fresh:
                        errs.append('time')
                    if not self.nut.countersane:
                        errs.append('counter')

                    #If there are errors, set the 'confirm' action and terminate.
                    if len(errs) > 0:
                        self.action = ('confirm', errs)
                    #Otherwise, start the ``handle`` loop
                    else:
                        self.handle()
                else:
                    self._response.tifOn(0x20, 0x40)
            else:
                self._response.tifOn(0x40, 0x80)

    def handle(self, args):
        """The core request handler. After each call, it will set the ``action``
        property. The user is expected to keep calling ``handle`` (with appropriate
        ``args``) until ``action`` is ``None``, at which point the response object
        can be finalized and returned.

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
        it may require additional information. That is gathered by setting the ``action``
        property. The user should keep running ``handle`` until ``action`` is None, at 
        which point the ``response`` can be finalized and returned.

        The ``action property``, if set, will be a tuple with at least one element.
        The first element will be a keyword, described further below. Depending on that
        keyword, additional elements may be provided. You are expected to call ``handle``
        again with any requested information passed in a single dictionary.

        confirm
        ^^^^^^^
            Means there is an issue with the nut. The user must confirm whether they wish
            to proceed.

            Contains the following additional element:
                - Array of strings representing possible issues:
                    - ip: the ip addresses didn't match
                    - time: the nut is older than the specified ttl
                    - counter: the counter did not pass requested sanity checks

            The subsequent call to ``handle`` expects the following dictionary:
                'confirm' : boolean
                    If True, the handler will process the request.
                    If False, the handler will set the appropriate error codes terminate.
        """
        #Entry point is to start processing commands.
        #Happens if ``action`` is None or if response to ``confirm`` is True.
        if ( (self.action is None) or ( (self.action[0] == 'confirm') and ('confirm' in args) and args['confirm'] == True ) ):
            cmd = self.params['client'].cmd
            #Is the ``cmd`` supported?
            if (cmd not in self.supported_cmds):
                self._response.tifOn(0x10, 0x40)
                self.action = None
            else:
                if cmd == 'query':
                    pass
                else:
                    raise RuntimeError("The supported command '{}' was unhandled! This should never happen! Please file a bug report!".format(cmd))
        #If ``action`` is confirm and it was not caught above, then it's a failed confirmation.
        elif self.action[0] == 'confirm':
            self._response.tifOn(0x20, 0x40)
            self.action = None
        #The fallback should never happen. Throw an error.
        else:
            raise RuntimeError("The combination of action ({}) and response ({}) was not caught. This should never happen! Please file a bug report!".format(self.action, args))


    def response(self):
        """Finalizes and returns the internal Response object.

        Parameters
        ----------
        """
        pass

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



