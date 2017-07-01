from .utils import depad
import nacl.hash
from base64 import urlsafe_b64encode

class Response:
    """Class encompassing a response to a SQRL request

    Keyword Args:
        ver (uint) : The version number for this response. Defaults to 1.

    Attributes:
        ver (uint) : The version of this response.
        tif (string) : The hexadecimal status bits set in this response
            in the string format required by the spec.
        params (dict) : The name-value pairs currently set.
    """

    _bits = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x100]
    _supportedvers = '1'

    def __init__(self, ver=1):
        self.ver = ver
        self._tif = 0
        self.params = {}

    def __repr__(self):
        return "<Response(TIF={}, params={})>".format(hex(self._tif), self.params)

    @staticmethod
    def load(ref):
        """Loads an existing response into a new one"""

        assert isinstance(ref, Response)
        r = Response(ref.ver)
        r._tif = ref._tif
        r.params = ref.params
        return r

    @staticmethod
    def _compose(params):
        """Compose a dictionary of name-value pairs into the format required by the spec

        ``ver`` is always first. The other parameters will be placed in 
        alphabetical order (accoring to Python's ``sorted`` function).
        """

        l = []
        for name in sorted(params.keys()):
            if name == 'ver':
                l.insert(0, "{}={}".format(name, params[name]))
            else:
                l.append("{}={}".format(name, params[name]))
        return "\r\n".join(l) + "\r\n"

    @property
    def tif(self):
        """Converts the _tif property into the printable format required by the spec."""
        return hex(self._tif)[2:]

    def hmac(self, key):
        """Computes the HMAC for the current state of the response"""

        assert len(key) >= 16
        s = self.toString()
        return depad(nacl.hash.siphash24(s.encode('utf-8'), key=key[:16], encoder=nacl.encoding.URLSafeBase64Encoder).decode('utf-8'))

    def toString(self):
        """Converts to b64u encoded string"""

        p = dict(self.params)
        p['ver'] = self._supportedvers
        p['tif'] = self.tif
        return depad(urlsafe_b64encode(Response._compose(p).encode('utf-8')).decode('utf-8'))

    def addParam(self, key, value):
        """Adds/updates the given name-value pair"""

        self.params[key] = value

    def tifOn(self, *args):
        """Turns on given status bits, if not already on."""

        for bit in args:
            if bit in self._bits:
                if self._tif & bit == 0:
                    self._tif += bit
        return self
        
    def tifOff(self, *args):
        """Turns off the given status bits, if not already off."""

        for bit in args:
            if bit in self._bits:
                if self._tif & bit != 0:
                    self._tif -= bit
        return self

