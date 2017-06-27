import nacl.hash

class Response:
    """Class encompassing a response to a SQRL request"""

    bits = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x100]

    def __init__(self, ver='1'):
        """Constructor

        Parameters
        ----------
        ver : string
            The protocol version to use for this response. Defaults to '1'.
        """
        self.thisver = ver
        self.suppver = '1'
        self._tif = 0

    @property
    def tif(self):
        """Converts the _tif property into the printable format required by the spec."""
        return hex(self._tif)[2:]

    def finalize(self, nut, qry, **kwargs):
        pass

    def hmac(self, key):
        pass

    def toString(self):
        pass

    def tifOn(self, *args):
        """Turns on given status bits, if not already on.

        Parameters
        ----------
        args : integer(s)
            One or more bits, as defined in Response.bits
        """
        for bit in args:
            if bit in self.bits:
                if self._tif & bit == 0:
                    self._tif += bit
        return self
        
    def tifOff(self, *args):
        """Turns off a given status bit, if not already off.

        Parameters
        ----------
        args : integer(s)
            One or more bits, as defined in Response.bits
        """
        for bit in args:
            if bit in self.bits:
                if self._tif & bit != 0:
                    self._tif -= bit
        return self

