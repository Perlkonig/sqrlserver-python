import ipaddress
import hashlib
import time
import struct
import nacl.secret
import urllib.parse
from base64 import urlsafe_b64encode, urlsafe_b64decode
from bitstring import BitArray

from .utils import pad, depad

class Nut:
    """A class encompassing SQRL nuts

    Expected workflow is as follows:
        - Construct nut with key and nonce
        - If generating:
            - generate
            - toString
        - If validating/queriying:
            - load
            - validate
            - inspect
    """

    def __init__(self, key):
        """Constructor

        Parameters
        ----------
        key : bytes
            32-byte key
        """
        self.nuts = {'raw': None, 'qr': None, 'link': None}
        self.key = key
        self.ipmatch = False
        self.fresh = False
        self.countersane = False
        self.isqr = False
        self.islink = False

    def generate(self, ipaddr, counter, timestamp=None):
        """Generates a unique nut using the technique described in the spec (LINK)

        Parameters
        ----------
        ipaddr : string
            The string representation of a valid IPv4 or IPv6 address.
        counter : long
            An incremental counter. Used for sanity checking.
        timestamp : double
            Unix timestamp. If None, current time is used.

        Stores parameters in self, generates the raw bitstring, then stores
        encrypted versions of the "qr" and "link" versions of the nut.
        """

        self.ip = ipaddress.ip_address(ipaddr)
        baip = BitArray(self.ip.packed)
        #Shorten to 32 bits if IPv6
        if (len(baip) == 128):
            m = hashlib.sha256()
            m.update(self.key)
            m.update(baip.bytes)
            baip = BitArray(m.digest())[-32:]

        self.timestamp = timestamp
        if self.timestamp is None:
            self.timestamp = time.time()
        batime = BitArray(struct.pack('I', int(self.timestamp)))

        self.counter = counter
        bacounter = BitArray(struct.pack('I', counter))

        barand = BitArray(nacl.utils.random(4))

        #compose the 128 array
        self.nuts['raw'] = baip + batime + bacounter + barand
        assert len(self.nuts['raw']) == 128
        self.nuts['qr'] = BitArray(self.nuts['raw'])
        self.nuts['qr'][-1] = 0
        self.nuts['link'] = BitArray(self.nuts['raw'])
        self.nuts['link'][-1] = 1

        #encrypt
        box = nacl.secret.SecretBox(self.key)
        self.nuts['qr'] = box.encrypt(self.nuts['qr'].bytes)
        self.nuts['link'] = box.encrypt(self.nuts['link'].bytes)

        return self

    def load(self, nut):
        """Decrypts the given nut and extracts its parts.

        Parameters
        ----------
        nut : string
            A previously generated nut string
        """

        #decrypt the nut
        box = nacl.secret.SecretBox(self.key)
        msg = urlsafe_b64decode(pad(nut).encode('utf-8'))
        out = box.decrypt(msg)
        self.nuts['raw'] = BitArray(out)
        assert len(self.nuts['raw']) == 128

        #extract ipaddress (not possible, one way only)
        self.ip = None

        #verify timestamp
        self.timestamp = struct.unpack('I', self.nuts['raw'][32:64].bytes)[0]

        #verify counter
        self.counter = struct.unpack('I', self.nuts['raw'][64:96].bytes)[0]

        #set flag
        if self.nuts['raw'][-1] == 0:
            self.isqr = True
            self.islink = False
        else:
            self.isqr = False
            self.islink = True

        return self

    def validate(self, ipaddr, ttl, maxcounter=None, mincounter=0):
        """Validates the currently loaded nut. 

        The nut must be generated or loaded first. It is the user's responsiblity
        to keep a list of valid nuts and reject repeats, to avoid replay attacks.
        This routine only validates the data encoded into the nut.

        Populates the following properties:
            - ipmatch
            - fresh
            - countersane

        Parameters
        ----------
        ipaddr : string
            The string representation of a valid IPv4 or IPv6 address.
        ttl : long
            Number of seconds old the nut is allowed to be
        maxcounter : long
            Current counter. If None, then no upper-bound checking will occur.
        mincounter : long
            Smallest counter value you're willing to accept.
        """

        #verify ipaddress
        ip = ipaddress.ip_address(ipaddr)
        baip = BitArray(ip.packed)
        #Shorten to 32 bits if IPv6
        if (len(baip) == 128):
            m = hashlib.sha256()
            m.update(self.key)
            m.update(baip.bytes)
            baip = BitArray(m.digest())[-32:]
        if baip == self.nuts['raw'][:32]:
            self.ipmatch = True
        else:
            self.ipmatch = False

        #verify timestamp
        now = int(time.time())
        nuttime = self.timestamp
        if ( (nuttime <= now) and ((now - nuttime) < ttl) ):
            self.fresh = True
        else:
            self.fresh = False

        #verify counter
        if ( ( (mincounter is None) or (self.counter >= mincounter) ) and ( (maxcounter is None) or (self.counter <= maxcounter) ) ):
            self.countersane = True
        else:
            self.countersane = False

        return self

    def toString(self, flag):
        """Converts the given nut to a base64url-encoded string"""
        if flag not in self.nuts:
            return None
        return depad(urlsafe_b64encode(self.nuts[flag]).decode('utf-8'))