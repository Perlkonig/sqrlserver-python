import ipaddress
import hashlib
import time
import struct
import nacl.secret
import urllib.parse
from base64 import urlsafe_b64encode, urlsafe_b64decode
from bitstring import BitArray

from .utils import pad, depad

class Nut(object):
    """A class encompassing SQRL nuts.

    The server should not need to use this class directly, but of course
    it may. It is designed to work as follows:

    - Construct the object with the 32-byte key.
    - If generating a new nut, use :py:meth:`.generate` followed by 
      :py:meth:`.toString`.
    - If validating an existing nut, use :py:meth:`.load`, then :py:meth:`.validate`,
      then look at the various attributes to determine if any errors were found.

    Attributes:
        key (bytes) : 32 bytes used to encrypt the nut. 
        ipmatch (bool) : Whether the last validation found matching IPs.
        fresh (bool) : Whether the last validation found the nut to be fresh.
        countersane (bool) : Whether the last validation found the
            counter to be within limits. Default is False, even if counter
            checking was disabled.
        isqr (bool) : Set when loading a nut. States whether it's a QR nut.
        islink (bool) : Set when loading a nut. States whether it's a link nut.
    """

    def __init__(self, key):
        """Constructor

        Args:
            key (bytes) : 32-byte key used to encrypt/decrypt the nut
        """

        assert len(key) == 32

        self.nuts = {'raw': None, 'qr': None, 'link': None}
        self.key = key
        self.ipmatch = False
        self.fresh = False
        self.countersane = False
        self.isqr = False
        self.islink = False

    def generate(self, ipaddr, counter, timestamp=None):
        """Generates a unique nut using the technique described in the spec (LINK)

        Args:
            ipaddr (string) : The string representation of a valid
                IPv4 or IPv6 address.
            counter (uint) : 
                An incremental counter. Used for sanity checking.

        Keyword Args:
            timestamp (uint) : Unix timestamp (seconds only). If None,
                current time is used.

        Returns:
            Nut : The populated Nut object.
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

        Args:
            nut (string) : A previously generated nut string

        Returns
            Nut
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

        The nut must be generated or loaded first. It is the user's
        responsiblity to keep a list of valid nuts and reject repeats,
        to avoid replay attacks. This routine only validates the data
        encoded into the nut.

        Args:
            ipaddr (string) : The string representation of a valid
                IPv4 or IPv6 address.
            ttl (uint) : Number of seconds old the nut is allowed to be.

        Keyword Args:
            maxcounter (uint) : Current counter. If None, then no
                upper-bound checking will occur.
            mincounter (uint) : Smallest counter value you're willing
                to accept. If None, then no lower-bound checking will
                occur

        Returns:
            Nut : The user has to inspect the attributes ``ipmatch``, 
            ``fresh``, and ``countersane`` to determine if the nut fully 
            validated.
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
        """Converts the given nut to a base64url-encoded string

        Args:
            flag (string) : One of ``qr``, ``link``, or ``raw``.

        Warning:
            While it is possible to do this to the "raw" nut, don't! It has 
            not been encrypted.

        Returns:
            string : b64u-encoded nut
        """

        if flag not in self.nuts:
            return None
        return depad(urlsafe_b64encode(self.nuts[flag]).decode('utf-8'))