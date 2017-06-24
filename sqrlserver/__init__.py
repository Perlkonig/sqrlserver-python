import ipaddress
import hashlib
import time
import struct
import numpy.random
from base64 import b64encode, b64decode
from bitstring import BitArray

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def nut_generate(key, nonce, ipaddr, counter, timestamp=None):
	"""Generates a unique nut

	Parameters
	----------
	key : byte string
		The AES key. Must be exactly 16 bytes long.
	nonce : byte string
		The AES initialization vector. Must be exactly 16 bytes long.
	ipaddr : string
		The string representation of a valid IPv4 or IPv6 address.
	counter : long
		An incremental counter. Used for sanity checking.
	timestamp : double
		Unix timestamp. If None, current time is used.

	Returns
	-------
	(string, string)
		Tuple of base64-encoded nuts, the first with flag set to 0
		and the second with flag set to 1
	"""

	# Nut consists of the following:
	#   32 bits: connection ip address if secured, 0.0.0.0 if non-secured
	#   32 bits: UNIX timestamp
	#   32 bits: counter
	#   31 bits: pseudo-random noise
	#    1 bit : flag to indicate source (0 = qr code; 1 = link)

	ip = ipaddress.ip_address(ipaddr)
	baip = BitArray(ip.packed)
	#Shorten to 32 bits if IPv6
	if (len(baip) == 128):
		m = hashlib.sha256()
		m.update(key)
		m.update(baip.bytes)
		baip = BitArray(m.digest())[-32:]

	if timestamp is None:
		timestamp = time.time()
	batime = BitArray(struct.pack('L', int(timestamp)))

	bacounter = BitArray(struct.pack('L', counter))

	barand = BitArray(numpy.random.bytes(4))

	#compose the 128 array
	banut = baip + batime + bacounter + barand
	assert len(banut) == 128
	banut_qr = BitArray(banut)
	banut_qr[-1] = 0
	banut_link = BitArray(banut)
	banut_link[-1] = 1

	#encrypt
	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=backend)
	encryptor = cipher.encryptor()
	ctqr = encryptor.update(banut_qr.bytes) + encryptor.finalize()
	encryptor = cipher.encryptor()
	ctlink = encryptor.update(banut_link.bytes) + encryptor.finalize()

	#process and return
	return (b64encode(ctqr)[:-2].decode('utf-8'), b64encode(ctlink)[:-2].decode('utf-8'))

def nut_validate(response, key, nonce, ipaddr, ttl, maxcounter, mincounter=0):
	"""Decodes and validates the returned nut

	Parameters
	----------
	response : string
		Base64-encoded nut
	key : byte string
		The AES key. Must be exactly 16 bytes long.
	nonce : byte string
		The AES initialization vector. Must be exactly 16 bytes long.
	ipaddr : string
		The string representation of a valid IPv4 or IPv6 address.
	ttl : long
		Number of seconds old the nut is allowed to be
	maxcounter : long
		Current counter.
	mincounter : long
		Smallest counter value you're willing to accept.

	Returns
	-------
	dictionary of booleans
		ipmatch : True if ip addresses match
		fresh   : True if ttl has not elapsed
		counter : True if counter value is within limits
		qr      : True if from a QR code
		link    : True if from a clicked link
	"""

	#decrypt the nut
	ct = b64decode((response+'==').encode('utf-8'))
	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=backend)
	decryptor = cipher.decryptor()
	out = decryptor.update(ct) + decryptor.finalize()
	banut = BitArray(out)
	assert len(banut) == 128

	ret = {}

	#verify ipaddress
	ip = ipaddress.ip_address(ipaddr)
	baip = BitArray(ip.packed)
	#Shorten to 32 bits if IPv6
	if (len(baip) == 128):
		m = hashlib.sha256()
		m.update(key)
		m.update(baip.bytes)
		baip = BitArray(m.digest())[-32:]
	if baip == banut[:32]:
		ret['ipmatch'] = True
	else:
		ret['ipmatch'] = False

	#verify timestamp
	now = int(time.time())
	nuttime = struct.unpack('L', banut[32:64].bytes)[0]
	if ( (nuttime <= now) and ((now - nuttime) < ttl) ):
		ret['fresh'] = True
	else:
		ret['fresh'] = False

	#verify counter
	counter = struct.unpack('L', banut[64:96].bytes)[0]
	if ( (counter >= mincounter) and (counter <= maxcounter) ):
		ret['counter'] = True
	else:
		ret['counter'] = False

	if (banut[-1] == 0):
		ret['qr'] = True
		ret['link'] = False
	else:
		ret['qr'] = False
		ret['link'] = True

	return ret