import ipaddress
import hashlib
import time
import struct
import numpy.random
from base64 import b64encode, b64decode
from bitstring import BitArray

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def nut_generate(key, nonce, ipaddr, counter):
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

	t = time.time()
	batime = BitArray(struct.pack('f', t))

	bacounter = BitArray(struct.pack('L', counter))

	barand = BitArray(numpy.random.bytes(4))

	#compose the 128 array
	banut = baip + batime + bacounter + barand
	if len(banut) != 128:
		raise Exception("The nut wasn't 128 bits long. This should never happen")
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

def nut_validate(response, key, nonce, ipaddr, flag, maxcounter, mincounter, ttl):
	pass




#def main():
#    """Entry point for the application script"""
#    print("Call your main application code here")
