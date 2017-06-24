# the inclusion of the tests module is not meant to offer best practices for
# testing in general, but rather to support the `find_packages` example in
# setup.py that excludes installing the "tests" package

import sqrlserver
import numpy.random

nuts = {}
key = numpy.random.bytes(16)
nonce = numpy.random.bytes(16)
counter = 123

def test_nutgen():
	#unsecured
	nutqr, nutlink = sqrlserver.nut_generate(key, nonce, '0.0.0.0', counter)
	assert nutqr != nutlink
	nuts['unsecured-qr'] = nutqr
	nuts['unsecured-link'] = nutlink

	#real ipv4
	nutqr, nutlink = sqrlserver.nut_generate(key, nonce, '155.6.0.126', counter)
	assert nutqr != nutlink
	nuts['ipv4-qr'] = nutqr
	nuts['ipv4-link'] = nutlink

	#real ipv6
	nutqr, nutlink = sqrlserver.nut_generate(key, nonce, '2001:db8:a0b:12f0::1', counter)
	assert nutqr != nutlink
	nuts['ipv6-qr'] = nutqr
	nuts['ipv6-link'] = nutlink


