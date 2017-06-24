# the inclusion of the tests module is not meant to offer best practices for
# testing in general, but rather to support the `find_packages` example in
# setup.py that excludes installing the "tests" package

import sqrlserver
import numpy.random
import time

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

def test_nutval():
	#first test that all nuts are valid as they stand
	val = sqrlserver.nut_validate(nuts['unsecured-qr'], key, nonce, '0.0.0.0', 600, counter+1)
	assert val['ipmatch'] 
	assert val['fresh'] 
	assert val['counter'] 
	assert val['qr']
	assert not val['link']
	val = sqrlserver.nut_validate(nuts['unsecured-link'], key, nonce, '0.0.0.0', 600, counter+1)
	assert val['ipmatch'] 
	assert val['fresh'] 
	assert val['counter'] 
	assert val['link']
	assert not val['qr']
	val = sqrlserver.nut_validate(nuts['ipv4-qr'], key, nonce, '155.6.0.126', 600, counter+1)
	assert val['ipmatch'] 
	assert val['fresh'] 
	assert val['counter'] 
	assert val['qr']
	assert not val['link']
	val = sqrlserver.nut_validate(nuts['ipv4-link'], key, nonce, '155.6.0.126', 600, counter+1)
	assert val['ipmatch'] 
	assert val['fresh'] 
	assert val['counter'] 
	assert val['link']
	assert not val['qr']
	val = sqrlserver.nut_validate(nuts['ipv6-qr'], key, nonce, '2001:db8:a0b:12f0::1', 600, counter+1)
	assert val['ipmatch'] 
	assert val['fresh'] 
	assert val['counter'] 
	assert val['qr']
	assert not val['link']
	val = sqrlserver.nut_validate(nuts['ipv6-link'], key, nonce, '2001:db8:a0b:12f0::1', 600, counter+1)
	assert val['ipmatch'] 
	assert val['fresh'] 
	assert val['counter'] 
	assert val['link']
	assert not val['qr']

	#mismatched IP addresses
	val = sqrlserver.nut_validate(nuts['ipv4-qr'], key, nonce, '155.6.0.125', 600, counter+1)
	assert not val['ipmatch']
	val = sqrlserver.nut_validate(nuts['ipv6-link'], key, nonce, '2002:db8:a0b:12f0::1', 600, counter+1)
	assert not val['ipmatch']

	#too old
	t = time.time() - 3000
	nut = sqrlserver.nut_generate(key, nonce, '155.6.0.126', counter, t)[0]
	val = sqrlserver.nut_validate(nut, key, nonce, '155.6.0.126', 600, counter)
	assert not val['fresh']

	#in the future
	t = time.time() + 3000
	nut = sqrlserver.nut_generate(key, nonce, '155.6.0.126', counter, t)[0]
	val = sqrlserver.nut_validate(nut, key, nonce, '155.6.0.126', 600, counter)
	assert not val['fresh']

	#counter too small
	nut = sqrlserver.nut_generate(key, nonce, '155.6.0.126', 5)[0]
	val = sqrlserver.nut_validate(nut, key, nonce, '155.6.0.126', 600, counter, counter-10)
	assert not val['counter']

	#counter too big
	nut = sqrlserver.nut_generate(key, nonce, '155.6.0.126', counter + 100)[0]
	val = sqrlserver.nut_validate(nut, key, nonce, '155.6.0.126', 600, counter)
	assert not val['counter']
