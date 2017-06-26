import sqrlserver
import nacl.utils
import nacl.exceptions
import time
import pytest

nuts = {}
key = nacl.utils.random(32)
counter = 123

def test_gen_unsecured():
    nut = sqrlserver.Nut(key)
    nut = nut.generate('0.0.0.0', counter)
    nutqr = nut.toString('qr')
    nutlink = nut.toString('link')
    assert nutqr != nutlink
    nuts['unsecured-qr'] = nutqr
    nuts['unsecured-link'] = nutlink

def test_gen_ipv4():
    nut = sqrlserver.Nut(key)
    nut = nut.generate('155.6.0.126', counter)
    nutqr = nut.toString('qr')
    nutlink = nut.toString('link')
    assert nutqr != nutlink
    nuts['ipv4-qr'] = nutqr
    nuts['ipv4-link'] = nutlink

def test_gen_ipv6():
    nut = sqrlserver.Nut(key)
    nut = nut.generate('2001:db8:a0b:12f0::1', counter)
    nutqr = nut.toString('qr')
    nutlink = nut.toString('link')
    assert nutqr != nutlink
    nuts['ipv6-qr'] = nutqr
    nuts['ipv6-link'] = nutlink

def test_validate_initial():
    nut = sqrlserver.Nut(key)
    nut = nut.load(nuts['unsecured-qr']).validate('0.0.0.0', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.isqr
    assert not nut.islink

    nut = nut.load(nuts['unsecured-link']).validate('0.0.0.0', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.islink
    assert not nut.isqr

    nut = nut.load(nuts['ipv4-qr']).validate('155.6.0.126', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.isqr
    assert not nut.islink

    nut = nut.load(nuts['ipv4-link']).validate('155.6.0.126', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.islink
    assert not nut.isqr

    nut = nut.load(nuts['ipv6-qr']).validate('2001:db8:a0b:12f0::1', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.isqr
    assert not nut.islink

    nut = nut.load(nuts['ipv6-link']).validate('2001:db8:a0b:12f0::1', 600, counter)
    assert nut.ipmatch
    assert nut.fresh
    assert nut.countersane
    assert nut.islink
    assert not nut.isqr

def test_validate_ip():
    nut = sqrlserver.Nut(key)
    #mismatched IP addresses
    nut = nut.load(nuts['ipv4-link']).validate('155.6.0.125', 600, counter)
    assert not nut.ipmatch
    nut = nut.load(nuts['ipv6-link']).validate('2002:db8:a0b:12f0::1', 600, counter)
    assert not nut.ipmatch

def test_validate_age():
    nut = sqrlserver.Nut(key)
    #too old
    t = time.time() - 3000
    nut = nut.generate('155.6.0.126', counter, t).validate('155.6.0.126', 600, counter)
    assert not nut.fresh

    #in the future
    t = time.time() + 3000
    nut = nut.generate('155.6.0.126', counter, t).validate('155.6.0.126', 600, counter)
    assert not nut.fresh

def test_validate_counter():
    nut = sqrlserver.Nut(key)
    #counter too small
    nut = nut.generate('155.6.0.126', 5).validate('155.6.0.126', 600, counter, counter-10)
    assert not nut.countersane

    #counter too big
    nut = nut.generate('155.6.0.126', counter + 100).validate('155.6.0.126', 600, counter)
    assert not nut.countersane

    #counter validation can be turned off
    #   Use previously generated nut with a counter value too high
    #   but omit the maxcounter from the validation call.
    nut.validate('155.6.0.126', 600)
    assert nut.countersane

def test_validate_encryption():
    #incorrect key
    with pytest.raises(nacl.exceptions.CryptoError):
        wrongnut = sqrlserver.Nut(nacl.utils.random(32))
        wrongnut.load(nuts['ipv4-link']).validate('155.6.0.126', 600, counter)
