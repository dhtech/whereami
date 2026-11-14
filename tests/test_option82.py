# SPDX-License-Identifier: GPL-3.0-or-later
# What the relay said, as the bytes the lease database keeps.

from whereami import option82 as o


def test_cisco_remote_id_is_a_mac_or_a_hostname():
    assert o.remote_id(bytes.fromhex('0006001122aabbcc')) == o.RemoteId(
        'mac', '00:11:22:aa:bb:cc', False)
    name = b'D23-A'
    assert o.remote_id(bytes([1, len(name)]) + name) == o.RemoteId(
        'hostname', 'd23-a', False)


def test_cisco_circuit_id_is_vlan_module_port():
    # vlan 491, module 1, port 12
    assert o.circuit_id(bytes.fromhex('000401eb010c')) == o.CircuitId(
        491, 1, 12, None, False)


def test_juniper_writes_text():
    assert o.remote_id(b'dist-a-01') == o.RemoteId('hostname', 'dist-a-01',
                                                   True)
    assert o.remote_id(b'"Dist-A-01"') == o.RemoteId('hostname', 'dist-a-01',
                                                     True)
    assert o.remote_id(b'00:11:22:aa:bb:cc') == o.RemoteId(
        'mac', '00:11:22:aa:bb:cc', True)
    assert o.circuit_id(b'ge-0/0/12.0:D23') == o.CircuitId(
        'D23', 0, 12, 'ge-0/0/12.0', True)
    assert o.circuit_id(b'"xe-1/2/3:users"') == o.CircuitId(
        'users', 2, 3, 'xe-1/2/3', True)


def test_nothing_usable_is_none():
    for nothing in (None, b'', b'null', b'\x00\x04\x00\x00\x00\x00',
                    b'\xff\xfe\xfd', b'\x00\x06\x01\x02',   # a length that lies
                    b'\x02\x01x'):                          # an unknown type
        assert o.remote_id(nothing) is None, nothing
        assert o.circuit_id(nothing) is None, nothing
    # text that is no interface with a vlan
    for odd in (b'ge-0/0/12.0', b'hello:world', b'ge-0/0/12.0:'):
        assert o.circuit_id(odd) is None, odd
    # a hostname is not taken from something with odd characters
    assert o.remote_id(b'bad name;') is None


def test_memoryview_from_the_database_is_taken():
    assert o.remote_id(memoryview(b'dist-a-01')).value == 'dist-a-01'
    assert o.circuit_id(memoryview(bytes.fromhex('000401eb010c'))).port == 12
