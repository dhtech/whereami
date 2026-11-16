# SPDX-License-Identifier: GPL-3.0-or-later
# From an address to a switch and a port, with stand-ins for the lease
# database, the plan and the switches.

from whereami.lookup import Port, lookup
from whereami.plan import Switch

MAC = '00:11:22:aa:bb:cc'
D23 = Switch('d23-a.event.dreamhack.local', 'access', '10.9.0.23')
D24 = Switch('d24-a.event.dreamhack.local', 'access', '10.9.0.24')
DIST = Switch('dist-d.event.dreamhack.local', 'dist', '10.9.0.2')
CISCO_PORT = bytes.fromhex('0004007b0105')      # vlan 123, module 1, port 5
RELAY_MAC = bytes.fromhex('0006aabbccddeeff')


def named(name):
    return bytes([1, len(name)]) + name


class Leases:
    def __init__(self, lease):
        self.lease = lease

    def active(self, ip):
        return self.lease


class Plan:
    def __init__(self, switches=(D23, D24, DIST), on_vlan=(D23, D24)):
        self.known = {s.name.split('.')[0]: s for s in switches}
        self.on_vlan = list(on_vlan)

    def switch(self, name):
        return self.known.get(name.split('.')[0])

    def access_switches_on_vlan(self, vlan):
        return self.on_vlan if vlan == 123 else []


class Snmp:
    def __init__(self, ports):
        self.ports = ports      # {switch name: Port}
        self.asked = []

    def find_port(self, switch, vlan, mac):
        self.asked.append((switch.name.split('.')[0], vlan, mac))
        return self.ports.get(switch.name.split('.')[0])


def run(lease, plan=None, snmp=None):
    return list(lookup('10.50.23.7', Leases(lease), plan or Plan(),
                       snmp or Snmp({})))


def lease(remote, circuit=CISCO_PORT):
    return {'mac': MAC, 'remote_id': remote, 'circuit_id': circuit}


def test_no_lease_no_answer():
    steps = run(None)
    assert [s['type'] for s in steps] == ['error']
    assert 'no active DHCP lease' in steps[0]['message']


def test_a_relay_that_names_itself_is_asked_for_the_port():
    snmp = Snmp({'d23-a': Port('GigabitEthernet1/0/5', 'table 23', 10105)})
    steps = run(lease(named(b'D23-A')), snmp=snmp)
    assert [s['type'] for s in steps] == ['lease', 'relay', 'asking', 'done']
    assert steps[1]['relay'] == 'd23-a' and steps[1]['vlan'] == 123
    assert steps[3] == {
        'type': 'done', 'switch': 'd23-a.event.dreamhack.local',
        'layer': 'access', 'interface': 'GigabitEthernet1/0/5',
        'alias': 'table 23', 'ifindex': 10105, 'vlan': 123, 'module': 1,
        'port': 5, 'mac': MAC, 'ip': '10.50.23.7'}
    assert snmp.asked == [('d23-a', 123, MAC)]


def test_a_juniper_says_the_port_itself():
    snmp = Snmp({})
    steps = run(lease(b'dist-d', b'ge-0/0/12.0:D23'), snmp=snmp)
    assert steps[-1]['type'] == 'done'
    assert steps[-1]['switch'] == DIST.name
    assert steps[-1]['interface'] == 'ge-0/0/12.0'
    assert steps[-1]['ifindex'] is None
    # nobody was asked
    assert snmp.asked == []
    assert 'asking' not in [s['type'] for s in steps]


def test_a_relay_that_gave_its_mac_means_asking_the_vlans_switches():
    snmp = Snmp({'d24-a': Port('GigabitEthernet1/0/7', '', 10107)})
    steps = run(lease(RELAY_MAC), snmp=snmp)
    assert steps[-1]['type'] == 'done'
    assert steps[-1]['switch'] == D24.name
    # the first did not have it, the second did, and then it stopped
    assert [who for who, _, _ in snmp.asked] == ['d23-a', 'd24-a']


def test_for_the_log_option_82_as_it_came_and_who_is_asked():
    snmp = Snmp({'d24-a': Port('GigabitEthernet1/0/7', '', 10107)})
    steps = run(lease(RELAY_MAC), snmp=snmp)
    # the lease step carries what the relay sent, untouched, as hex
    assert steps[0] == {'type': 'lease', 'ip': '10.50.23.7', 'mac': MAC,
                        'remote_id': '0006aabbccddeeff', 'circuit_id': '0004007b0105'}
    # each switch is named before it is asked, in the order asked
    assert [s['switch'] for s in steps if s['type'] == 'asking'] == [D23.name, D24.name]
    assert [s['type'] for s in steps] == ['lease', 'relay', 'asking', 'asking', 'done']
    # a lease without option 82 says so in the log too
    steps = run(lease(None, None))
    assert steps[0]['remote_id'] is None and steps[0]['circuit_id'] is None


def test_nobody_sees_the_mac():
    steps = run(lease(RELAY_MAC))
    assert steps[-1]['type'] == 'error'
    assert 'None of the access switches on VLAN 123' in steps[-1]['message']
    steps = run(lease(named(b'd23-a')))
    assert 'does not see your MAC address' in steps[-1]['message']


def test_an_uplink_is_not_where_you_are():
    snmp = Snmp({'d23-a': Port('TenGigabitEthernet1/0/1', 'uplink', 1, True)})
    steps = run(lease(named(b'd23-a')), snmp=snmp)
    assert steps[-1]['type'] == 'error' and 'uplink' in steps[-1]['message']


def test_what_the_plan_does_not_have():
    steps = run(lease(named(b'x99-a')))
    assert 'The plan has no switch called x99-a' in steps[-1]['message']
    steps = run(lease(RELAY_MAC, bytes.fromhex('000403e70105')))   # vlan 999
    assert 'no access switch on VLAN 999' in steps[-1]['message']


def test_no_option_82():
    for remote, circuit in ((None, CISCO_PORT), (named(b'd23-a'), None),
                            (b'null', CISCO_PORT),
                            (named(b'd23-a'), b'\x00\x04\x00\x00\x00\x00')):
        steps = run(lease(remote, circuit))
        assert [s['type'] for s in steps] == ['lease', 'error'], (remote, circuit)
        assert 'no option 82' in steps[-1]['message']
