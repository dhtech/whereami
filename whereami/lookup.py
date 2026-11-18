# SPDX-License-Identifier: GPL-3.0-or-later
"""Which switch and port is this address plugged into?

The way the old whereami did it:

  1. the address's active lease says the client's MAC and what the
     relaying switch added (option 82): who it is (remote id) and where
     the request came in (circuit id: vlan, module, port);
  2. a relay that names ITSELF by hostname is the switch the client is
     on. A Juniper says the port in the circuit id; a Cisco is asked
     over SNMP on which port it sees the MAC;
  3. a relay that only gave its MAC is a dist switch with access
     switches behind it: the plan says which access switches serve that
     VLAN, and each is asked for the MAC until one has it.

A port that is a trunk is the way to another switch, not where the
client is - that answer is refused.

A switch that gives no answer to work with is NOT a switch that does
not see the client: "it did not answer" (away, or it does not let
whereami ask), "it turned down whereami's login" and "it could not be
reached by its name" are each said as what they are, in an 'unanswered'
step and in the final error, and the lookup goes on to the next switch
where there is one.

lookup() yields what it learns step by step (the page shows the steps
as they come) and ends with a 'done' or an 'error'. Two things are
there for the page's log, for whoever has to find out why a lookup
went wrong: the lease step carries option 82 as the relay sent it
(hex), and an 'asking' step says which switch is asked over SNMP,
before it is asked. It talks to the
lease database, the plan and the switches through three objects handed
in - nothing here opens a connection.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from . import option82


@dataclass(frozen=True)
class Port:
    """A switch port a MAC was found on."""
    description: str        # the switch's name for it (GigabitEthernet1/0/5)
    alias: str = ''         # the description somebody gave it
    ifindex: int | None = None   # None: not asked (a Juniper's circuit id)
    trunk: bool = False


# why a switch gave nothing to go on
SILENT = 'silent'            # nothing came back in time
REFUSED = 'refused'          # it answered: whereami's login is not its own
UNREACHABLE = 'unreachable'  # its name leads to no address
FAILED = 'failed'            # anything else (the server's log has it)

_WHY = {
    SILENT: '%(switch)s did not answer over SNMP: it is away, or it does not '
            'let whereami ask (its SNMP settings%(vlan)s).',
    REFUSED: '%(switch)s answered, but turned down whereami\'s SNMP login: '
             'the account or its passwords on the switch are not the ones '
             'whereami has.',
    UNREACHABLE: '%(switch)s could not be asked over SNMP: its name leads '
                 'to no address.',
    FAILED: '%(switch)s could not be asked over SNMP (the reason is in the '
            'server\'s log).',
}


class Unanswered(Exception):
    """A switch that was asked and gave nothing to go on - which is not
    the same as a switch that does not see the MAC."""

    def __init__(self, switch: str, why: str = SILENT):
        super().__init__('%s: %s' % (switch, why))
        self.switch = switch
        self.why = why if why in _WHY else FAILED

    def words(self, vlan=None) -> str:
        """What happened, for the person looking at the page."""
        on = ', or VLAN %d is not on it' % vlan if isinstance(vlan, int) else ''
        return _WHY[self.why] % {'switch': self.switch, 'vlan': on}


def error(message: str) -> dict:
    return {'type': 'error', 'message': message}


def unanswered(exc: Unanswered, vlan) -> dict:
    return {'type': 'unanswered', 'switch': exc.switch, 'why': exc.why,
            'message': exc.words(vlan)}


def _hex(value) -> str | None:
    return None if value is None else bytes(value).hex()


def lookup(ip: str, leases, plan, snmp) -> Iterator[dict]:
    """Steps towards the switch and port of IP.

    leases.active(ip)  -> {'mac', 'remote_id', 'circuit_id'} or None
    plan.switch(name)  -> a switch (name, layer) or None
    plan.access_switches_on_vlan(vlan) -> switches
    snmp.find_port(switch, vlan, mac)  -> Port, or None when the switch
                                          answers that it does not see
                                          the MAC; raises Unanswered when
                                          it gives no answer to go on
    """
    lease = leases.active(ip)
    if lease is None:
        yield error('There is no active DHCP lease for your address (%s).'
                    % ip)
        return
    mac = lease['mac']
    yield {'type': 'lease', 'ip': ip, 'mac': mac,
           'remote_id': _hex(lease.get('remote_id')),
           'circuit_id': _hex(lease.get('circuit_id'))}

    remote = option82.remote_id(lease.get('remote_id'))
    circuit = option82.circuit_id(lease.get('circuit_id'))
    if remote is None or circuit is None:
        yield error('The switch that relayed your DHCP request did not say '
                    'where you are (no option 82). Either this network is '
                    'not set up for whereami, or you should release and '
                    'renew your address.')
        return
    yield {'type': 'relay', 'relay': remote.value, 'relay_is': remote.kind,
           'vlan': circuit.vlan, 'module': circuit.module,
           'port': circuit.port}

    if remote.kind == 'hostname':
        switch = plan.switch(remote.value)
        if switch is None:
            yield error('The plan has no switch called %s.' % remote.value)
            return
        if remote.juniper:
            # a Juniper says the port itself
            port = Port(circuit.interface or '')
        else:
            yield {'type': 'asking', 'switch': switch.name}
            try:
                port = snmp.find_port(switch, circuit.vlan, mac)
            except Unanswered as exc:
                yield error(exc.words(circuit.vlan) + ' So whereami cannot '
                            'say which of its ports you are on.')
                return
        if port is None:
            yield error('%s does not see your MAC address (%s) on that '
                        'VLAN.' % (switch.name, mac))
            return
        candidates = [(switch, port)]
    else:
        if remote.juniper or not isinstance(circuit.vlan, int):
            yield error('The relay gave its MAC address and no VLAN number: '
                        'the access switch cannot be looked for.')
            return
        switches = plan.access_switches_on_vlan(circuit.vlan)
        if not switches:
            yield error('The plan has no access switch on VLAN %d.'
                        % circuit.vlan)
            return
        candidates = []
        quiet = []      # asked, and gave nothing to go on
        for switch in switches:
            yield {'type': 'asking', 'switch': switch.name}
            try:
                port = snmp.find_port(switch, circuit.vlan, mac)
            except Unanswered as exc:
                quiet.append(switch.name)
                yield unanswered(exc, circuit.vlan)
                continue
            if port is not None:
                candidates.append((switch, port))
                break
        if not candidates and len(quiet) == len(switches):
            yield error('No access switch on VLAN %d gave an answer over '
                        'SNMP (%s), so whereami cannot look for your MAC '
                        'address (%s).' % (circuit.vlan, ', '.join(quiet),
                                           mac))
            return
        if not candidates and quiet:
            yield error('None of the access switches on VLAN %d that '
                        'answered sees your MAC address (%s). You may be '
                        'on one that gave no answer over SNMP: %s.'
                        % (circuit.vlan, mac, ', '.join(quiet)))
            return
        if not candidates:
            yield error('None of the access switches on VLAN %d sees your '
                        'MAC address (%s).' % (circuit.vlan, mac))
            return

    switch, port = candidates[0]
    if port.trunk:
        yield error('%s sees you on %s, which is an uplink - you are behind '
                    'another switch. Release and renew your address if that '
                    'is wrong.' % (switch.name, port.description))
        return
    yield {'type': 'done', 'switch': switch.name, 'layer': switch.layer,
           'interface': port.description, 'alias': port.alias,
           'ifindex': port.ifindex, 'vlan': circuit.vlan,
           'module': circuit.module, 'port': circuit.port, 'mac': mac,
           'ip': ip}
