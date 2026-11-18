# SPDX-License-Identifier: GPL-3.0-or-later
# What is asked of a switch, and how - with a switch made of a dict.

import pytest

from whereami import snmp
from whereami.lookup import Port
from whereami.plan import Switch

DIST = Switch('d23-a.event.dreamhack.local', 'dist', '10.0.0.1')
ACCESS = Switch('d23-b.event.dreamhack.local', 'access', '10.0.0.2')
MAC = '00:11:22:aa:bb:cc'
MAC_OID = '0.17.34.170.187.204'
CREDS = snmp.Credentials(
    snmp.DistCredentials('whereami-user', 'auth-word', 'priv-word'),
    'the-community')


class FakeSwitch:
    """Answers from a table of {oid: value}; remembers what was asked."""

    def __init__(self, table):
        self.table = dict(table)
        self.asked = []
        self.written = []
        self.take_writes = True

    def get(self, host, how, oid):
        self.asked.append((host, how, oid))
        return self.table.get(oid)

    def set(self, host, how, oid, text):
        self.written.append((host, how, oid, text))
        if self.take_writes:
            self.table[oid] = text.encode()
        return self.take_writes


def table(trunk=b'2'):
    return {
        snmp.FDB_PORT + '.' + MAC_OID: b'12',
        snmp.BASE_PORT_IFINDEX + '.12': b'10112',
        snmp.TRUNK_STATUS + '.10112': trunk,
        snmp.IF_DESCR + '.10112': b'GigabitEthernet1/0/12',
        snmp.IF_ALIAS + '.10112': b'D23 row 4',
    }


def test_dist_is_asked_with_v3_in_the_vlans_context():
    fake = FakeSwitch(table())
    port = snmp.Switches(CREDS, fake).find_port(DIST, 491, MAC)
    assert port == Port('GigabitEthernet1/0/12', 'D23 row 4', 10112, False)
    host, how, oid = fake.asked[0]
    assert host == DIST.name and oid.endswith(MAC_OID)
    assert how == {'version': 3, 'security_username': 'whereami-user',
                   'security_level': 'auth_with_privacy',
                   'auth_protocol': 'SHA', 'auth_password': 'auth-word',
                   'privacy_protocol': 'AES', 'privacy_password': 'priv-word',
                   'context': 'vlan-491'}
    assert all(h['context'] == 'vlan-491' for _, h, _ in fake.asked)


def test_access_is_asked_with_v2_and_the_vlan_after_the_community():
    fake = FakeSwitch(table())
    port = snmp.Switches(CREDS, fake).find_port(ACCESS, 140, MAC)
    assert port.description == 'GigabitEthernet1/0/12'
    assert {tuple(sorted(h.items())) for _, h, _ in fake.asked} == {
        (('community', 'the-community@140'), ('version', 2))}


def test_a_trunk_is_marked():
    fake = FakeSwitch(table(trunk=b'1'))
    assert snmp.Switches(CREDS, fake).find_port(DIST, 491, MAC).trunk is True


def test_a_mac_the_switch_does_not_see_is_none():
    for nothing in (None, b'', b'NOSUCHINSTANCE', b'No Such Instance'):
        t = table()
        t[snmp.FDB_PORT + '.' + MAC_OID] = nothing
        fake = FakeSwitch(t)
        assert snmp.Switches(CREDS, fake).find_port(DIST, 491, MAC) is None
        assert len(fake.asked) == 1     # and nothing more is asked
    # a bridge port without an ifIndex is no port either
    t = table()
    del t[snmp.BASE_PORT_IFINDEX + '.12']
    assert snmp.Switches(CREDS, FakeSwitch(t)).find_port(DIST, 491, MAC) is None


def test_a_port_without_a_name_still_comes_back():
    t = table()
    del t[snmp.IF_DESCR + '.10112'], t[snmp.IF_ALIAS + '.10112']
    port = snmp.Switches(CREDS, FakeSwitch(t)).find_port(DIST, 491, MAC)
    assert port == Port('ifIndex 10112', '', 10112, False)


def test_nothing_odd_goes_into_a_question():
    switches = snmp.Switches(CREDS, FakeSwitch({}))
    for mac in ('', 'zz:11:22:aa:bb:cc', '00:11:22:aa:bb', '1.3.6.1'):
        with pytest.raises(snmp.Refused):
            switches.find_port(DIST, 491, mac)
    for vlan in (0, 4095, -1, '491', 'users; x', 4.0):
        with pytest.raises(snmp.Refused):
            switches.find_port(DIST, vlan, MAC)
    assert switches.transport.asked == []


def test_missing_credentials_are_said_not_guessed():
    none = snmp.Credentials(None, None)
    with pytest.raises(LookupError):
        snmp.Switches(none, FakeSwitch({})).find_port(DIST, 491, MAC)
    with pytest.raises(LookupError):
        snmp.Switches(none, FakeSwitch({})).find_port(ACCESS, 491, MAC)


def test_credentials_do_not_print_their_secrets():
    text = repr(CREDS) + str(CREDS) + repr(CREDS.dist)
    for secret in ('auth-word', 'priv-word', 'the-community'):
        assert secret not in text


def test_a_description_is_written_to_the_one_port_and_read_back():
    fake = FakeSwitch(table())
    said = snmp.Switches(CREDS, fake).set_description(DIST, 10112,
                                                      '  D23   row 5 ')
    assert said == 'D23 row 5'
    (host, how, oid, text), = fake.written
    assert (host, oid, text) == (DIST.name, snmp.IF_ALIAS + '.10112',
                                 'D23 row 5')
    # no VLAN's table: the port's description is the switch's own
    assert how['version'] == 3 and how['context'] == ''


def test_a_description_is_refused():
    fake = FakeSwitch(table())
    switches = snmp.Switches(CREDS, fake)
    with pytest.raises(snmp.Refused):       # not on an access switch
        switches.set_description(ACCESS, 10112, 'x')
    for text in ('x' * 61, 'line\x00', 'café', 'a;b', 'a"b', 'a\\b', '$x'):
        with pytest.raises(snmp.Refused):
            switches.set_description(DIST, 10112, text)
    for ifindex in (0, -1, '10112', None, True, 1.5):
        with pytest.raises(snmp.Refused):
            switches.set_description(DIST, ifindex, 'x')
    assert fake.written == []
    # a new line in the text is only white space between words
    assert switches.set_description(DIST, 10112, 'a\nb') == 'a b'


def test_a_switch_that_refuses_the_write_is_an_error():
    fake = FakeSwitch(table())
    fake.take_writes = False
    with pytest.raises(LookupError):
        snmp.Switches(CREDS, fake).set_description(DIST, 10112, 'x')


# --- the transport, with a stand-in for the library -----------------------

class Variable:
    def __init__(self, value, snmp_type='OCTETSTR'):
        self.value, self.snmp_type = value, snmp_type


class Library:
    """Stands in for ezsnmp.Session."""
    made = []
    answer = Variable('12', 'INTEGER')
    takes = True
    away = False

    def __init__(self, **how):
        self.how = how
        self.sets = []
        Library.made.append(self)

    def get(self, oid):
        if Library.away:
            raise TimeoutError('priv-word is in this text')
        return Library.answer

    def set(self, oid, value, snmp_type):
        self.sets.append((oid, value, snmp_type))
        return Library.takes


class Log:
    def __init__(self):
        self.lines = []

    def warning(self, text, *args):
        self.lines.append(text % args)


def test_the_transport_asks_the_library(monkeypatch):
    monkeypatch.setattr(snmp, '_session_class', lambda: Library)
    Library.made.clear()
    log = Log()
    transport = snmp.EzSnmp(timeout=3, retries=2, log=log)
    how = {'version': 2, 'community': 'c@140'}
    assert transport.get('sw', how, '.1.3') == '12'
    assert Library.made[-1].how == {'hostname': 'sw', 'timeout': 3,
                                    'retries': 2, 'use_numeric': True,
                                    'version': 2, 'community': 'c@140'}
    monkeypatch.setattr(Library, 'answer', Variable('NOSUCHINSTANCE',
                                                    'NOSUCHINSTANCE'))
    assert transport.get('sw', how, '.1.3') is None
    assert transport.set('sw', how, '.1.3.5', 'text') is True
    assert Library.made[-1].sets == [('.1.3.5', 'text', 'OCTETSTR')]
    monkeypatch.setattr(Library, 'takes', False)
    assert transport.set('sw', how, '.1.3.5', 'text') is False
    # a switch that is away is NOT "nothing": the transport says that no
    # answer came, and the log does not get what the library put in its
    # error
    monkeypatch.setattr(Library, 'away', True)
    assert log.lines == []
    with pytest.raises(snmp.NoAnswer) as caught:
        transport.get('sw', how, '.1.3')
    assert caught.value.why == 'silent'
    assert log.lines == ['snmp get on sw: no answer to go on (silent, '
                         'TimeoutError)']
    assert 'priv-word' not in str(caught.value)


def test_what_the_librarys_errors_mean():
    # the classes and the words Debian 13's python3-ezsnmp 1.1.0 gave
    # against a real snmpd, case by case
    def raised(name, text, base=Exception):
        return type(name, (base,), {})(text)
    timeout = 'timed out while connecting to remote host'
    assert snmp.why(raised('EzSNMPTimeoutError', timeout)) == 'silent'
    assert snmp.why(raised('EzSNMPError', 'Unknown user name')) == 'refused'
    assert snmp.why(raised('EzSNMPError', 'Authentication failure (incorrect '
                           'password, community or key)')) == 'refused'
    assert snmp.why(raised('EzSNMPConnectionError',
                           "couldn't create SNMP handle")) == 'unreachable'
    assert snmp.why(raised('EzSNMPError', 'something new')) == 'failed'
    assert snmp.why(ValueError('x')) == 'failed'


class Quiet:
    """A transport whose switch gives no answer to the questions whose
    OID starts with one of SILENT_TO."""

    def __init__(self, answers, silent_to, why='silent'):
        self.answers, self.silent_to, self.why = answers, silent_to, why

    def get(self, host, how, oid):
        if any(oid.startswith(start) for start in self.silent_to):
            raise snmp.NoAnswer(self.why)
        return self.answers.get(oid)


def test_a_switch_that_gives_no_answer_is_not_one_that_does_not_see_the_mac():
    from whereami.lookup import Unanswered
    for kind in ('silent', 'refused', 'unreachable', 'failed'):
        quiet = Quiet(table(), (snmp.FDB_PORT,), kind)
        with pytest.raises(Unanswered) as caught:
            snmp.Switches(CREDS, quiet).find_port(DIST, 491, MAC)
        assert caught.value.switch == DIST.name and caught.value.why == kind
    # it answered where the MAC is; a later question it does not answer
    # (the port's description) does not undo that
    quiet = Quiet(table(), (snmp.IF_ALIAS, snmp.TRUNK_STATUS))
    port = snmp.Switches(CREDS, quiet).find_port(DIST, 491, MAC)
    assert port == Port('GigabitEthernet1/0/12', '', 10112, False)


# --- the same on the netsnmp binding ---------------------------------------

class Binding:
    """Stands in for the netsnmp module."""

    def __init__(self):
        self.asked = []
        self.answer = b'12'
        self.takes = 1
        self.away = False

    class Varbind:
        def __init__(self, tag=None, iid=None, val=None, type=None):
            self.tag, self.iid, self.val, self.type = tag, iid, val, type

    def snmpget(self, var, **how):
        self.asked.append(('get', var.tag, how))
        if self.away:
            raise OSError('priv-word is in this text')
        return (self.answer,)

    def snmpset(self, var, **how):
        self.asked.append(('set', (var.tag, var.iid, var.val, var.type), how))
        return self.takes


def test_the_netsnmp_transport_speaks_the_bindings_words():
    lib, log = Binding(), Log()
    transport = snmp.NetSnmp(timeout=3, retries=2, log=log, library=lib)
    switches = snmp.Switches(CREDS, transport)
    how = switches._how(DIST, 491)
    assert transport.get('sw', how, '.1.3') == b'12'
    assert lib.asked[-1] == ('get', '.1.3', {
        'Version': 3, 'SecName': 'whereami-user', 'SecLevel': 'authPriv',
        'AuthProto': 'SHA', 'AuthPass': 'auth-word', 'PrivProto': 'AES',
        'PrivPass': 'priv-word', 'Context': 'vlan-491', 'DestHost': 'sw',
        'Timeout': 3_000_000, 'Retries': 2})
    transport.get('sw', switches._how(ACCESS, 140), '.1.3')
    assert lib.asked[-1][2] == {'Version': 2, 'Community': 'the-community@140',
                                'DestHost': 'sw', 'Timeout': 3_000_000,
                                'Retries': 2}
    assert transport.set('sw', how, '.1.3.5.10112', 'text') is True
    assert lib.asked[-1][1] == ('.1.3.5', '10112', 'text', 'OCTETSTR')
    lib.takes = 0
    assert transport.set('sw', how, '.1.3.5.10112', 'text') is False
    # this binding cannot say WHY nothing came: it stays "nothing"
    lib.away = True
    assert transport.get('sw', how, '.1.3') is None
    assert log.lines == ['snmp get on sw: OSError']


def test_a_whole_lookup_through_the_netsnmp_transport():
    # bytes from the binding become the port, as with the other library
    lib = Binding()
    answers = {k: v for k, v in table().items()}
    lib.snmpget = lambda var, **how: (answers.get(var.tag),)
    port = snmp.Switches(CREDS, snmp.NetSnmp(library=lib)).find_port(
        DIST, 491, MAC)
    assert port == Port('GigabitEthernet1/0/12', 'D23 row 4', 10112, False)
