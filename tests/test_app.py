# SPDX-License-Identifier: GPL-3.0-or-later
"""The pages, with stand-ins for the databases, the plan and the
switches."""
import datetime
import json

import pytest

pytest.importorskip('flask')

from whereami.app import create_app  # noqa: E402
from whereami.lookup import Port  # noqa: E402
from whereami.plan import Switch  # noqa: E402
from whereami.snmp import Refused  # noqa: E402

UTC = datetime.timezone.utc
DIST = Switch('dist-d.event.dreamhack.local', 'dist', '10.9.0.2')
D23 = Switch('d23-a.event.dreamhack.local', 'access', '10.9.0.23')
MAC = '00:11:22:aa:bb:cc'
IP = '10.50.23.7'
ME = {'X-Remote-User': 'alice', 'X-Real-IP': IP}


def named(name):
    return bytes([1, len(name)]) + name


class Leases:
    def __init__(self, lease=None):
        self.lease = lease
        self.asked = []
        self.broken = False

    def active(self, ip):
        self.asked.append(ip)
        return self.lease

    def schema_version(self):
        if self.broken:
            raise RuntimeError('away')
        return 2


class Store:
    def __init__(self):
        self.rows = []
        self.descriptions = []

    def latest(self):
        out = {}
        for row in self.rows:
            out[row['switch']] = row
        return out

    def confirm(self, switch, confirmed, comment, interface, username):
        self.rows.append({'switch': switch, 'confirmed': confirmed, 'comment': comment,
                          'interface': interface, 'username': username,
                          'at': datetime.datetime(2026, 11, 20, 12, 0, tzinfo=UTC)})

    def described(self, *row):
        self.descriptions.append(row)

    def schema_version(self):
        return 1


class Plan:
    site = 'EVENT'

    def switches(self):
        return [D23, DIST]

    def switch(self, name):
        return {s.name.split('.')[0]: s for s in (D23, DIST)}.get(name.split('.')[0])

    def access_switches_on_vlan(self, vlan):
        return [D23]


class Switches:
    credentials = None      # "the dist account is there" for the page

    def __init__(self, port=Port('GigabitEthernet1/0/5', 'old words', 10105)):
        self.port = port
        self.written = []

    def find_port(self, switch, vlan, mac):
        return self.port

    def set_description(self, switch, ifindex, text):
        if ';' in text:
            raise Refused('no')
        self.written.append((switch.name, ifindex, text))
        return text


ON_DIST = {'mac': MAC, 'remote_id': named(b'dist-d'), 'circuit_id': bytes.fromhex('0004007b0105')}
BEHIND_DIST = {'mac': MAC, 'remote_id': bytes.fromhex('0006aabbccddeeff'),
               'circuit_id': bytes.fromhex('0004007b0105')}


@pytest.fixture
def world():
    class World:
        leases, store, plan, switches = Leases(ON_DIST), Store(), Plan(), Switches()
    w = World()
    w.app = create_app(w.leases, w.store, w.plan, w.switches,
                       {'TESTING': True, 'TIMEZONE': 'Europe/Stockholm'})
    w.client = w.app.test_client()
    return w


def stream(world, headers=ME):
    body = world.client.get('/stream', headers=headers).get_data(as_text=True)
    return [json.loads(line[6:]) for line in body.split('\n\n') if line.startswith('data: ')]


# --- nobody without a name --------------------------------------------------

def test_nothing_without_a_name(world):
    for path in ('/', '/stream', '/status', '/api/switches', '/analytics/switch.status'):
        assert world.client.get(path).status_code == 401, path
        assert world.client.get(path, headers={'X-Remote-User': 'a b;c'}).status_code == 401
    for path in ('/confirm', '/describe'):
        assert world.client.post(path).status_code == 401
    assert world.leases.asked == []


def test_two_things_are_open(world):
    assert world.client.get('/healthz').get_data(as_text=True) == 'ok\n'
    got = world.client.get('/ipv6', headers={'X-Real-IP': '2001:db8::7'})
    assert got.get_json() == {'ip': '2001:db8::7', 'ipv6': True}
    assert got.headers['Access-Control-Allow-Origin'] == '*'
    assert world.client.get('/ipv6', headers={'X-Real-IP': IP}).get_json()['ipv6'] is False
    world.leases.broken = True
    assert world.client.get('/healthz').status_code == 503


# --- the lookup -------------------------------------------------------------

def test_the_lookup_is_for_the_visitors_own_address(world):
    steps = stream(world)
    assert world.leases.asked == [IP]
    assert [s['type'] for s in steps] == ['lease', 'relay', 'done']
    done = steps[-1]
    assert (done['switch'], done['interface'], done['layer']) == (
        DIST.name, 'GigabitEthernet1/0/5', 'dist')
    assert done['describable'] is True and done['said'] is None and done['ticket']
    # an address in the query is not looked at
    world.client.get('/stream?ip=10.9.9.9', headers=ME).get_data()
    assert world.leases.asked == [IP, IP]


def test_over_ipv6_there_is_no_lease_to_find(world):
    steps = stream(world, dict(ME, **{'X-Real-IP': '2001:db8::7'}))
    assert [s['type'] for s in steps] == ['error'] and 'IPv4' in steps[0]['message']
    assert world.leases.asked == []


def test_an_access_port_gets_no_description_form(world):
    world.leases.lease = BEHIND_DIST
    done = stream(world)[-1]
    assert done['type'] == 'done' and done['switch'] == D23.name
    assert done['describable'] is False


def test_a_broken_lookup_is_said_not_shown(world):
    def broken(ip):
        raise RuntimeError('password=hunter2 host=db')
    world.leases.active = broken
    steps = stream(world)
    assert [s['type'] for s in steps] == ['error']
    assert 'hunter2' not in steps[0]['message']


# --- confirming -------------------------------------------------------------

def ticket(world, headers=ME):
    return stream(world, headers)[-1]['ticket']


def test_confirming_the_switch_that_was_found(world):
    got = world.client.post('/confirm', headers=ME, data={
        'ticket': ticket(world), 'verdict': 'ok', 'comment': '  row 4,\n left  '})
    assert got.status_code == 200 and got.get_json()['switch'] == DIST.name
    row, = world.store.rows
    assert (row['switch'], row['confirmed'], row['comment'], row['interface'], row['username']) == (
        DIST.name, True, 'row 4, left', 'GigabitEthernet1/0/5', 'alice')
    assert got.get_json()['said']['confirmed'] is True
    # the next lookup says so
    assert stream(world)[-1]['said']['username'] == 'alice'


def test_a_problem_needs_words(world):
    t = ticket(world)
    assert world.client.post('/confirm', headers=ME, data={
        'ticket': t, 'verdict': 'problem'}).status_code == 400
    assert world.client.post('/confirm', headers=ME, data={
        'ticket': t, 'verdict': 'problem', 'comment': 'wrong row'}).status_code == 200
    assert world.store.rows[-1]['confirmed'] is False
    assert world.client.post('/confirm', headers=ME, data={
        'ticket': t, 'verdict': 'maybe'}).status_code == 400
    assert world.client.post('/confirm', headers=ME, data={
        'ticket': t, 'verdict': 'ok', 'comment': 'x' * 501}).status_code == 400


def test_only_the_ticket_says_which_switch(world):
    t = ticket(world)
    # no ticket, a made-up one, a changed one, somebody else's
    for bad in ('', 'made.up.ticket', t[:-2] + ('AA' if not t.endswith('AA') else 'BB')):
        got = world.client.post('/confirm', headers=ME, data={
            'ticket': bad, 'verdict': 'ok', 'switch': 'd99-a'})
        assert got.status_code == 403, bad
    other = dict(ME, **{'X-Remote-User': 'somebody-else'})
    assert world.client.post('/confirm', headers=other, data={
        'ticket': t, 'verdict': 'ok'}).status_code == 403
    assert world.store.rows == []


def test_an_old_ticket_is_refused(world, monkeypatch):
    t = ticket(world)
    import whereami.app as module
    monkeypatch.setattr(module, 'TICKET_AGE', -1)
    assert world.client.post('/confirm', headers=ME, data={
        'ticket': t, 'verdict': 'ok'}).status_code == 403


# --- the description --------------------------------------------------------

def test_the_description_goes_to_the_port_that_was_found(world):
    got = world.client.post('/describe', headers=ME, data={
        'ticket': ticket(world), 'description': 'D23 row 4', 'ifindex': '1', 'switch': 'x'})
    assert got.status_code == 200 and got.get_json()['description'] == 'D23 row 4'
    assert world.switches.written == [(DIST.name, 10105, 'D23 row 4')]
    assert world.store.descriptions == [
        (DIST.name, 'GigabitEthernet1/0/5', 10105, 'D23 row 4', 'alice')]


def test_no_description_on_an_access_port_or_with_odd_text(world):
    world.leases.lease = BEHIND_DIST
    assert world.client.post('/describe', headers=ME, data={
        'ticket': ticket(world), 'description': 'x'}).status_code == 400
    world.leases.lease = ON_DIST
    got = world.client.post('/describe', headers=ME, data={
        'ticket': ticket(world), 'description': 'a;b'})
    assert got.status_code == 400 and got.get_json()['error'] == 'no'
    assert world.switches.written == [] and world.store.descriptions == []


# --- the status -------------------------------------------------------------

def test_the_status_of_every_switch_of_the_plan(world):
    assert world.client.get('/analytics/switch.status', headers=ME).get_json() == {
        D23.name: 'UNKNOWN', DIST.name: 'UNKNOWN'}
    world.store.confirm(DIST.name, True, '', 'Gi1/0/5', 'alice')
    world.store.confirm(D23.name, False, 'wrong row', 'Gi0/1', 'bob')
    # the old shape knows OK and UNKNOWN only
    assert world.client.get('/analytics/switch.status', headers=ME).get_json() == {
        D23.name: 'UNKNOWN', DIST.name: 'OK'}
    rows = {r['switch']: r for r in
            world.client.get('/api/switches', headers=ME).get_json()['switches']}
    assert rows[D23.name]['status'] == 'PROBLEM' and rows[D23.name]['comment'] == 'wrong row'
    assert rows[DIST.name]['at'] == '2026-11-20T12:00:00Z'
    page = world.client.get('/status', headers=ME).get_data(as_text=True)
    assert 'wrong row' in page and '2026-11-20 13:00' in page     # Stockholm
    assert page.index(D23.name) < page.index(DIST.name)           # problems first


def test_the_page_and_its_headers(world):
    got = world.client.get('/', headers=ME)
    assert got.status_code == 200
    page = got.get_data(as_text=True)
    assert 'alice' in page and 'app.js' in page
    csp = got.headers['Content-Security-Policy']
    assert "script-src 'self'" in csp and "connect-src 'self';" in csp
    assert got.headers['Cache-Control'] == 'no-store'


def test_the_ipv6_check_may_ask_its_two_addresses_only():
    app = create_app(Leases(), Store(), Plan(), Switches(), {
        'TESTING': True, 'IPV6_OWN_URL': 'https://v6.whereami.example/ipv6',
        'IPV6_OUTSIDE_URL': 'https://ipv6.example.net/'})
    got = app.test_client().get('/', headers=ME)
    assert ("connect-src 'self' https://v6.whereami.example https://ipv6.example.net;"
            in got.headers['Content-Security-Policy'])
    page = got.get_data(as_text=True)
    assert 'data-own="https://v6.whereami.example/ipv6"' in page
