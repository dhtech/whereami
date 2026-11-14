# SPDX-License-Identifier: GPL-3.0-or-later
# The plan holds every site; whereami answers for one.

import sqlite3

import pytest

from whereami.plan import Plan, Switch

NETWORKS = [
    # node_id, name, vlan
    (1, 'EVENT@TECH-SRV', 910), (2, 'EVENT@D-MGMT', 650), (3, 'EVENT@D23', 123),
    (4, 'EVENT@D24', 124), (5, 'COLO@SERVERS', 300), (6, 'COLO@LAB-MGMT', 651),
    (7, 'COLO@D23', 123),
]
HOSTS = [
    # node_id, name, ipv4, network_id, layer
    (10, 'whereami.event.test', '10.1.0.30', 1, None),
    (11, 'd23-a.event.dreamhack.local', '10.9.0.23', 2, 'access'),
    (12, 'd24-a.event.dreamhack.local', '10.9.0.24', 2, 'access'),
    (13, 'dist-d.event.dreamhack.local', '10.9.0.2', 2, 'dist'),
    (14, 'core-1.event.dreamhack.local', '10.9.0.1', 2, 'core'),
    (20, 'web.colo.test', '10.2.0.5', 5, None),
    (21, 'd23-a.lab.dreamhack.local', '10.8.0.23', 6, 'access'),
]
ACTIVE = [(3, 'd23-a.event.dreamhack.local'), (4, 'd24-a.event.dreamhack.local'),
          (7, 'd23-a.lab.dreamhack.local')]


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / 'ipplan.db')
    conn = sqlite3.connect(path)
    conn.executescript('''
        CREATE TABLE network(node_id, name, vlan);
        CREATE TABLE host(node_id, name, ipv4_addr_txt, network_id);
        CREATE TABLE option(node_id, name, value);
        CREATE TABLE active_switch(node_id, switch_name);''')
    conn.executemany('INSERT INTO network VALUES (?, ?, ?)', NETWORKS)
    for node_id, name, ipv4, network_id, layer in HOSTS:
        conn.execute('INSERT INTO host VALUES (?, ?, ?, ?)',
                     (node_id, name, ipv4, network_id))
        if layer:
            conn.execute("INSERT INTO option VALUES (?, 'layer', ?)",
                         (node_id, layer))
    conn.executemany('INSERT INTO active_switch VALUES (?, ?)', ACTIVE)
    conn.commit()
    conn.close()
    return path


def test_the_site_is_the_servers_own_or_the_one_named(db):
    assert Plan(db, hostname='whereami.event.test').site == 'EVENT'
    assert Plan(db, hostname='web.colo.test').site == 'COLO'
    assert Plan(db, site='event', hostname='nobody').site == 'EVENT'
    with pytest.raises(LookupError, match='does not know its site'):
        Plan(db, hostname='laptop.test')


def test_the_switches_are_the_sites_access_and_dist(db):
    plan = Plan(db, site='EVENT')
    assert [(s.name.split('.')[0], s.layer) for s in plan.switches()] == [
        ('d23-a', 'access'), ('d24-a', 'access'), ('dist-d', 'dist')]
    # the other site has a d23-a of its own
    assert [s.name for s in Plan(db, site='COLO').switches()] == [
        'd23-a.lab.dreamhack.local']


def test_a_switch_by_the_name_a_relay_gives(db):
    plan = Plan(db, site='EVENT')
    want = Switch('d23-a.event.dreamhack.local', 'access', '10.9.0.23')
    assert plan.switch('D23-A') == want
    assert plan.switch('d23-a.event.dreamhack.local') == want
    assert plan.switch('dist-d').layer == 'dist'
    # not a prefix of another name, not another site's, not a router
    assert plan.switch('d2') is None
    assert plan.switch('d23-a.lab.dreamhack.local') is None
    assert plan.switch('core-1') is None


def test_the_access_switches_of_a_vlan_are_the_sites(db):
    assert [s.name for s in
            Plan(db, site='EVENT').access_switches_on_vlan(123)] == [
        'd23-a.event.dreamhack.local']
    assert [s.name for s in
            Plan(db, site='COLO').access_switches_on_vlan(123)] == [
        'd23-a.lab.dreamhack.local']
    assert Plan(db, site='EVENT').access_switches_on_vlan(999) == []
