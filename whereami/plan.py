# SPDX-License-Identifier: GPL-3.0-or-later
"""What whereami asks the network plan (/etc/ipplan.db) - for ONE site.

The plan database holds every site. A site is what the plan calls it:
the part before the "@" of a network's name ("EVENT@D23" is in site
EVENT); a host is in the site of the network its plan line stands
under. whereami serves the site of the machine it runs on, found by
that machine's own name in the plan - or the one it is told
(WHEREAMI_SITE).

A switch is a host with the option layer= ("access" or "dist").
"""
from __future__ import annotations

import socket
import sqlite3
from dataclasses import dataclass

DB = '/etc/ipplan.db'
LAYERS = ('access', 'dist')


@dataclass(frozen=True)
class Switch:
    name: str
    layer: str
    ipv4: str | None


def _site(network_name: str | None) -> str | None:
    if not network_name or '@' not in network_name:
        return None
    return network_name.split('@', 1)[0]


class Plan:
    def __init__(self, path: str = DB, site: str | None = None,
                 hostname: str | None = None):
        self.path = path
        self.site = (site or self._own_site(hostname)).upper()

    def _rows(self, sql: str, args: tuple = ()) -> list[tuple]:
        conn = sqlite3.connect('file:%s?mode=ro' % self.path, uri=True)
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def _own_site(self, hostname: str | None) -> str:
        hostname = hostname or socket.getfqdn()
        rows = self._rows('''SELECT n.name FROM host AS h, network AS n
                             WHERE h.name = ? AND n.node_id = h.network_id''',
                          (hostname,))
        site = _site(rows[0][0]) if rows else None
        if site is None:
            # never "every site": that would name another site's switches
            raise LookupError('whereami does not know its site: %s is not in '
                              '%s (set WHEREAMI_SITE)' % (hostname, self.path))
        return site

    def switches(self) -> list[Switch]:
        """Every access and dist switch of the site, by name."""
        rows = self._rows(
            '''SELECT h.name, o.value, h.ipv4_addr_txt, n.name
               FROM host AS h, option AS o, network AS n
               WHERE o.node_id = h.node_id AND o.name = 'layer'
                 AND n.node_id = h.network_id''')
        return sorted((Switch(name, layer, ipv4)
                       for name, layer, ipv4, network in rows
                       if layer in LAYERS and _site(network) == self.site),
                      key=lambda s: s.name)

    def switch(self, name: str) -> Switch | None:
        """The site's switch called NAME: its full name in the plan, or
        the one whose name starts with NAME and a dot (a relay says
        "d23-a", the plan "d23-a.event.dreamhack.local"). None when
        there is none, or more than one."""
        name = name.lower().rstrip('.')
        found = [s for s in self.switches()
                 if s.name.lower() == name
                 or s.name.lower().startswith(name + '.')]
        return found[0] if len(found) == 1 else None

    def access_switches_on_vlan(self, vlan: int) -> list[Switch]:
        """The site's access switches that serve the network with that
        VLAN - where a client is whose relay only gave a MAC."""
        rows = self._rows(
            '''SELECT s.switch_name, n.name FROM active_switch AS s,
                      network AS n
               WHERE n.node_id = s.node_id AND n.vlan = ?''', (vlan,))
        names = {name.lower() for name, network in rows
                 if _site(network) == self.site}
        return [s for s in self.switches()
                if s.layer == 'access' and s.name.lower() in names]
