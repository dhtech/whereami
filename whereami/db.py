# SPDX-License-Identifier: GPL-3.0-or-later
"""The two databases.

  Leases   the lease history that lease2db keeps
           (https://github.com/dhtech/lease2db, schema version 2 or
           later: option 82 as bytes). Only read; every connection is
           made read-only.
  Store    whereami's own: who confirmed which switch, and which
           descriptions were written to ports. Rows are only ever
           ADDED - the newest row for a switch is what holds, the older
           ones are its history.

The tables of the Store are in schema.sql; `python3 -m whereami.initdb`
creates them.
"""
from __future__ import annotations

LEASE_SCHEMA_NEEDED = 2
SCHEMA_VERSION = 1

ACTIVE_LEASE = """
    SELECT mac::text AS mac, remote_id, circuit_id
    FROM leases_active
    WHERE ip = %s::inet AND mac IS NOT NULL
    ORDER BY starts DESC LIMIT 1"""

LATEST = """
    SELECT DISTINCT ON (switch) switch, confirmed, comment, interface, username, at
    FROM confirmations ORDER BY switch, at DESC, id DESC"""

HISTORY = """
    SELECT switch, confirmed, comment, interface, username, at
    FROM confirmations WHERE switch = %s ORDER BY at DESC, id DESC LIMIT %s"""

CONFIRM = """
    INSERT INTO confirmations (switch, confirmed, comment, interface, username)
    VALUES (%s, %s, %s, %s, %s)"""

DESCRIBED = """
    INSERT INTO port_descriptions (switch, interface, ifindex, description, username)
    VALUES (%s, %s, %s, %s, %s)"""


def _pool(dsn: str, size: int, read_only: bool):
    # imported here: the rest of the program (and its tests) can be
    # loaded without a PostgreSQL driver
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    def configure(conn):
        conn.autocommit = True
        if read_only:
            # the SERVER refuses any statement that writes
            conn.execute('SET default_transaction_read_only = on')

    pool = ConnectionPool(dsn, min_size=1, max_size=size, open=False, timeout=10,
                          configure=configure, kwargs={'row_factory': dict_row})
    # open without waiting: the page comes up, and says so, when the
    # database is away
    pool.open(wait=False)
    return pool


class Leases:
    """What lookup() calls its "leases"."""

    def __init__(self, dsn: str, pool_size: int = 4):
        self.pool = _pool(dsn, pool_size, read_only=True)

    def active(self, ip: str) -> dict | None:
        """The active lease of IP: its MAC and what the relay said, as
        the bytes it sent. None when there is none."""
        with self.pool.connection() as conn:
            row = conn.execute(ACTIVE_LEASE, (ip,)).fetchone()
        if row is None:
            return None
        return {'mac': row['mac'],
                'remote_id': _bytes(row['remote_id']),
                'circuit_id': _bytes(row['circuit_id'])}

    def schema_version(self) -> int:
        with self.pool.connection() as conn:
            return conn.execute('SELECT version FROM lease2db_schema').fetchone()['version']


def _bytes(value) -> bytes | None:
    return None if value is None else bytes(value)


class Store:
    def __init__(self, dsn: str, pool_size: int = 4):
        self.pool = _pool(dsn, pool_size, read_only=False)

    def _rows(self, sql: str, values: tuple = ()) -> list[dict]:
        with self.pool.connection() as conn:
            return conn.execute(sql, values).fetchall()

    def latest(self) -> dict[str, dict]:
        """{switch: its newest confirmation row}."""
        return {row['switch']: row for row in self._rows(LATEST)}

    def history(self, switch: str, limit: int = 20) -> list[dict]:
        return self._rows(HISTORY, (switch, limit))

    def confirm(self, switch: str, confirmed: bool, comment: str, interface: str,
                username: str) -> None:
        with self.pool.connection() as conn:
            conn.execute(CONFIRM, (switch, confirmed, comment, interface, username))

    def described(self, switch: str, interface: str, ifindex: int, description: str,
                  username: str) -> None:
        with self.pool.connection() as conn:
            conn.execute(DESCRIBED, (switch, interface, ifindex, description, username))

    def schema_version(self) -> int:
        return self._rows('SELECT version FROM whereami_schema')[0]['version']
