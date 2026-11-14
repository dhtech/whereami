# SPDX-License-Identifier: GPL-3.0-or-later
# What is asked of the two databases (the statements; a PostgreSQL is
# not needed to run these).
import re

from whereami import db, initdb


def test_the_lease_is_the_active_one_of_that_address():
    sql = ' '.join(db.ACTIVE_LEASE.split())
    assert 'FROM leases_active' in sql and 'ip = %s::inet' in sql
    assert sql.endswith('ORDER BY starts DESC LIMIT 1')
    # the relay's two values as the bytes lease2db keeps
    assert re.search(r'SELECT mac::text AS mac, remote_id, circuit_id\b', sql)


def test_the_newest_row_of_a_switch_holds():
    sql = ' '.join(db.LATEST.split())
    assert 'DISTINCT ON (switch)' in sql
    assert sql.endswith('ORDER BY switch, at DESC, id DESC')


def test_rows_are_only_added():
    for statement in (db.CONFIRM, db.DESCRIBED):
        assert statement.strip().startswith('INSERT INTO')
    everything = ' '.join(v for k, v in vars(db).items()
                          if k.isupper() and isinstance(v, str))
    assert not re.search(r'\b(UPDATE|DELETE|DROP|TRUNCATE)\b', everything)


def test_the_schema_can_be_applied_again():
    schema = initdb.schema()
    for create in re.findall(r'CREATE (?:TABLE|INDEX)[^\n]*', schema):
        assert 'IF NOT EXISTS' in create, create
    for table in ('whereami_schema', 'confirmations', 'port_descriptions'):
        assert 'CREATE TABLE IF NOT EXISTS %s ' % table in schema
    # every column the statements name is in the schema
    for column in ('switch', 'confirmed', 'comment', 'interface', 'username',
                   'at', 'ifindex', 'description'):
        assert re.search(r'^\t%s\s' % column, schema, re.M), column


def test_bytes_from_the_driver_are_bytes():
    assert db._bytes(None) is None
    assert db._bytes(memoryview(b'\x00\x04')) == b'\x00\x04'
