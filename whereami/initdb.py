# SPDX-License-Identifier: GPL-3.0-or-later
"""Create whereami's own tables:  python3 -m whereami.initdb

Reads WHEREAMI_DSN. Safe to run again (see schema.sql)."""
from __future__ import annotations

import os
import sys
from importlib import resources


def schema() -> str:
    return resources.files('whereami').joinpath('schema.sql').read_text('utf-8')


def main() -> int:
    dsn = os.environ.get('WHEREAMI_DSN', '')
    if not dsn:
        print('WHEREAMI_DSN is not set: no database to prepare', file=sys.stderr)
        return 2
    import psycopg
    with psycopg.connect(dsn) as conn:
        conn.execute(schema())
        version = conn.execute('SELECT version FROM whereami_schema').fetchone()[0]
    print('whereami: tables present, schema version %d' % version)
    return 0


if __name__ == '__main__':
    sys.exit(main())
