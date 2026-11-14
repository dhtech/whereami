# SPDX-License-Identifier: GPL-3.0-or-later
"""The switches' SNMP credentials, from a file.

Whoever runs the server puts them there (from a secret store, by hand,
...) as JSON, readable by whereami only:

    {"dist": {"user": "...", "auth_password": "...",
              "priv_password": "...",
              "auth_proto": "SHA", "priv_proto": "AES"},
     "access_community": "..."}

Either half may be missing: whereami then says which switches it cannot
ask, instead of failing as a whole. The file is read for every lookup,
so a changed credential is used without a restart.
"""
from __future__ import annotations

import json

from .snmp import Credentials, DistCredentials

PATH = '/etc/whereami/secrets.json'


def _text(value) -> str | None:
    return value if isinstance(value, str) and value else None


def load(path: str = PATH) -> Credentials:
    """The credentials in PATH; empty ones for no file or a broken one
    (which is said in missing(), never raised with the content)."""
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = None
    if not isinstance(data, dict):
        return Credentials(None, None)
    dist = None
    d = data.get('dist')
    if isinstance(d, dict) and _text(d.get('user')) and _text(d.get('auth_password')) \
            and _text(d.get('priv_password')):
        dist = DistCredentials(d['user'], d['auth_password'], d['priv_password'],
                               _text(d.get('auth_proto')) or 'SHA',
                               _text(d.get('priv_proto')) or 'AES')
    return Credentials(dist, _text(data.get('access_community')))


def missing(credentials: Credentials) -> list[str]:
    """Which halves are not there, in words for a page."""
    out = []
    if credentials.dist is None:
        out.append('the dist switches\' SNMPv3 account')
    if not credentials.access_community:
        out.append('the access switches\' SNMP community')
    return out
