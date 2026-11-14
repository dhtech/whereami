# SPDX-License-Identifier: GPL-3.0-or-later
"""What a relaying switch says about a DHCP client (option 82).

The lease database (lease2db) keeps the two sub-options as the bytes
the relay sent. Two makes of switch write them differently:

  Cisco    binary, each with a type and a length in front:
             remote id   00 06 <6 bytes>      the switch's MAC
                         01 LL <LL bytes>     the switch's hostname
                                              ("remote-id hostname")
             circuit id  00 04 VV VV MM PP    vlan, module, port
  Juniper  text:
             remote id   the switch's hostname (or a MAC with colons)
             circuit id  ge-0/0/12.0:vlan-name  interface, then the vlan

A value that is neither is not guessed at: the functions return None.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_MAC = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')
_HOSTNAME = re.compile(r'^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$')
# ge-0/0/12.0 - type, fpc, pic (the "module"), port, unit
_JUNIPER_IF = re.compile(r'^[a-z]+-\d+/(\d+)/(\d+)(\.\d+)?$')


@dataclass(frozen=True)
class RemoteId:
    kind: str        # 'hostname' or 'mac'
    value: str       # lower case
    juniper: bool    # written as text - the switch is a Juniper


@dataclass(frozen=True)
class CircuitId:
    vlan: int | str | None   # Cisco: the number; Juniper: the vlan's name
    module: int | None
    port: int | None
    interface: str | None    # Juniper: the interface as the switch wrote it
    juniper: bool


def _tlv(data: bytes) -> tuple[int, bytes] | None:
    """(type, value) when DATA is one Cisco sub-option: a type of 0 or
    1, a length that is exactly the rest."""
    if len(data) >= 3 and data[0] in (0, 1) and data[1] == len(data) - 2:
        return data[0], data[2:]
    return None


def _text(data: bytes) -> str | None:
    try:
        text = data.decode('ascii')
    except UnicodeDecodeError:
        return None
    # dhcpd writes a text value in quotes; some relays send them along
    text = text.strip().strip('"')
    return text if text and text.isprintable() else None


def remote_id(data: bytes | None) -> RemoteId | None:
    """Who relayed: a hostname or a MAC. None for nothing usable."""
    if not data:
        return None
    data = bytes(data)
    tlv = _tlv(data)
    if tlv is not None:
        kind, value = tlv
        if kind == 0 and len(value) == 6:
            return RemoteId('mac', ':'.join('%02x' % b for b in value), False)
        if kind == 1:
            name = _text(value)
            if name and _HOSTNAME.match(name.lower()):
                return RemoteId('hostname', name.lower(), False)
        return None
    text = _text(data)
    if text is None or text.lower() == 'null':
        return None
    text = text.lower()
    if _MAC.match(text):
        return RemoteId('mac', text, True)
    if _HOSTNAME.match(text):
        return RemoteId('hostname', text, True)
    return None


def circuit_id(data: bytes | None) -> CircuitId | None:
    """Where on the relay: vlan, module and port. None for nothing
    usable (also the all-zero value some relays send for "none")."""
    if not data:
        return None
    data = bytes(data)
    tlv = _tlv(data)
    if tlv is not None:
        kind, value = tlv
        if kind == 0 and len(value) == 4:
            vlan = int.from_bytes(value[:2], 'big')
            if vlan == 0 and value[2] == 0 and value[3] == 0:
                return None
            return CircuitId(vlan, value[2], value[3], None, False)
        return None
    text = _text(data)
    if text is None or ':' not in text:
        return None
    interface, vlan = text.split(':', 1)
    found = _JUNIPER_IF.match(interface.lower())
    if not found or not vlan:
        return None
    return CircuitId(vlan, int(found.group(1)), int(found.group(2)),
                     interface, True)
