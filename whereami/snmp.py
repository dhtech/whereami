# SPDX-License-Identifier: GPL-3.0-or-later
"""Asking a switch where a MAC address is - and, when a tech wants it,
writing a port's description.

Two kinds of switch are asked, each in the way it answers:

  dist     SNMPv3 (user, authentication and privacy). A Cisco keeps one
           forwarding table per VLAN and shows it in the context
           "vlan-<number>".
  access   SNMPv2c. The old access switches (2950) know no contexts:
           the VLAN goes after the community, "<community>@<number>".

The questions, in order (the old whereami's):

  dot1dTpFdbPort           MAC          -> bridge port
  dot1dBasePortIfIndex     bridge port  -> ifIndex
  vlanTrunkPortDynamicStatus  ifIndex   -> 1 when the port is a trunk
  ifDescr, ifAlias         ifIndex      -> the port's name, its description

A description is written to ifAlias of ONE ifIndex on a dist switch,
and only text made of the characters in DESCRIPTION_CHARS.

The talking itself is done by a "transport": the Net-SNMP project's own
Python binding "netsnmp" (PyPI: python3-netsnmp, compiled against
libsnmp - what the old whereami used) when it is installed, otherwise
python3-ezsnmp or its ancestor python3-easysnmp (Debian packages both).
Either is imported when first used, so that everything else loads and
is tested without them.

A switch that gives no answer to work with is not a switch that does
not see the MAC. The ezsnmp transport says which it
was: nothing came back in time (away, a community or a privacy password
that is not the switch's, a VLAN it has not - a switch stays silent to
all of these), the switch answered and turned the login down (SNMPv3
only: an unknown user, a wrong authentication password), or its name
leads to no address. Tried against a real snmpd with Debian 13's
python3-ezsnmp 1.1.0. The netsnmp transport cannot tell: its "nothing"
stays "the switch does not see the MAC", as before.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .lookup import FAILED, REFUSED, SILENT, UNREACHABLE, Port, Unanswered

FDB_PORT = '.1.3.6.1.2.1.17.4.3.1.2'            # dot1dTpFdbPort
BASE_PORT_IFINDEX = '.1.3.6.1.2.1.17.1.4.1.2'   # dot1dBasePortIfIndex
TRUNK_STATUS = '.1.3.6.1.4.1.9.9.46.1.6.1.1.14'  # vlanTrunkPortDynamicStatus
IF_DESCR = '.1.3.6.1.2.1.2.2.1.2'
IF_ALIAS = '.1.3.6.1.2.1.31.1.1.1.18'

TRUNKING = '1'

DESCRIPTION_MAX = 60
DESCRIPTION_CHARS = re.compile(r'^[A-Za-z0-9 _.,:/@#()+-]*$')
_MAC = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')


class Refused(ValueError):
    """Something this module will not send to a switch."""


@dataclass(frozen=True)
class DistCredentials:
    """The dist layer's SNMPv3 account."""
    user: str
    auth_password: str
    priv_password: str
    auth_proto: str = 'SHA'
    priv_proto: str = 'AES'
    level: str = 'auth_with_privacy'

    def __repr__(self) -> str:      # never the passwords, in no log
        return 'DistCredentials(user=%r)' % self.user


@dataclass(frozen=True)
class Credentials:
    dist: DistCredentials | None
    access_community: str | None

    def __repr__(self) -> str:
        return 'Credentials(dist=%r, access_community=%s)' % (
            self.dist, 'set' if self.access_community else 'None')


def mac_index(mac: str) -> str:
    """A MAC as the six numbers an OID ends with."""
    mac = mac.lower()
    if not _MAC.match(mac):
        raise Refused('not a MAC address: %r' % mac)
    return '.'.join(str(int(part, 16)) for part in mac.split(':'))


def clean_description(text: str) -> str:
    """TEXT as it may be written to a port, or Refused."""
    text = ' '.join((text or '').split())
    if len(text) > DESCRIPTION_MAX:
        raise Refused('A description is at most %d characters.'
                      % DESCRIPTION_MAX)
    if not DESCRIPTION_CHARS.match(text):
        raise Refused('A description may hold letters (a-z), digits, spaces '
                      'and _ . , : / @ # ( ) + - only.')
    return text


def _answer(value) -> str | None:
    """What a switch answered, as text; None for no such thing."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'replace')
    value = str(value).strip()
    if not value or value.upper().replace(' ', '').startswith('NOSUCH'):
        return None
    return value


NOTHING = ('NOSUCHOBJECT', 'NOSUCHINSTANCE', 'ENDOFMIBVIEW')


def _session_class():
    try:
        from ezsnmp import Session
    except ImportError:
        from easysnmp import Session
    return Session


class NoAnswer(Exception):
    """A transport's word for "the switch gave nothing to go on"; WHY is
    one of lookup's SILENT, REFUSED, UNREACHABLE, FAILED."""

    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


def why(exc: Exception) -> str:
    """What kind of failure the library's exception is. Its class name
    and a few fixed phrases of Net-SNMP are looked at; its text is never
    kept or logged (it may hold what was sent)."""
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    if 'timeout' in name or 'timed out' in text:
        return SILENT
    if ('unknown user' in text or 'authentication failure' in text
            or 'wrong digest' in text or 'unsupported security level' in text):
        return REFUSED
    if 'connection' in name or 'create snmp handle' in text:
        return UNREACHABLE
    return FAILED


class EzSnmp:
    """The transport: one question, one answer. get() gives the value,
    None when the switch answers that there is no such thing, and raises
    NoAnswer when the switch gives nothing to go on (away, wrong
    credentials, no such VLAN) - which is also said in the log."""

    def __init__(self, timeout: int = 2, retries: int = 1, log=None):
        self.timeout = timeout
        self.retries = retries
        self.log = log

    def _session(self, host: str, how: dict):
        return _session_class()(hostname=host, timeout=self.timeout,
                                retries=self.retries, use_numeric=True, **how)

    def _failed(self, what: str, host: str, exc: Exception) -> str:
        kind = why(exc)
        if self.log is not None:
            # the exception's class only: its text may hold what was sent
            self.log.warning('snmp %s on %s: no answer to go on (%s, %s)',
                             what, host, kind, type(exc).__name__)
        return kind

    def get(self, host: str, how: dict, oid: str):
        try:
            variable = self._session(host, how).get(oid)
        except Exception as exc:
            raise NoAnswer(self._failed('get', host, exc)) from None
        if variable is None or variable.snmp_type in NOTHING:
            return None
        return variable.value

    def set(self, host: str, how: dict, oid: str, text: str) -> bool:
        try:
            return bool(self._session(host, how).set(oid, text, 'OCTETSTR'))
        except Exception as exc:
            self._failed('set', host, exc)
            return False


_NETSNMP_NAMES = {'version': 'Version', 'community': 'Community',
                  'security_username': 'SecName', 'security_level': 'SecLevel',
                  'auth_protocol': 'AuthProto', 'auth_password': 'AuthPass',
                  'privacy_protocol': 'PrivProto',
                  'privacy_password': 'PrivPass', 'context': 'Context'}
_NETSNMP_LEVELS = {'no_auth_or_privacy': 'noAuthNoPriv',
                   'auth_without_privacy': 'authNoPriv',
                   'auth_with_privacy': 'authPriv'}


class NetSnmp:
    """The same transport on the netsnmp binding. It says "nothing"
    by itself (None) when a switch does not answer, and this transport
    cannot tell that from "no such thing": it never raises NoAnswer."""

    def __init__(self, timeout: int = 2, retries: int = 1, log=None,
                 library=None):
        self.timeout = timeout * 1_000_000      # the binding counts in µs
        self.retries = retries
        self.log = log
        self.library = library

    def _library(self):
        if self.library is None:
            import netsnmp
            self.library = netsnmp
        return self.library

    def _how(self, host: str, how: dict) -> dict:
        out = {_NETSNMP_NAMES[key]: value for key, value in how.items()}
        if 'SecLevel' in out:
            out['SecLevel'] = _NETSNMP_LEVELS.get(out['SecLevel'],
                                                  out['SecLevel'])
        out.update(DestHost=host, Timeout=self.timeout, Retries=self.retries)
        return out

    def get(self, host: str, how: dict, oid: str):
        lib = self._library()
        try:
            return lib.snmpget(lib.Varbind(oid), **self._how(host, how))[0]
        except Exception as exc:
            if self.log is not None:
                self.log.warning('snmp get on %s: %s', host,
                                 type(exc).__name__)
            return None

    def set(self, host: str, how: dict, oid: str, text: str) -> bool:
        lib = self._library()
        tag, _, iid = oid.rpartition('.')
        try:
            return bool(lib.snmpset(lib.Varbind(tag, iid, text, 'OCTETSTR'),
                                    **self._how(host, how)))
        except Exception as exc:
            if self.log is not None:
                self.log.warning('snmp set on %s: %s', host,
                                 type(exc).__name__)
            return False


def default_transport(log=None):
    """netsnmp when it is installed, else ezsnmp/easysnmp."""
    try:
        import netsnmp
    except ImportError:
        return EzSnmp(log=log)
    return NetSnmp(log=log, library=netsnmp)


class Switches:
    """What lookup() calls its "snmp"."""

    def __init__(self, credentials: Credentials, transport=None):
        self.credentials = credentials
        self.transport = transport or default_transport()

    def _how(self, switch, vlan: int | None) -> dict:
        """The session settings for SWITCH's layer, for VLAN's table."""
        if vlan is not None and not (isinstance(vlan, int) and 0 < vlan < 4095):
            raise Refused('not a VLAN number: %r' % (vlan,))
        if switch.layer == 'dist':
            dist = self.credentials.dist
            if dist is None:
                raise LookupError('the dist switches\' SNMP account is not '
                                  'known to whereami')
            return {'version': 3, 'security_level': dist.level,
                    'security_username': dist.user,
                    'auth_protocol': dist.auth_proto,
                    'auth_password': dist.auth_password,
                    'privacy_protocol': dist.priv_proto,
                    'privacy_password': dist.priv_password,
                    'context': 'vlan-%d' % vlan if vlan is not None else ''}
        community = self.credentials.access_community
        if not community:
            raise LookupError('the access switches\' SNMP community is not '
                              'known to whereami')
        if vlan is not None:
            community = '%s@%d' % (community, vlan)
        return {'version': 2, 'community': community}

    def _ask(self, switch, vlan, oid: str) -> str | None:
        """One answer of SWITCH, or Unanswered when it gives none."""
        try:
            return _answer(self.transport.get(switch.name,
                                              self._how(switch, vlan), oid))
        except NoAnswer as exc:
            raise Unanswered(switch.name, exc.why) from None

    def _get(self, switch, vlan, oid: str) -> str | None:
        """The same for a question whose answer can be done without: no
        answer is "nothing"."""
        try:
            return self._ask(switch, vlan, oid)
        except Unanswered:
            return None

    def find_port(self, switch, vlan: int | None, mac: str) -> Port | None:
        """The port SWITCH sees MAC on in VLAN; None when it answers that
        it does not see it; Unanswered when it gives no answer to the
        first question (then nothing is known). A trunk comes back
        marked as one - the caller decides what that means."""
        bridge_port = self._ask(switch, vlan, '%s.%s' % (FDB_PORT,
                                                         mac_index(mac)))
        if bridge_port is None or not bridge_port.isdigit():
            return None
        ifindex = self._get(switch, vlan, '%s.%s' % (BASE_PORT_IFINDEX,
                                                     bridge_port))
        if ifindex is None or not ifindex.isdigit():
            return None
        trunk = self._get(switch, vlan, '%s.%s' % (TRUNK_STATUS, ifindex))
        description = self._get(switch, vlan, '%s.%s' % (IF_DESCR, ifindex))
        alias = self._get(switch, vlan, '%s.%s' % (IF_ALIAS, ifindex))
        return Port(description or 'ifIndex %s' % ifindex, alias or '',
                    int(ifindex), trunk == TRUNKING)

    def set_description(self, switch, ifindex: int, text: str) -> str:
        """Write TEXT as the description of port IFINDEX on the dist
        switch SWITCH, read it back, and return what the switch now
        says. Refused for anything but a dist switch and clean text."""
        if switch.layer != 'dist':
            raise Refused('Descriptions are written on dist switches only.')
        if not isinstance(ifindex, int) or isinstance(ifindex, bool) \
                or ifindex <= 0:
            raise Refused('not a port: %r' % (ifindex,))
        text = clean_description(text)
        oid = '%s.%d' % (IF_ALIAS, ifindex)
        if not self.transport.set(switch.name, self._how(switch, None), oid,
                                  text):
            raise LookupError('%s did not take the description.' % switch.name)
        return self._get(switch, None, oid) or ''
