# SPDX-License-Identifier: GPL-3.0-or-later
"""The web application.

  /                         your switch and port, found as you watch
  /stream                   the same, as server-sent events
  /confirm    (POST)        "this switch is where it should be" (or not)
  /describe   (POST)        write a description to your dist port
  /status                   every switch of the site and who confirmed it
  /leaderboard              who has confirmed the most switches
  /api/switches             the same as JSON (for a map)
  /analytics/switch.status  {switch: "OK" | "UNKNOWN"} - the old shape
  /ipv6                     the address you came from (the IPv6 check)
  /healthz                  for a monitor

WHO IS ASKING. whereami does not log anybody in. A reverse proxy in
front does (the directory), and hands over the name in a header
(X-Remote-User) and the visitor's address in another (X-Real-IP).
whereami listens on the loopback address only and believes those
headers - and refuses every page without a name, so a proxy that lets
somebody through unnamed shows nothing. /healthz and /ipv6 are the two
exceptions: they tell nothing but "up" and the caller's own address.

WHAT A VISITOR MAY CHANGE. Only what the lookup found for THEM: the
answer carries a signed ticket naming the visitor, the switch and the
port, and /confirm and /describe take nothing else. Nobody can confirm
a switch they are not plugged into, or write to another port.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import secrets as random_source
import zoneinfo
from urllib.parse import urlsplit

from flask import Flask, Response, abort, jsonify, render_template, request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import __version__, credentials
from .lookup import lookup
from .snmp import Refused, Switches

TICKET_AGE = 30 * 60        # seconds a lookup's answer may be acted on
COMMENT_MAX = 500
_USERNAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$')
_OPEN = ('healthz', 'ipv6', 'static')      # endpoints without a login


def create_app(leases=None, store=None, plan=None, switches=None,
               config: dict | None = None) -> Flask:
    """The application. LEASES, STORE, PLAN and SWITCHES are anything
    with the methods of db.Leases, db.Store, plan.Plan and
    snmp.Switches (the tests hand in their own); by default they are
    made from the environment."""
    app = Flask(__name__)
    env = os.environ.get
    app.config.update(
        LEASES_DSN=env('WHEREAMI_LEASES_DSN', ''),
        DSN=env('WHEREAMI_DSN', ''),
        PLAN=env('WHEREAMI_PLAN', '/etc/ipplan.db'),
        SITE=env('WHEREAMI_SITE', ''),
        SECRETS=env('WHEREAMI_SECRETS', credentials.PATH),
        KEY_FILE=env('WHEREAMI_KEY_FILE', ''),
        TIMEZONE=env('WHEREAMI_TIMEZONE', 'UTC'),
        TITLE=env('WHEREAMI_TITLE', 'whereami'),
        USER_HEADER=env('WHEREAMI_USER_HEADER', 'X-Remote-User'),
        ADDRESS_HEADER=env('WHEREAMI_ADDRESS_HEADER', 'X-Real-IP'),
        # the IPv6 check: an address of our own that is reached over
        # IPv6 only, and somebody outside - each answers with the
        # caller's address
        IPV6_OWN_URL=env('WHEREAMI_IPV6_OWN_URL', ''),
        IPV6_OUTSIDE_URL=env('WHEREAMI_IPV6_OUTSIDE_URL', ''),
    )
    app.config.update(config or {})

    if leases is None:
        from .db import Leases
        if not app.config['LEASES_DSN']:
            raise RuntimeError('WHEREAMI_LEASES_DSN is not set: no lease database to read')
        leases = Leases(app.config['LEASES_DSN'])
    if store is None:
        from .db import Store
        if not app.config['DSN']:
            raise RuntimeError('WHEREAMI_DSN is not set: no database of our own')
        store = Store(app.config['DSN'])
    if plan is None:
        from .plan import Plan
        plan = Plan(app.config['PLAN'], app.config['SITE'] or None)

    def the_switches():
        """The switches as they are asked NOW: the credentials are read
        for every lookup."""
        if switches is not None:
            return switches
        from .snmp import default_transport
        return Switches(credentials.load(app.config['SECRETS']),
                        default_transport(log=app.logger))

    tickets = URLSafeTimedSerializer(_key(app), salt='whereami-ticket')
    tz = zoneinfo.ZoneInfo(app.config['TIMEZONE'])

    # --- who is asking ---------------------------------------------------

    def username() -> str | None:
        name = request.headers.get(app.config['USER_HEADER'], '').strip()
        return name if _USERNAME.match(name) else None

    def address() -> str:
        return request.headers.get(app.config['ADDRESS_HEADER'], '').strip() \
            or request.remote_addr or ''

    @app.before_request
    def named_visitors_only():
        if request.endpoint in _OPEN or request.endpoint is None:
            return None
        if username() is None:
            abort(401)
        return None

    @app.template_filter('when')
    def when(value):
        if value is None:
            return ''
        return value.astimezone(tz).strftime('%Y-%m-%d %H:%M')

    @app.context_processor
    def common():
        return {'title': app.config['TITLE'], 'version': __version__,
                'timezone': app.config['TIMEZONE'], 'user': username(),
                'site': getattr(plan, 'site', '')}

    @app.after_request
    def headers(response):
        # everything on the pages is our own; the IPv6 check may ask the
        # two addresses it is configured with, nothing else
        connect = ["'self'"] + [o for o in (_origin(app.config['IPV6_OWN_URL']),
                                           _origin(app.config['IPV6_OUTSIDE_URL'])) if o]
        response.headers.setdefault(
            'Content-Security-Policy',
            "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; "
            "connect-src %s; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            % ' '.join(connect))
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('Cache-Control', 'no-store')
        return response

    # --- the state of the switches ---------------------------------------

    def switch_rows() -> list[dict]:
        """Every switch of the site with the newest word about it."""
        latest = store.latest()
        rows = []
        for switch in plan.switches():
            said = latest.get(switch.name.lower())
            rows.append({
                'switch': switch.name, 'layer': switch.layer,
                'status': 'UNKNOWN' if said is None else 'OK' if said['confirmed'] else 'PROBLEM',
                'comment': said['comment'] if said else '',
                'interface': said['interface'] if said else '',
                'username': said['username'] if said else '',
                'at': said['at'] if said else None,
            })
        return rows

    def leaders(rows: list[dict]) -> list[dict]:
        """The people, by how many switches they hold: a switch counts
        for whoever said the newest word about it - "confirmed" when
        that word is that it is where it should be, "problems" when it
        is a problem. Most confirmed first; equal numbers share a
        place (1, 1, 3)."""
        people: dict[str, dict] = {}
        for row in rows:
            if row['status'] == 'UNKNOWN':
                continue
            person = people.setdefault(row['username'], {
                'username': row['username'], 'confirmed': 0, 'problems': 0, 'latest': None})
            person['confirmed' if row['status'] == 'OK' else 'problems'] += 1
            if row['at'] is not None and (person['latest'] is None or row['at'] > person['latest']):
                person['latest'] = row['at']
        out = sorted(people.values(),
                     key=lambda p: (-p['confirmed'], -p['problems'], p['username']))
        for position, person in enumerate(out, 1):
            before = out[position - 2] if position > 1 else None
            person['place'] = before['place'] if before and before['confirmed'] == person['confirmed'] \
                else position
        return out

    def word_about(switch_name: str) -> dict | None:
        said = store.latest().get(switch_name.lower())
        if said is None:
            return None
        return {'confirmed': bool(said['confirmed']), 'comment': said['comment'],
                'username': said['username'], 'at': when(said['at'])}

    # --- the pages --------------------------------------------------------

    @app.get('/')
    def index():
        return render_template('index.html', ipv6_own=app.config['IPV6_OWN_URL'],
                               ipv6_outside=app.config['IPV6_OUTSIDE_URL'],
                               comment_max=COMMENT_MAX)

    @app.get('/stream')
    def stream():
        user, ip = username(), address()

        def steps():
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                yield {'type': 'error', 'message':
                       'You came here from %s. whereami finds you by your IPv4 '
                       'address\'s DHCP lease - come over IPv4.' % (ip or 'no address')}
                return
            asked = the_switches()
            try:
                for step in lookup(ip, leases, plan, asked):
                    if step['type'] == 'done':
                        step = finished(step, user, asked)
                    yield step
            except LookupError as exc:      # a credential is missing, ...
                yield {'type': 'error', 'message': str(exc)}
            except Exception:
                app.logger.exception('lookup for %s failed', ip)
                yield {'type': 'error', 'message':
                       'The lookup broke off (a database or a switch could not be '
                       'asked). It is in the server\'s log.'}

        def sse():
            for step in steps():
                yield 'data: %s\n\n' % json.dumps(step)

        return Response(sse(), mimetype='text/event-stream',
                        headers={'X-Accel-Buffering': 'no'})

    def finished(step: dict, user: str, asked) -> dict:
        """The answer, with the ticket to act on it."""
        describable = (step['layer'] == 'dist' and step['ifindex'] is not None
                       and getattr(getattr(asked, 'credentials', None), 'dist', True) is not None)
        ticket = tickets.dumps({'u': user, 's': step['switch'], 'l': step['layer'],
                                'i': step['interface'], 'x': step['ifindex']})
        try:
            said = word_about(step['switch'])
        except Exception:
            app.logger.exception('reading the confirmations failed')
            said = None
        return dict(step, ticket=ticket, describable=describable, said=said)

    def ticket_of(user: str) -> dict:
        try:
            ticket = tickets.loads(request.form.get('ticket', ''), max_age=TICKET_AGE)
        except BadSignature:        # also: too old
            abort(403, 'Look yourself up again: this answer is too old, or not yours.')
        if ticket.get('u') != user:
            abort(403, 'Look yourself up again: this answer is not yours.')
        return ticket

    @app.post('/confirm')
    def confirm():
        user = username()
        ticket = ticket_of(user)
        verdict = request.form.get('verdict')
        if verdict not in ('ok', 'problem'):
            abort(400, 'Say whether the switch is right: verdict=ok or verdict=problem.')
        comment = _clean(request.form.get('comment', ''))
        if len(comment) > COMMENT_MAX:
            abort(400, 'A comment is at most %d characters.' % COMMENT_MAX)
        if verdict == 'problem' and not comment:
            abort(400, 'Say what is wrong with the switch.')
        store.confirm(ticket['s'].lower(), verdict == 'ok', comment, ticket['i'], user)
        app.logger.info('%s: %s says %s', ticket['s'], user, verdict)
        return jsonify(saved=True, switch=ticket['s'], said=word_about(ticket['s']))

    @app.post('/describe')
    def describe():
        user = username()
        ticket = ticket_of(user)
        if ticket.get('l') != 'dist' or ticket.get('x') is None:
            abort(400, 'A description can be written to a port of a dist switch only.')
        switch = plan.switch(ticket['s'])
        if switch is None:
            abort(400, 'The plan no longer has the switch %s.' % ticket['s'])
        try:
            now = the_switches().set_description(switch, ticket['x'],
                                                 request.form.get('description', ''))
        except Refused as exc:
            abort(400, str(exc))
        except LookupError as exc:
            abort(502, str(exc))
        store.described(switch.name.lower(), ticket['i'], ticket['x'], now, user)
        app.logger.info('%s %s: %s wrote the description %r', switch.name, ticket['i'], user, now)
        return jsonify(saved=True, switch=switch.name, interface=ticket['i'], description=now)

    @app.get('/status')
    def status():
        rows = switch_rows()
        counts = {state: sum(1 for r in rows if r['status'] == state)
                  for state in ('OK', 'PROBLEM', 'UNKNOWN')}
        by_user: dict[str, int] = {}
        for row in rows:
            if row['status'] == 'OK':
                by_user[row['username']] = by_user.get(row['username'], 0) + 1
        order = {'PROBLEM': 0, 'UNKNOWN': 1, 'OK': 2}
        rows.sort(key=lambda r: (order[r['status']], r['switch']))
        return render_template('status.html', rows=rows, counts=counts, total=len(rows),
                               by_user=sorted(by_user.items(), key=lambda kv: (-kv[1], kv[0])))

    @app.get('/leaderboard')
    def leaderboard():
        rows = switch_rows()
        return render_template('leaderboard.html', leaders=leaders(rows), total=len(rows),
                               confirmed=sum(1 for r in rows if r['status'] == 'OK'))

    @app.get('/api/switches')
    def api_switches():
        return jsonify(site=getattr(plan, 'site', ''),
                       switches=[dict(row, at=_iso(row['at'])) for row in switch_rows()])

    @app.get('/analytics/switch.status')
    def switch_status():
        # the old whereami's answer, for what reads it: a problem is
        # "not OK" there too
        return jsonify({row['switch']: 'OK' if row['status'] == 'OK' else 'UNKNOWN'
                        for row in switch_rows()})

    @app.get('/ipv6')
    def ipv6():
        """The caller's own address - what the IPv6 check on the page
        asks an IPv6-only name of this server. Open to a page of
        another origin: it tells the caller nothing but its address."""
        ip = address()
        try:
            version = ipaddress.ip_address(ip).version
        except ValueError:
            version = None
        response = jsonify(ip=ip, ipv6=version == 6)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

    @app.get('/healthz')
    def healthz():
        plain = {'Content-Type': 'text/plain; charset=utf-8'}
        try:
            leases.schema_version()
            store.schema_version()
        except Exception as exc:
            app.logger.warning('health check: %s', type(exc).__name__)
            return 'a database is not reachable\n', 503, plain
        return 'ok\n', 200, plain

    @app.errorhandler(Exception)
    def failed(exc):
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            if _wants_json():
                return jsonify(error=exc.description), exc.code
            if exc.code == 401:
                return ('Nobody is logged in: whereami shows nothing without a name.\n',
                        401, {'Content-Type': 'text/plain; charset=utf-8'})
            return render_template('error.html', message=exc.description), exc.code
        app.logger.exception('request failed')
        message = 'whereami could not read what it needs right now (a database is away).'
        if _wants_json():
            return jsonify(error=message), 503
        return render_template('error.html', message=message), 503

    return app


def _wants_json() -> bool:
    return request.method == 'POST' or request.path.startswith(('/api/', '/analytics/'))


def _key(app: Flask) -> bytes:
    """What the tickets are signed with. Every worker process must have
    the same: a file (made once, readable by whereami only). Without
    one a key is made up for this process - fine for one process."""
    path = app.config.get('KEY_FILE')
    if path:
        with open(path, 'rb') as handle:
            key = handle.read().strip()
        if len(key) < 32:
            raise RuntimeError('%s holds less than 32 bytes: not a key' % path)
        return key
    app.logger.warning('WHEREAMI_KEY_FILE is not set: tickets are signed with a key '
                       'of this process only')
    return random_source.token_bytes(32)


def _origin(url: str) -> str | None:
    parts = urlsplit(url or '')
    return '%s://%s' % (parts.scheme, parts.netloc) if parts.scheme == 'https' and parts.netloc else None


def _clean(text: str) -> str:
    """One line of printable text."""
    return ' '.join(''.join(c if c.isprintable() else ' ' for c in text).split())


def _iso(value) -> str | None:
    if not isinstance(value, datetime.datetime):
        return None
    return value.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
