# whereami

Which switch and port am I plugged into?

During the build-up of an event a tech plugs a laptop into a port,
opens whereami and is told which switch and port that is. The tech then
confirms that the switch is where it should be; the others follow the
progress on a status page.

This is a new program on the ideas of the old `whereami3`.

## What it does

- **The lookup** (`/`): which switch and port your address is on, shown
  step by step as it is found.
- **Confirm** the switch - "it is where it should be" - or report a
  problem with it, with a comment. Every word is kept; the newest one
  about a switch holds.
- **Describe** the port, when you are on a dist switch: the text is
  written to the port's description over SNMP. Optional.
- **The status page** (`/status`) and the same as data
  (`/api/switches`; `/analytics/switch.status` in the old whereami's
  shape): every switch of the site, confirmed or not, by whom.
- **The leaderboard** (`/leaderboard`): who has confirmed the most
  switches. A switch counts for whoever said the newest word about it;
  equal numbers share a place.
- **The log**: under the answer, every step of the lookup as the server
  sent it - the lease's option 82 as the relay sent it, which switch
  was asked over SNMP, how long each step took. For finding out why a
  lookup went wrong.
- **A switch that does not answer** is said as that, not as "does not
  see your MAC address": it did not answer over SNMP (away, or it does
  not let whereami ask), it turned down whereami's login (SNMPv3), or
  its name leads to no address. The page names the switch, the lookup
  goes on to the next one, and the server's log gets a warning. (With
  the ezsnmp library; the `netsnmp` binding cannot tell the two apart.)
- **The IPv6 check**: your browser asks an IPv6-only name of the server
  and a service outside, and says whether each answered.

Nothing is shown without a login. whereami does not log anybody in
itself: a reverse proxy in front of it does, and tells whereami who it
is and where the visitor came from (`contrib/nginx.conf`).

## How it finds you

1. Your address's active DHCP lease (the lease database that
   [lease2db](https://github.com/dhtech/lease2db) keeps) says your MAC
   and what the relaying switch added to your request (option 82).
2. A relay that names itself is the switch you are on: a Juniper says
   the port, a Cisco is asked over SNMP where it sees your MAC.
3. A relay that only gave its MAC has access switches behind it: the
   network plan says which serve your VLAN, and they are asked.

The plan (`/etc/ipplan.db`) holds every site; whereami answers for its
own.

## Running it

whereami is a WSGI application (`whereami.wsgi:app`) on Flask, psycopg
and one SNMP library (ezsnmp, or the Net-SNMP project's own `netsnmp`
when that is installed). `contrib/whereami.service` is an example unit
for gunicorn, `contrib/nginx.conf` the proxy in front of it. Its
settings come from the environment:

| Variable | What |
|---|---|
| `WHEREAMI_LEASES_DSN` | the lease database (read only) |
| `WHEREAMI_DSN` | whereami's own database; `python3 -m whereami.initdb` makes its tables |
| `WHEREAMI_KEY_FILE` | at least 32 random bytes: signs the tickets a lookup hands out |
| `WHEREAMI_SECRETS` | the switches' SNMP credentials, JSON (default `/etc/whereami/secrets.json`; see `whereami/credentials.py`) |
| `WHEREAMI_PLAN`, `WHEREAMI_SITE` | the plan database (default `/etc/ipplan.db`) and the site to answer for (default: this machine's own) |
| `WHEREAMI_IPV6_OWN_URL`, `WHEREAMI_IPV6_OUTSIDE_URL` | the two addresses of the IPv6 check; each answers with the caller's address |
| `WHEREAMI_TIMEZONE`, `WHEREAMI_TITLE` | how times and the pages' title are shown |

The name people use must reach whereami over **IPv4**: it finds a
visitor by the DHCP lease of the IPv4 address they came from.

## Tests

    python3 -m pytest
