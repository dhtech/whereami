-- SPDX-License-Identifier: GPL-3.0-or-later
-- whereami's own tables. Safe to run again: nothing that exists is
-- touched. Applied by `python3 -m whereami.initdb`.

CREATE TABLE IF NOT EXISTS whereami_schema (version integer NOT NULL);
INSERT INTO whereami_schema (version)
	SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM whereami_schema);

CREATE TABLE IF NOT EXISTS confirmations (
	id         bigserial PRIMARY KEY,
	switch     text NOT NULL,
	confirmed  boolean NOT NULL,
	comment    text NOT NULL DEFAULT '',
	interface  text NOT NULL DEFAULT '',
	username   text NOT NULL,
	at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE confirmations IS
	'What a tech said about a switch. Rows are only added: the newest row of a switch holds.';
CREATE INDEX IF NOT EXISTS confirmations_switch_at ON confirmations (switch, at DESC, id DESC);

CREATE TABLE IF NOT EXISTS port_descriptions (
	id          bigserial PRIMARY KEY,
	switch      text NOT NULL,
	interface   text NOT NULL,
	ifindex     integer NOT NULL,
	description text NOT NULL,
	username    text NOT NULL,
	at          timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE port_descriptions IS
	'Every description whereami wrote to a port of a dist switch, and for whom.';
