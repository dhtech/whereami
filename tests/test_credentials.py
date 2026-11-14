# SPDX-License-Identifier: GPL-3.0-or-later
# The switches' credentials, from the file.
import json

from whereami import credentials


def write(tmp_path, data):
    path = tmp_path / 'secrets.json'
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return str(path)


FULL = {'dist': {'user': 'u', 'auth_password': 'auth-word',
                 'priv_password': 'priv-word'},
        'access_community': 'the-community'}


def test_the_whole_file(tmp_path):
    got = credentials.load(write(tmp_path, FULL))
    assert (got.dist.user, got.dist.auth_password, got.dist.priv_password,
            got.dist.auth_proto, got.dist.priv_proto) == (
                'u', 'auth-word', 'priv-word', 'SHA', 'AES')
    assert got.access_community == 'the-community'
    assert credentials.missing(got) == []


def test_the_protocols_can_be_said(tmp_path):
    data = dict(FULL, dist=dict(FULL['dist'], auth_proto='SHA256',
                                priv_proto='AES256'))
    got = credentials.load(write(tmp_path, data))
    assert (got.dist.auth_proto, got.dist.priv_proto) == ('SHA256', 'AES256')


def test_a_half_may_be_missing(tmp_path):
    only_access = credentials.load(write(tmp_path, {'access_community': 'c'}))
    assert only_access.dist is None and only_access.access_community == 'c'
    assert len(credentials.missing(only_access)) == 1
    # a dist account without one of its three is no account
    for lacking in ('user', 'auth_password', 'priv_password'):
        dist = dict(FULL['dist'])
        dist[lacking] = ''
        got = credentials.load(write(tmp_path, {'dist': dist}))
        assert got.dist is None, lacking


def test_no_file_or_a_broken_one_is_nothing_not_an_error(tmp_path):
    for path in (str(tmp_path / 'not-there.json'),
                 write(tmp_path, '{not json'),
                 write(tmp_path, '["a list"]')):
        got = credentials.load(path)
        assert got.dist is None and got.access_community is None
        assert len(credentials.missing(got)) == 2
