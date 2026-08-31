"""
Copyright (c) 2020 Keitaro AB

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import os

import pytest
from flask import Flask, session
from flask.sessions import SessionInterface

import ckan.plugins.toolkit as toolkit
from ckan.common import current_user

from ckanext.saml2auth.views import saml2auth as views
from ckanext.saml2auth.tests.test_blueprint_get_request import (
    _prepare_unsigned_response
)

here = os.path.dirname(os.path.abspath(__file__))
extras_folder = os.path.join(here, 'extras')


class _FakeSession(dict):
    """Plain dict subclass: Flask 3.1 sets ``session.accessed`` on every
    access, which a bare dict cannot take."""


class _FakeBeakerSession(_FakeSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.invalidated = 0

    def invalidate(self):
        self.clear()
        self.invalidated += 1


class _Interface(SessionInterface):
    def __init__(self, sess):
        self.sess = sess
        self.regenerated = 0

    def open_session(self, app, request):
        return self.sess

    def save_session(self, app, sess, response):
        pass


class _RegeneratingInterface(_Interface):
    """CKAN >= 2.10.11 BeakerSessionInterface."""
    def regenerate(self, sess):
        self.regenerated += 1
        sess.invalidate()


def _flask_app(interface):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-only'
    app.config['WTF_CSRF_FIELD_NAME'] = '_csrf_token'
    app.session_interface = interface
    return app


class TestRegenerateSessionHelper(object):

    def test_prefers_session_interface_regenerate(self):
        sess = _FakeBeakerSession({'pre_login': 'x'})
        app = _flask_app(_RegeneratingInterface(sess))
        with app.test_request_context('/acs', method='POST'):
            views._regenerate_session()
        assert app.session_interface.regenerated == 1
        assert 'pre_login' not in sess

    def test_falls_back_to_beaker_invalidate(self):
        sess = _FakeBeakerSession({'pre_login': 'x'})
        app = _flask_app(_Interface(sess))
        with app.test_request_context('/acs', method='POST'):
            views._regenerate_session()
        assert sess.invalidated == 1
        assert 'pre_login' not in sess

    def test_falls_back_to_clear_for_plain_sessions(self):
        sess = _FakeSession({'pre_login': 'x'})
        app = _flask_app(_Interface(sess))
        with app.test_request_context('/acs', method='POST'):
            views._regenerate_session()
        assert sess == {}


class TestRotateCsrfTokenHelper(object):

    def test_replaces_existing_token(self):
        sess = _FakeSession({'_csrf_token': 'old'})
        app = _flask_app(_Interface(sess))
        with app.test_request_context('/acs', method='POST'):
            views._rotate_csrf_token()
        assert sess['_csrf_token'] != 'old'

    def test_noop_without_token(self):
        sess = _FakeSession()
        app = _flask_app(_Interface(sess))
        with app.test_request_context('/acs', method='POST'):
            views._rotate_csrf_token()
        assert '_csrf_token' not in sess


@pytest.mark.skipif(
    not toolkit.check_ckan_version(min_version='2.10'),
    reason='session regeneration on login applies to the Flask-Login (2.10+) path')
@pytest.mark.usefixtures(u'clean_db', u'with_plugins')
@pytest.mark.ckan_config(u'ckan.plugins', u'saml2auth')
@pytest.mark.ckan_config(u'ckanext.saml2auth.entity_id', u'urn:gov:gsa:SAML:2.0.profiles:sp:sso:test:entity')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
@pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.local_path', os.path.join(extras_folder, 'provider0', 'idp.xml'))
@pytest.mark.ckan_config(u'ckanext.saml2auth.want_response_signed', u'False')
@pytest.mark.ckan_config(u'ckanext.saml2auth.want_assertions_signed', u'False')
@pytest.mark.ckan_config(u'ckanext.saml2auth.want_assertions_or_response_signed', u'False')
class TestAcsSessionFixation(object):

    def test_session_regenerated_before_login_and_token_rotated_after(self, app, monkeypatch):
        """The ACS view must regenerate the session *before* login_user()
        and rotate the CSRF token *after* it, mirroring CKAN core's login."""
        calls = []

        real_regenerate = views._regenerate_session
        real_rotate = views._rotate_csrf_token

        def spy_regenerate():
            calls.append(('regenerate', current_user.is_authenticated))
            real_regenerate()

        def spy_rotate():
            calls.append(('rotate', current_user.is_authenticated))
            real_rotate()

        monkeypatch.setattr(views, '_regenerate_session', spy_regenerate)
        monkeypatch.setattr(views, '_rotate_csrf_token', spy_rotate)

        response = app.post(
            url='/acs',
            params={'SAMLResponse': _prepare_unsigned_response()},
            follow_redirects=False)

        assert 302 == response.status_code
        assert calls == [('regenerate', False), ('rotate', True)]

    @pytest.mark.skipif(
        toolkit.check_ckan_version(min_version='2.11'),
        reason='server-side sessions (CKAN 2.11) keep their data on regenerate '
               'and only rotate the id; dropping data is Beaker cookie behaviour')
    def test_pre_login_session_state_does_not_survive_login(self, app, monkeypatch):
        """With Beaker cookie sessions (CKAN 2.10), regenerating starts an
        empty session, so nothing planted before the SAML round-trip
        survives login."""
        seen = {}

        real_regenerate = views._regenerate_session

        def plant_then_regenerate():
            session['planted_by_attacker'] = 'yes'
            real_regenerate()
            seen['after_regenerate'] = dict(session)

        monkeypatch.setattr(views, '_regenerate_session', plant_then_regenerate)

        response = app.post(
            url='/acs',
            params={'SAMLResponse': _prepare_unsigned_response()},
            follow_redirects=False)

        assert 302 == response.status_code
        assert 'planted_by_attacker' not in seen['after_regenerate']
