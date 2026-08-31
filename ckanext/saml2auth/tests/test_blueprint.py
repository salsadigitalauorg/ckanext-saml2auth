# encoding: utf-8

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

from ckan.plugins.toolkit import url_for

here = os.path.dirname(os.path.abspath(__file__))
extras_folder = os.path.join(here, 'extras')


@pytest.mark.usefixtures(u'clean_db', u'clean_index')
@pytest.mark.ckan_config(u'ckan.plugins', u'saml2auth')
class TestBlueprint(object):

    def test_user_register_disabled_by_default(self, app):
        url = url_for(u'user.register')
        response = app.get(url=url)
        assert 403 == response.status_code

        assert u'This resource is forbidden' \
               u' by the system administrator. ' \
               u'Only SSO through SAML2 authorization ' \
               u'is available at this moment.' in response

    def test_internal_user_login_disabled_by_deafult(self, app):
        url = url_for(u'user.login')
        response = app.get(url=url)
        assert 403 == response.status_code

        assert u'This resource is forbidden' \
               u' by the system administrator. ' \
               u'Only SSO through SAML2 authorization ' \
               u'is available at this moment.' in response

    @pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.local_path',
                             os.path.join(extras_folder, 'provider2', 'idp.xml'))
    def test_came_from_sent_as_relay_state(self, app):

        url = url_for('saml2auth.saml2login', came_from='/dataset/my-dataset')

        response = app.get(url=url, follow_redirects=False)
        assert 'RelayState=%2Fdataset%2Fmy-dataset' in response.headers['Location']

    @pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.location', u'local')
    @pytest.mark.ckan_config(u'ckanext.saml2auth.idp_metadata.local_path',
                             os.path.join(extras_folder, 'provider2', 'idp.xml'))
    @pytest.mark.ckan_config(u'ckanext.saml2auth.enable_ckan_internal_login',
                             True)
    def test_ckan_cookie_cleared_on_slo(self, app):

        from unittest import mock
        from http.cookies import SimpleCookie
        from flask import make_response
        import ckan.tests.factories as factories

        password = u'RandomPassword123'
        user = factories.User(password=password)

        # One client for the whole flow. app.get() and app.post() each build
        # a new test client, so cookies would not carry between requests.
        client = app.test_client()
        client.post(url_for(u'user.login'),
                    data={u'login': user[u'name'], u'password': password})

        # Confirm the session authenticates before logging out, otherwise
        # the assertions below would pass on a session that never existed.
        before = client.get(u'/dashboard/datasets', follow_redirects=False)
        assert before.status_code == 200

        # side_effect rather than return_value: make_response() needs an
        # application context, which only exists once the request is handled.
        with mock.patch('ckanext.saml2auth.plugin._perform_slo',
                        side_effect=lambda: make_response('')):
            response = client.get(url_for(u'user.logout'),
                                  follow_redirects=False)

        ckan_cookies = []
        for header in [h[1] for h in response.headers
                       if h[0].lower() == 'set-cookie']:
            cookie = SimpleCookie()
            cookie.load(header)
            ckan_cookies.extend(
                morsel for name, morsel in cookie.items() if name == 'ckan')

        # Exactly one. Two 'ckan' headers scoped differently is what #107
        # reports, where the one the browser held was not the one cleared.
        assert len(ckan_cookies) == 1

        # The session must no longer authenticate. Asserting this rather
        # than the shape of the cookie, because the two supported CKAN
        # versions clear it by different means: 2.11 expires the Flask
        # session cookie, while on 2.10 Beaker replaces it with a fresh
        # cookie holding an empty session, so there is no expiry to assert.
        after = client.get(u'/dashboard/datasets', follow_redirects=False)
        assert after.status_code == 302
        assert 'user/login' in after.headers['Location']
