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
import logging

from saml2.ident import code, decode

log = logging.getLogger(__name__)


def set_subject_id(session, subject_id):
    log.debug('Setting subject_id in session: %s', subject_id)
    session['_saml2_subject_id'] = code(subject_id)
    log.debug('Encoded subject_id: %s', session['_saml2_subject_id'])


def get_subject_id(session):
    try:
        return decode(session['_saml2_subject_id'])
    except KeyError:
        return None


def set_saml_session_info(session, saml_session_info):
    log.debug('Setting SAML session info in session: %s', saml_session_info)
    saml_session_info['name_id'] = code(saml_session_info['name_id'])
    log.debug('Encoded name_id: %s', saml_session_info['name_id'])
    session['_saml_session_info'] = saml_session_info


def get_saml_session_info(session):
    try:
        log.debug('Retrieving SAML session info from session')
        saml_session_info = session['_saml_session_info']
        saml_session_info['name_id'] = decode(saml_session_info['name_id'])
        log.debug('Decoded name_id: %s', saml_session_info['name_id'])
        return saml_session_info
    except KeyError:
        return None
