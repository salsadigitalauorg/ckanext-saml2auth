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


def encode_value(value):
    """
    Encode a value if it's not already encoded
    """
    try:
        # Try to decode the value - if it succeeds, it's already encoded
        decode(value)
        # Return the original value since it's already encoded
        log.debug(f'{value} was already encoded')
        return value
    except Exception:
        # If decoding fails, it's not encoded yet, so encode it
        log.debug(f'{value} was encoded')
        return code(value)


def decode_value(value):
    """
    Decode a value if it's encoded, otherwise return as is
    """
    if value is None:
        return None
    try:
        # Try to decode the value
        decoded = decode(value)
        log.debug(f'{value} was decoded')
        return decoded
    except Exception:
        # If decoding fails, it's not encoded, return as is
        log.debug(f'{value} was not encoded')
        return value


def set_subject_id(session, subject_id):
    session['_saml2_subject_id'] = encode_value(subject_id)


def get_subject_id(session):
    try:
        return decode_value(session['_saml2_subject_id'])
    except KeyError:
        return None


def set_saml_session_info(session, saml_session_info):
    saml_session_info['name_id'] = encode_value(saml_session_info['name_id'])
    session['_saml_session_info'] = saml_session_info


def get_saml_session_info(session):
    try:
        saml_session_info = session['_saml_session_info']
        saml_session_info['name_id'] = decode_value(saml_session_info['name_id'])
        return saml_session_info
    except KeyError:
        return None
