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
    _saml2_subject_id = get_name_id_value(subject_id)
    session['_saml2_subject_id'] = code(_saml2_subject_id)


def get_subject_id(session):
    try:
        return decode(session['_saml2_subject_id'])
    except KeyError:
        return None


def set_saml_session_info(session, saml_session_info):
    log.debug('Setting SAML session info in session: %s', saml_session_info)
    saml_session_info['name_id'] = get_name_id_value(saml_session_info['name_id'])
    session['_saml_session_info'] = saml_session_info


def get_saml_session_info(session):
    try:
        return session['_saml_session_info']
    except KeyError:
        return None


def get_name_id_value(name_id):
    """Extract the string value from a SAML NameID object.
    
    This function handles the extraction of the actual identifier value from
    potentially complex SAML NameID objects. This is necessary because:
    
    1. Flask session serialization cannot handle complex XML objects like NameID
    2. Only the text value is typically needed for identification purposes
    3. Different SAML libraries may return different object types for NameID
    4. The session must contain serializable data to prevent errors
    
    Args:
        name_id: A SAML NameID object or string
        
    Returns:
        str: The extracted identifier value as a string
    """
    log.debug('Extracting name_id: %s', name_id)
    if hasattr(name_id, 'text'):
        # Handle XML element objects that have a text attribute
        value = name_id.text
    else:
        # Fallback for other object types (including strings)
        value = str(name_id)
    log.debug('Extracted name_id value: %s', value)
    return value
