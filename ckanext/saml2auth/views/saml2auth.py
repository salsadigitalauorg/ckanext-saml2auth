# encoding: utf-8
from flask import Blueprint
from saml2 import entity

import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.logic as logic
import ckan.lib.dictization.model_dictize as model_dictize
from ckan.lib import base
from ckan.views.user import set_repoze_user
from ckan.logic.action.create import _get_random_username_from_email
from ckan.common import config, g, request

from ckanext.saml2auth.spconfig import get_config as sp_config
from ckanext.saml2auth import helpers as h

import logging

log = logging.getLogger(__name__)

saml2auth = Blueprint(u'saml2auth', __name__)


def acs():
    u'''The location where the SAML assertion is sent with a HTTP POST.
    This is often referred to as the SAML Assertion Consumer Service (ACS) URL.
    '''
    g.user = None
    g.userobj = None

    context = {
        u'ignore_auth': True,
        u'keep_email': True,
        u'model': model
    }

    saml_user_firstname = \
        config.get(u'ckanext.saml2auth.user_firstname')
    saml_user_lastname = \
        config.get(u'ckanext.saml2auth.user_lastname')
    saml_user_email = \
        config.get(u'ckanext.saml2auth.user_email')
    saml_user_group = \
        config.get(u'ckanext.saml2auth.user_group', None)
    saml_sysadmin_group = \
        config.get(u'ckanext.saml2auth.saml_sysadmin_group', None)

    client = h.saml_client(sp_config())
    auth_response = client.parse_authn_request_response(
        request.form.get(u'SAMLResponse', None),
        entity.BINDING_HTTP_POST)
    auth_response.get_identity()
    user_info = auth_response.get_subject()

    # SAML username - unique
    saml_id = user_info.text

    # @TODO: Remove - for debug only
    log.error('>>>>> auth_response.ava <<<<<')
    log.error('>>>>> auth_response.ava <<<<<')
    log.error(auth_response.ava)
    log.error('>>>>> auth_response.ava <<<<<')
    log.error('>>>>> auth_response.ava <<<<<')

    # Required user attributes for user creation
    email = auth_response.ava[saml_user_email][0]
    firstname = auth_response.ava[saml_user_firstname][0]
    lastname = auth_response.ava[saml_user_lastname][0]
    groups = None
    in_saml_sysadmin_group = False
    # If saml_user_group is configured, user cannot login with out a successful SAML group mapping to either organisation_mapping or read_only_saml_groups
    if saml_user_group:
        # groups = ['CG-FED-DDCAT-SDK-Read', 'CG-FED-DDCAT-SDK-ED1']
        groups = auth_response.ava.get(saml_user_group, [])
        log.debug('Looking for SAML group with value: {}'.format(saml_user_group))
        log.debug('SAML groups found: {}'.format(groups))
        # If saml group does not exist in config for organisation_mapping or read_only_saml_groups, do not create/update/login in user
        # If there is not configuration set up for config for organisation_mapping or read_only_saml_groups, it will return True to carry on login workflow
        if saml_sysadmin_group and saml_sysadmin_group in groups:
            in_saml_sysadmin_group = True
            groups = None
        elif not h.saml_group_mapping_exist(groups):
            log.warning('User {0} {1} groups {2} does not exists'.format(firstname, lastname, groups))
            return toolkit.h.redirect_to('saml2auth.unauthorised', firstName=firstname, lastName=lastname, email=email)

    # Check if CKAN-SAML user exists for the current SAML login
    saml_user = model.Session.query(model.User) \
        .filter(model.User.plugin_extras[(u'saml2auth', u'saml_id')].astext == saml_id) \
        .first()

    # First we check if there is a SAML-CKAN user
    if not saml_user:
        # If there is no SAML user but there is a regular CKAN
        # user with the same email as the current login,
        # make that user a SAML-CKAN user and change
        # it's pass so the user can use only SSO
        ckan_user = model.User.by_email(email)
        if ckan_user:
            # If account exists and is deleted, reactivate it.
            h.activate_user_if_deleted(ckan_user[0])

            ckan_user_dict = model_dictize.user_dictize(ckan_user[0], context)
            try:
                ckan_user_dict[u'password'] = h.generate_password()
                ckan_user_dict[u'plugin_extras'] = {
                    u'saml2auth': {
                        # Store the saml username
                        # in the corresponding CKAN user
                        u'saml_id': saml_id
                    }
                }
                g.user = logic.get_action(u'user_update')(context, ckan_user_dict)[u'name']
            except logic.ValidationError as e:
                error_message = (e.error_summary or e.message or e.error_dict)
                base.abort(400, error_message)
        else:
            data_dict = {u'name': _get_random_username_from_email(email),
                         u'fullname': u'{0} {1}'.format(firstname, lastname),
                         u'email': email,
                         u'password': h.generate_password(),
                         u'plugin_extras': {
                             u'saml2auth': {
                                 # Store the saml username
                                 # in the corresponding CKAN user
                                 u'saml_id': saml_id
                             }
                         }}
            try:
                g.user = logic.get_action(u'user_create')(context, data_dict)[u'name']
            except logic.ValidationError as e:
                error_message = (e.error_summary or e.message or e.error_dict)
                base.abort(400, error_message)

    else:
        # If account exists and is deleted, reactivate it.
        h.activate_user_if_deleted(saml_user)

        user_dict = model_dictize.user_dictize(saml_user, context)
        # Update the existing CKAN-SAML user only if
        # SAML user name or SAML user email are changed
        # in the identity provider
        if email != user_dict['email'] \
                or u'{0} {1}'.format(firstname, lastname) != user_dict['fullname']:
            user_dict['email'] = email
            user_dict['fullname'] = u'{0} {1}'.format(firstname, lastname)
            try:
                user_dict = logic.get_action(u'user_update')(context, user_dict)
            except logic.ValidationError as e:
                error_message = (e.error_summary or e.message or e.error_dict)
                base.abort(400, error_message)
        g.user = user_dict['name']

    if saml_user_group:
        h.update_user_organasitions(g.user, groups)

    # If user email is in given list of emails
    # make that user sysadmin and opposite
    h.update_user_sysadmin_status(g.user, email, in_saml_sysadmin_group)

    g.userobj = model.User.by_name(g.user)
    # log the user in programmatically
    resp = toolkit.redirect_to(u'user.me')
    set_repoze_user(g.user, resp)
    return resp


def saml2login():
    u'''Redirects the user to the
     configured identity provider for authentication
    '''
    client = h.saml_client(sp_config())
    reqid, info = client.prepare_for_authenticate()

    redirect_url = None
    for key, value in info[u'headers']:
        if key == u'Location':
            redirect_url = value
    return toolkit.redirect_to(redirect_url)


def disable_default_login_register():
    u'''View function used to
    override and disable default Register/Login routes
    '''
    extra_vars = {u'code': [403], u'content': u'This resource is forbidden '
                                              u'by the system administrator. '
                                              u'Only SSO through SAML2 authorization'
                                              u' is available at this moment.'}
    return base.render(u'error_document_template.html', extra_vars), 403


def unauthorised():
    firstName = request.params.get('firstName', None)
    lastName = request.params.get('lastName', None)
    email = request.params.get('email', None)
    extra_vars = {
        u'code': [403],
        u'name': u'Not Authorised', 
        u'content': u' User {0} {1} with email {2} is not a member of any authenticated AD group'.format(firstName, lastName, email)
    }
    return base.render(u'error_document_template.html', extra_vars)


saml2auth.add_url_rule(u'/acs', view_func=acs, methods=[u'GET', u'POST'])
saml2auth.add_url_rule(u'/user/saml2login', view_func=saml2login)
saml2auth.add_url_rule(u'/user/unauthorised', view_func=unauthorised)

if not h.is_default_login_enabled():
    saml2auth.add_url_rule(
        u'/user/login', view_func=disable_default_login_register)
    saml2auth.add_url_rule(
        u'/user/register', view_func=disable_default_login_register)
