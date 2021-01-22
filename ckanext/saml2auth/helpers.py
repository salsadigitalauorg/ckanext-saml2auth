# encoding: utf-8
import logging
import string
import secrets
from six import text_type

from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

import ckan.model as model
import ckan.authz as authz
from ckan.plugins.toolkit import config, asbool, aslist, get_action, get_converter

log = logging.getLogger(__name__)


def saml_client(config):
    sp_config = Saml2Config()
    sp_config.load(config)
    client = Saml2Client(config=sp_config)
    return client


def generate_password():
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(8))
    return password


def is_default_login_enabled():
    return asbool(
        config.get('ckanext.saml2auth.enable_ckan_internal_login',
                   False))


def update_user_sysadmin_status(username, email):
    sysadmins_list = aslist(
        config.get('ckanext.saml2auth.sysadmins_list'))
    user = model.User.by_name(text_type(username))
    sysadmin = authz.is_sysadmin(username)

    if sysadmin and email not in sysadmins_list:
        user.sysadmin = False
        model.Session.add(user)
        model.Session.commit()
    elif not sysadmin and email in sysadmins_list:
        user.sysadmin = True
        model.Session.add(user)
        model.Session.commit()


def activate_user_if_deleted(userobj):
    u'''Reactivates deleted user.'''
    if userobj.is_deleted():
        userobj.activate()
        userobj.commit()
        log.info(u'User {} reactivated'.format(userobj.name))


def get_organisation_mapping():
    return get_converter('json_or_string')(config.get('ckanext.saml2auth.organisation_mapping'))


def get_read_only_saml_groups():
    return aslist(config.get('ckanext.saml2auth.read_only_saml_groups'))


def saml_group_mapping_exist(saml_groups):
    organisation_mapping = get_organisation_mapping()
    read_only_saml_groups = get_read_only_saml_groups()
    if isinstance(saml_groups, list):
        # If saml_groups exist and there is either organisation_mapping or read_only_saml_groups config set up, check to see if any saml_groups exist
        # First check if organisation_mapping_exists, if this is false then check if read_only_saml_groups_exists
        organisation_mapping_exists = any(saml_group for saml_group in saml_groups if saml_group in organisation_mapping) if isinstance(organisation_mapping, dict) else False
        log.debug('organisation_mapping_exists: {0}'.format(organisation_mapping_exists))
        read_only_saml_groups_exists = any(saml_group for saml_group in saml_groups if saml_group in read_only_saml_groups) if isinstance(read_only_saml_groups, list) else False
        log.debug('read_only_saml_groups_exists: {0}'.format(read_only_saml_groups_exists))
        return organisation_mapping_exists or read_only_saml_groups_exists
    else:
        # There are no SAML groups to find mappings, return false to stop login workflow
        log.debug('No SAML groups')
        return False


def update_user_organasitions(user, saml_groups):
    context = {
        u'user': get_action('get_site_user')({'ignore_auth': True}, {})['name']
    }
    # Get organisations that the user has a permission for
    organisation_list_for_user = get_action('organization_list_for_user')(context, {"id": user})
    # Remove user's access from its current organisations, saml2 groups are the source of truth
    remove_user_from_all_organisations(context, organisation_list_for_user, user)
    # Load organisation_mapping config from CKAN.INI which will be in JSON format
    # The order of the organisation_mapping config values should be sorted with highest role priority mapping first
    organisation_mapping = get_organisation_mapping()
    log.debug('Using organisation_mapping: {0}'.format(organisation_mapping))

    if isinstance(organisation_mapping, dict) and isinstance(saml_groups, list):
        organisations_added = []
        for org_map in organisation_mapping:
            log.debug('Checking organisation_mapping: {0}'.format(org_map))
            if org_map in saml_groups:
                organisation = organisation_mapping[org_map]
                log.debug('SAML group found in organisation_mapping: {0}'.format(organisation))
                org_name = organisation.get('org_name', None)
                org_role = organisation.get('role', None)
                if org_name not in organisations_added and add_organisation_member(context, user, org_name, org_role):
                    # If adding organisation member was successful we add it to the list as only 1 (the highest) role is assigned per organisation
                    log.debug('Member role '{0}' was successfully added to organisation '{1}'.format(org_role, org_name))
                    organisations_added.append(org_name)


def remove_user_from_all_organisations(context, organisation_list_for_user, user):
    log.debug('Removing {0} from all its current organasition roles'.format(user))
    for organisation in organisation_list_for_user or []:
        remove_organisation_member(context, user, organisation.get('name'), organisation.get('capacity'))


def remove_organisation_member(context, user, org_name, role):
    member_dict = {
        'username': user,
        'id': org_name,
        'role': role,
    }
    log.debug('Removing {0} member role from organasation {1}'.format(user, member_dict))
    get_action('organization_member_delete')(context, member_dict)


def add_organisation_member(context, user, org_name, role):
    # Only add a saml role if org_name has a value and the role exist in ckan roles list
    if org_name != None and role in [role.get('value') for role in authz.roles_list()]:
        member_dict = {
            'username': user,
            'id': org_name,
            'role': role,
        }
        log.debug('Adding {0} member role to organasation: {1}'.format(user, member_dict))
        get_action('organization_member_create')(context, member_dict)
        return True
    else:
        log.debug('Role does not exist in roles list: {0}'.format(role))
        return False
