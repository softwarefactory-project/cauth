#!/usr/bin/env python
#
# Copyright (C) 2015 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import crypt
import ldap
import logging
import requests
import urllib

from basicauth import encode
try:
    import keystoneclient as kc
except ImportError:
    kc = None

from cauth.auth import base


"""password-based authentication plugins."""


logger = logging.getLogger(__name__)


class BasePasswordAuthPlugin(base.AuthProtocolPlugin):

    @classmethod
    def get_args(cls):
        return {'username': {'description': 'user login'},
                'password': {'description': 'user password'}}


class LocalUserAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using the cauth config file.
    """

    _config_section = "users"

    def authenticate(self, **auth_context):
        transactionID = auth_context.get(
            'transactionID',
            self.init_transactionID())
        transactionHeader = '[transaction ID: %s]' % transactionID
        username = auth_context.get('username', '')
        password = auth_context.get('password', '')
        user = self.conf.get(username)
        if user:
            salted_password = user.get('password')
            if salted_password == crypt.crypt(password, salted_password):
                return {'login': username,
                        'email': user.get('mail'),
                        'name': user.get('lastname'),
                        'ssh_keys': [],
                        'external_auth': {'domain': self.get_domain(),
                                          'external_id': username}}
        err = '%s %s not found in local config file' % (transactionHeader,
                                                        username)
        if getattr(self, 'standalone', True):
            logger.debug(err)
        raise base.UnauthenticatedError(err)

    def get_domain(self):
        return "CAUTH_CONF"


class LDAPAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using an LDAP backend.
    """

    _config_section = "ldap"

    def get_domain(self):
        return self.conf['host']

    def authenticate(self, **auth_context):
        transactionID = auth_context.get(
            'transactionID',
            self.init_transactionID())
        transactionHeader = '[transaction ID: %s]' % transactionID
        username = auth_context.get('username', '')
        password = auth_context.get('password', '')
        logger.debug(
            '%s Initializing LDAP connection' % transactionHeader
        )
        try:
            conn = ldap.initialize(self.conf['host'])
            conn.set_option(ldap.OPT_REFERRALS, 0)
        except ldap.LDAPError as e:
            msg = '%s Client unable to bind on LDAP%s'
            if getattr(self, 'standalone', True):
                logger.error(
                     msg % (transactionHeader, ': %s' % e.message))
            raise base.UnauthenticatedError(msg % (transactionHeader, ''))
        if not password or not username:
            msg = '%s Client unable to bind on LDAP empty credentials.'
            if getattr(self, 'standalone', True):
                logger.error(msg % transactionHeader)
            raise base.UnauthenticatedError(
                '%s empty credentials' % transactionHeader)
        who = self.conf['dn'] % {'username': username}
        logger.debug(
            '%s attempting LDAP binding' % transactionHeader
        )
        try:
            conn.simple_bind_s(who, password)
        except (ldap.INVALID_CREDENTIALS, ldap.SERVER_DOWN):
            msg = '%s Client unable to bind on LDAP due to invalid credentials'
            if getattr(self, 'standalone', True):
                logger.error(msg % transactionHeader)
            raise base.UnauthenticatedError(
                '%s invalid credentials' % transactionHeader)

        basedn = self.conf.get('basedn', who)
        sfilter = self.conf.get('sfilter', '(cn=*)') % {'username': username}
        result = conn.search_s(basedn, ldap.SCOPE_SUBTREE, sfilter,
                               attrlist=[self.conf['sn'], self.conf['mail']])
        if len(result) == 1:
            user = result[0]  # user is a tuple
            mail = user[1].get(self.conf['mail'], [None])
            lastname = user[1].get(self.conf['sn'], [None])
            return {'login': username,
                    'email': mail[0],
                    'name': lastname[0],
                    'ssh_keys': [],
                    'external_auth': {'domain': self.get_domain(),
                                      'external_id': who}}
        msg = '%s LDAP search returned %i result(s)'
        if getattr(self, 'standalone', True):
            logger.error(msg % (transactionHeader,
                                len(result)))
        raise base.UnauthenticatedError(msg % (transactionHeader,
                                               len(result)))


class ManageSFAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using the ManageSF local db backend.
    """

    _config_section = "localdb"

    def authenticate(self, **auth_context):
        transactionID = auth_context.get(
            'transactionID',
            self.init_transactionID())
        transactionHeader = '[transaction ID: %s]' % transactionID
        username = auth_context.get('username', '')
        password = auth_context.get('password', '')
        bind_url = urllib.basejoin(self.conf['managesf_url'], '/bind')
        headers = {"Authorization": encode(username.encode('utf8'),
                                           password.encode('utf8'))}
        logger.debug(
            '%s binding to manageSF' % transactionHeader
        )
        response = requests.get(bind_url, headers=headers)

        if response.status_code > 399:
            msg = '%s localdb auth failed%s'
            if getattr(self, 'standalone', True):
                logger.error(
                    msg % (transactionHeader,
                           'for user %s, reason: %s' % (username,
                                                        response.text))
                )
            raise base.UnauthenticatedError(msg % (transactionHeader, ''))
        infos = response.json()
        return {'login': username,
                'email': infos['email'],
                'name': infos['fullname'],
                'ssh_keys': [{'key': infos['sshkey']}, ],
                'external_auth': {'domain': self.get_domain(),
                                  # username is the primary key
                                  'external_id': username}}

    def get_domain(self):
        # Remove port number
        return ":".join(self.conf['managesf_url'].split(':')[:2])


class KeystoneAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using the ManageSF local db backend.
    """

    _config_section = "keystone"

    def get_domain(self):
        return self.conf['auth_url']

    def authenticate(self, **auth_context):
        """Authentication against a keystone server. We simply try to fetch an
        unscoped token."""
        transactionID = auth_context.get(
            'transactionID',
            self.init_transactionID())
        transactionHeader = '[transaction ID: %s]' % transactionID
        username = auth_context.get('username', '')
        password = auth_context.get('password', '')
        auth_url = self.conf['auth_url']
        if kc:
            logger.debug(
                '%s connecting to keystone server' % transactionHeader
            )
            try:
                client = kc.client.Client(auth_url=auth_url,
                                          username=username,
                                          password=password)
                if client.authenticate():
                    # TODO(mhu) keystone can store a user's e-mail, but with
                    # default keystone policies this info can only be fetched
                    # by an admin account. Either patch keystone to allow
                    # a user to fetch her own info, or add admin auth to this
                    # plugin in order to fetch the e-mail.
                    external_id = client.user_id or username
                    return {'login': username,
                            'email': '',
                            'name': username,
                            'ssh_keys': [],
                            'external_auth': {'domain': self.get_domain(),
                                              'external_id': external_id}}
            except kc.exceptions.Unauthorized:
                msg = ("%s keystone authentication failed: "
                       "Invalid user or password")
                logger.debug((msg % transactionHeader) +
                             (" for user %s" % username))
                raise base.UnauthenticatedError(msg % transactionHeader)
            except Exception as e:
                msg = "%s Unknown error%s"
                logger.debug(msg % (transactionHeader, ': %s' % e))
                raise base.UnauthenticatedError(
                     msg % (transactionHeader, ''))
        else:
            msg = "%s keystone authentication not available on this server"
            raise base.UnauthenticatedError(msg % transactionHeader)
        # every other case
        msg = ("%s keystone authentication failed")
        raise base.UnauthenticatedError(msg % transactionHeader)


class PasswordAuthPlugin(BasePasswordAuthPlugin):
    """Generic password authentication, using all the specific plugins.
    """

    _config_section = None

    def __init__(self, conf):
        self.plugins = []
        plugins_list = [LocalUserAuthPlugin,
                        LDAPAuthPlugin,
                        ManageSFAuthPlugin]
        if kc:
            plugins_list.append(KeystoneAuthPlugin)
        for plugin in plugins_list:
            try:
                pg_instance = plugin(conf)
                pg_instance.standalone = False
                self.plugins.append(pg_instance)
            except base.AuthProtocolNotAvailableError as e:
                logger.debug('Missing auth protocol, skipping: %s' % e)

    def configure_plugin(self, conf):
        pass

    def get_domain(self):
        pass

    def authenticate(self, **auth_context):
        username = auth_context.get('username')
        transactionID = self.init_transactionID()
        auth_context['transactionID'] = transactionID
        if not username:
            raise base.UnauthenticatedError(
                '[transaction ID: %s] No username provided' % transactionID)
        user = None
        errors = []
        for plugin in self.plugins:
            try:
                user = plugin.authenticate(**auth_context)
            except base.UnauthenticatedError as e:
                errors.append(e)
        if user:
            return user
        msg = ('[transaction ID: %s] Password authentication '
               'failed for user %s: ')
        msg += '--'.join(errors)
        logger.info(
            msg % (transactionID, username))
        raise base.UnauthenticatedError('Password authentication failed')
