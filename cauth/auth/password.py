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
from cauth.utils import transaction


"""password-based authentication plugins."""


class BasePasswordAuthPlugin(base.AuthProtocolPlugin):

    log = logging.getLogger("cauth.BasePasswordAuthPlugin")

    @classmethod
    def get_args(cls):
        return {'username': {'description': 'user login'},
                'password': {'description': 'user password'}}


class LocalUserAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using the cauth config file.
    """

    _config_section = "users"
    log = logging.getLogger("cauth.LocalUserAuthPlugin")

    def authenticate(self, **auth_context):
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
            else:
                raise base.UnauthenticatedError("Bad password")
        raise base.UnauthenticatedError("User not found")

    def get_domain(self):
        return "CAUTH_CONF"


class LDAPAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using an LDAP backend.
    """

    _config_section = "ldap"
    log = logging.getLogger("cauth.LDAPAuthPlugin")

    def get_domain(self):
        return self.conf['host']

    def authenticate(self, **auth_context):
        transactionID = transaction.ensure_tid(auth_context)
        username = auth_context.get('username', '')
        password = auth_context.get('password', '')
        self.tdebug("Initializing LDAP connection", transactionID)
        try:
            conn = ldap.initialize(self.conf['host'])
            conn.set_option(ldap.OPT_REFERRALS, 0)
        except ldap.LDAPError as e:
            if getattr(self, 'standalone', True):
                self.terror("Client unable to bind on LDAP: %s",
                            transactionID, e.message)
            raise base.UnauthenticatedError("LDAP error")
        if not password or not username:
            if getattr(self, 'standalone', True):
                self.terror("Client unable to bind on LDAP empty credentials",
                            transactionID)
            raise base.UnauthenticatedError("LDAP error")
        who = self.conf['dn'] % {'username': username}
        self.tdebug("attempting LDAP binding", transactionID)
        try:
            conn.simple_bind_s(who, password)
        except (ldap.INVALID_CREDENTIALS, ldap.SERVER_DOWN):
            if getattr(self, 'standalone', True):
                self.terror("Client unable to bind due to invalid credentials",
                            transactionID)
            raise base.UnauthenticatedError("LDAP error")

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
        if getattr(self, 'standalone', True):
            self.terror("LDAP search returned %i result(s)",
                        transactionID, len(result))
        raise base.UnauthenticatedError("Unauthorized")


class ManageSFAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using the ManageSF local db backend.
    """

    _config_section = "localdb"
    log = logging.getLogger("cauth.ManageSFAuthPlugin")

    def authenticate(self, **auth_context):
        transactionID = transaction.ensure_tid(auth_context)
        username = auth_context.get('username', '')
        password = auth_context.get('password', '')
        bind_url = urllib.basejoin(self.conf['managesf_url'], '/bind')
        headers = {"Authorization": encode(username.encode('utf8'),
                                           password.encode('utf8'))}
        self.tdebug("Binding to managesf", transactionID)
        response = requests.get(bind_url, headers=headers)

        if response.status_code > 399:
            self.tdebug("localdb auth failed for user %s, reason: %s",
                        transactionID, username, response.status_code)
            raise base.UnauthenticatedError(
                "Unauthorized, %d" % response.status_code)
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
    log = logging.getLogger("cauth.KeystoneAuthPlugin")

    def get_domain(self):
        return self.conf['auth_url']

    def authenticate(self, **auth_context):
        """Authentication against a keystone server. We simply try to fetch an
        unscoped token."""
        transactionID = transaction.ensure_tid(auth_context)
        username = auth_context.get('username', '')
        password = auth_context.get('password', '')
        auth_url = self.conf['auth_url']
        if kc:
            self.tdebug('Connecting to keystone server', transactionID)
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
                self.terror("keystone authentication failed for user %s",
                            transactionID, username)
                raise base.UnauthenticatedError("Unauthorized")
            except Exception:
                self.texception("Unknown error", transactionID)
                raise base.UnauthenticatedError("Unauthorized")
        else:
            msg = "keystone authentication not available on this server"
            raise base.UnauthenticatedError(msg)
        # every other case
        raise base.UnauthenticatedError("Unauthorized")


class PasswordAuthPlugin(BasePasswordAuthPlugin):
    """Generic password authentication, using all the specific plugins.
    """

    _config_section = None
    log = logging.getLogger("cauth.PasswordAuthPlugin")
    name = "password"

    def __init__(self, conf):
        self.plugins = []
        plugins_list = [LocalUserAuthPlugin,
                        ManageSFAuthPlugin,
                        LDAPAuthPlugin]
        if kc:
            plugins_list.append(KeystoneAuthPlugin)
        for plugin in plugins_list:
            try:
                pg_instance = plugin(conf)
                pg_instance.standalone = False
                self.plugins.append(pg_instance)
            except base.AuthProtocolNotAvailableError:
                # Just skip unavailable protocols
                pass

    def configure_plugin(self, conf):
        pass

    def get_domain(self):
        pass

    def authenticate(self, **auth_context):
        username = auth_context.get('username')
        transactionID = transaction.ensure_tid(auth_context)
        if not username:
            raise base.UnauthenticatedError("Unauthorized")
        user = None
        errors = []
        for plugin in self.plugins:
            try:
                user = plugin.authenticate(**auth_context)
            except base.UnauthenticatedError as e:
                errors.append("[%s: %s]" % (plugin.name, e.message))
        if user:
            user['transactionID'] = transactionID
            return user
        self.tinfo("Password authentication failed for user %s: %s",
                   transactionID, username, ", ".join(errors))
        raise base.UnauthenticatedError('Password authentication failed')
