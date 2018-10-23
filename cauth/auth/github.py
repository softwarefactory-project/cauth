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


import logging
import requests

from cauth.auth import base, oauth2


"""GitHub-based authentication plugins."""


logger = logging.getLogger(__name__)


class BaseGithubAuthPlugin(base.AuthProtocolPlugin):

    _config_section = "github"
    auth_url = 'https://github.com/login/oauth/authorize'

    def __init__(self, conf):
        super(BaseGithubAuthPlugin, self).__init__(conf)
        self.read_ssh_keys = self.conf.get('read_ssh_keys', True)
        self.scope = 'user:email'
        if self.read_ssh_keys:
            self.scope += ', read:public_key'
        if self.conf.get('allowed_organizations'):
            self.scope += ', read:org'

    def organization_allowed(self, token):
        allowed_orgs = self.conf.get('allowed_organizations')
        if allowed_orgs:
            resp = self.get_user_orgs(token)
            user_orgs = resp.json()
            user_orgs = [org['login'] for org in user_orgs]

            allowed_orgs = allowed_orgs.split(',')
            allowed_orgs = filter(None, allowed_orgs)
            allowed = set(user_orgs) & set(allowed_orgs)
            if not allowed:
                return False
        return True

    def get_domain(self):
        return self.auth_url


class GithubPersonalAccessTokenAuthPlugin(BaseGithubAuthPlugin):
    """Allows a github user to authenticate with a personal access token,
    see https://github.com/blog/1509-personal-api-tokens and make sure the
    token has at least the following rights:
    'user:email, read:public_key, read:org'
    """

    def get_user_orgs(self, token, transactionHeader=None):
        basic_auth = requests.auth.HTTPBasicAuth(token,
                                                 'x-oauth-basic')
        resp = requests.get("https://api.github.com/user/orgs",
                            auth=basic_auth)
        if not resp.ok:
            msg = '%s Failed to get organizations' % transactionHeader
            logger.error(msg, resp)
        return resp

    @classmethod
    def get_args(cls):
        return {"token": {"description": "the user's personal API token"}}

    def authenticate(self, **auth_context):
        transactionID = self.init_transactionID()
        transactionHeader = '[transaction ID: %s]' % transactionID
        token = auth_context.get('token', None)
        basic_auth = requests.auth.HTTPBasicAuth(token,
                                                 'x-oauth-basic')
        msg = '%s Attempting basic auth against github server'
        logger.debug(msg % transactionHeader)
        try:
            resp = requests.get("https://api.github.com/user",
                                auth=basic_auth)
            if not resp.ok:
                msg = '%s Failed to authenticate user: %s'
                logger.error(msg, (transactionHeader, resp))
            data = resp.json()

            ssh_keys = []
            if self.read_ssh_keys:
                resp = requests.get("https://api.github.com/user/keys",
                                    auth=basic_auth)
                if not resp.ok:
                    msg = '%s Failed to get keys: %s'
                    logger.error(msg, (transactionHeader, resp))

                ssh_keys = resp.json()
        except Exception as e:
            logger.error('%s: %s' (transactionHeader, e.message))
            raise base.UnauthenticatedError('%s: %s' (transactionHeader,
                                                      e.message))

        login = data.get('login')
        email = data.get('email')
        name = data.get('name')

        if not self.organization_allowed(token):
            raise base.UnauthenticatedError(
                "%s Organization not allowed" % transactionHeader)
        msg = ('%s Client %s (%s) authenticated with '
               'Github Personal Access token')
        logger.info(msg % (transactionHeader, login, email))
        return {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys,
                'external_auth': {'domain': self.get_domain(),
                                  'external_id': data.get('id') or login}}


class GithubAuthPlugin(BaseGithubAuthPlugin,
                       oauth2.BaseOAuth2Plugin):
    """Allows a Github user to authenticate with the OAuth protocol.
    """

    provider = "Github"

    access_token_url = 'https://github.com/login/oauth/access_token'

    def get_user_orgs(self, token, transactionHeader=None):
        headers = {'Authorization': self.access_token_type + ' ' + token}
        resp = requests.get("https://api.github.com/user/orgs",
                            headers=headers)
        if not resp.ok:
            logger.error('%s Failed to get keys', (transactionHeader, resp))
        return resp

    def get_error(self, **auth_context):
        """Parse the auth context returned by OAuth's first step."""
        error = auth_context.get('error', None)
        error_description = auth_context.get('error_description', None)
        return error, error_description

    def get_provider_id(self, user_data):
        """Return a provider-specific unique id from the user data."""
        return user_data.get('id') or user_data.get('login')

    def get_user_data(self, token, transactionHeader=None):

        logger.debug(
            '%s Querying github user API' % transactionHeader
        )
        headers = {'Authorization': self.access_token_type + ' ' + token}
        resp = requests.get("https://api.github.com/user",
                            headers=headers)
        if not resp.ok:
            msg = '%s Failed to fetch user info%s'
            logger.error(msg % (transactionHeader, ' :%s' % resp))
            raise base.UnauthenticatedError(msg % (transactionHeader, ''))
        data = resp.json()
        login = data.get('login')
        name = data.get('name')

        ssh_keys = []
        if self.read_ssh_keys:
            logger.debug(
                '%s Querying github SSH keys API' % transactionHeader
            )
            resp = requests.get(
                "https://api.github.com/users/%s/keys" % login,
                headers=headers)
            if not resp.ok:
                msg = '%s Failed to fetch user keys%s'
                logger.error(msg % (transactionHeader, ' :%s' % resp))
                raise base.UnauthenticatedError(msg % (transactionHeader, ''))
            ssh_keys = resp.json()

        if not self.organization_allowed(token):
            raise base.UnauthenticatedError(
                "%s Organization not allowed" % transactionHeader)

        logger.debug(
            '%s Querying github SSH emails API' % transactionHeader
        )
        resp = requests.get("https://api.github.com/user/emails",
                            headers=headers)
        if not resp.ok:
            msg = '%s Failed to fetch emails%s'
            logger.error(msg % (transactionHeader, ' :%s' % resp))
            raise base.UnauthenticatedError(msg % (transactionHeader, ''))
        emails = resp.json()

        logger.debug(
            "%s fetched Emails: %s" % (transactionHeader, str(emails)))
        # Get email from autorize response, just in case no primary is set
        email = data.get('email')
        for mail in emails:
            if mail.get('primary') is True:
                email = mail.get('email')
                break
        emails = [e['email'] for e in emails if e.get('verified')]

        logger.info(
            '%s Client %s (%s) authenticated through Github'
            % (transactionHeader, login, email))
        return {'login': login,
                'email': email,
                'emails': emails,
                'name': name,
                'ssh_keys': ssh_keys,
                'external_auth': {'domain': self.get_domain(),
                                  'external_id': self.get_provider_id(data)}}
