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

from cauth.utils import transaction
from cauth.auth import base, oauth2


"""GitHub-based authentication plugins."""


class BaseGithubAuthPlugin(base.AuthProtocolPlugin):
    log = logging.getLogger("cauth.BaseGithubAuthPlugin")

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

    def organization_allowed(self, token, transactionID):
        allowed_orgs = self.conf.get('allowed_organizations')
        if allowed_orgs:
            resp = self.get_user_orgs(token, transactionID)
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

    log = logging.getLogger("cauth.GithubPersonalAccessTokenAuthPlugin")

    def get_user_orgs(self, token, transactionID):
        basic_auth = requests.auth.HTTPBasicAuth(token,
                                                 'x-oauth-basic')
        resp = requests.get("https://api.github.com/user/orgs",
                            auth=basic_auth)
        if not resp.ok:
            self.terror("Failed to get organizations: %s",
                        transactionID, resp)
        return resp

    @classmethod
    def get_args(cls):
        return {"token": {"description": "the user's personal API token"}}

    def authenticate(self, **auth_context):
        transactionID = transaction.ensure_tid(auth_context)
        token = auth_context.get('token', None)
        basic_auth = requests.auth.HTTPBasicAuth(token,
                                                 'x-oauth-basic')
        self.tdebug('Attempting basic auth against github server',
                    transactionID)
        try:
            resp = requests.get("https://api.github.com/user",
                                auth=basic_auth)
            if not resp.ok:
                self.terror('Failed to authenticate user: %s',
                            transactionID, resp)
            data = resp.json()

            ssh_keys = []
            if self.read_ssh_keys:
                resp = requests.get("https://api.github.com/user/keys",
                                    auth=basic_auth)
                if not resp.ok:
                    self.terror("Failed to get keys: %s", transactionID, resp)

                ssh_keys = resp.json()
        except Exception as e:
            self.terror("%s", transactionID, e.message)
            raise base.UnauthenticatedError(e.message)

        login = data.get('login')
        email = data.get('email')
        name = data.get('name')

        if not self.organization_allowed(token, transactionID):
            raise base.UnauthenticatedError("Organization not allowed")
        self.tinfo("Client %s (%s) authenticated with "
                   "Github Personal Access token", transactionID, login, email)
        return {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys,
                'external_auth': {'domain': self.get_domain(),
                                  'external_id': data.get('id') or login},
                'transactionID': transactionID}


class GithubAuthPlugin(BaseGithubAuthPlugin,
                       oauth2.BaseOAuth2Plugin):
    """Allows a Github user to authenticate with the OAuth protocol.
    """

    provider = "Github"

    access_token_url = 'https://github.com/login/oauth/access_token'
    log = logging.getLogger("cauth.GithubAuthPlugin")

    def get_user_orgs(self, token, transactionID):
        headers = {'Authorization': self.access_token_type + ' ' + token}
        resp = requests.get("https://api.github.com/user/orgs",
                            headers=headers)
        if not resp.ok:
            self.terror("Failed to get keys %s", transactionID, resp)
        return resp

    def get_error(self, **auth_context):
        """Parse the auth context returned by OAuth's first step."""
        error = auth_context.get('error', None)
        error_description = auth_context.get('error_description', None)
        return error, error_description

    def get_provider_id(self, user_data):
        """Return a provider-specific unique id from the user data."""
        return user_data.get('id') or user_data.get('login')

    def get_user_data(self, token, transactionID):

        self.tdebug("Querying github user API", transactionID)
        headers = {'Authorization': self.access_token_type + ' ' + token}
        resp = requests.get("https://api.github.com/user",
                            headers=headers)
        if not resp.ok:
            self.terror("Failed to fetch user info: %s",
                        transactionID, resp)
            raise base.UnauthenticatedError("Failed to fetch user info")
        data = resp.json()
        login = data.get('login')
        name = data.get('name')

        ssh_keys = []
        if self.read_ssh_keys:
            self.tdebug("Querying github SSH keys API", transactionID)
            resp = requests.get(
                "https://api.github.com/users/%s/keys" % login,
                headers=headers)
            if not resp.ok:
                self.terror("Failed to fetch user keys: %s",
                            transactionID, resp)
                raise base.UnauthenticatedError("Failed to fetch user keys")
            ssh_keys = resp.json()

        if not self.organization_allowed(token, transactionID):
            self.terror("Failed to fetch organization", transactionID)
            raise base.UnauthenticatedError("Organization not allowed")

        self.tdebug("Querying github SSH emails API", transactionID)
        resp = requests.get("https://api.github.com/user/emails",
                            headers=headers)
        if not resp.ok:
            self.terror("Failed to fetch emails: %s",
                        transactionID, resp)
            raise base.UnauthenticatedError("Failed to fetch emails")
        emails = resp.json()

        self.tdebug("fetched Emails: %s", transactionID, str(emails))
        # Get email from autorize response, just in case no primary is set
        email = data.get('email')
        for mail in emails:
            if mail.get('primary') is True:
                email = mail.get('email')
                break
        emails = [e['email'] for e in emails if e.get('verified')]

        self.tinfo("Client %s (%s) authenticated through Github",
                   transactionID, login, email)
        return {'login': login,
                'email': email,
                'emails': emails,
                'name': name,
                'ssh_keys': ssh_keys,
                'external_auth': {'domain': self.get_domain(),
                                  'external_id': self.get_provider_id(data)},
                'transactionID': transactionID}
