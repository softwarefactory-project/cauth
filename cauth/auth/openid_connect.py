#!/usr/bin/env python
#
# Copyright (C) 2016 Red Hat
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
from pecan import request
from oic.oic import Client
from oic.oic.message import AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from cauth.auth import base
from cauth.model import db

"""OpenID Connect authentication plugin."""


logger = logging.getLogger(__name__)


DEFAULT_FIELD_MAPPING = {'login': 'email',  # if email is used, remove @...
                         'email': 'email',
                         'name': 'name',
                         'uid': 'sub',
                         'ssh_keys': None}


class OpenIDConnectAuthPlugin(base.AuthProtocolPlugin):

    _config_section = "openid_connect"

    provider_config = None

    @classmethod
    def get_args(cls):
        return {}

    def get_domain(self):
        return self.conf['issuer_url']

    def _get_client(self):
        client = Client(client_id=self.conf['client_id'],
                        client_authn_method=CLIENT_AUTHN_METHOD)
        # Set client configurations based on issuer_url
        if not OpenIDConnectAuthPlugin.provider_config:
            OpenIDConnectAuthPlugin.provider_config = client.provider_config(
                self.conf['issuer_url'])
        else:
            client.handle_provider_config(
                OpenIDConnectAuthPlugin.provider_config,
                self.conf['issuer_url'])
        return client

    def _redirect(self, back, response):
        """Send the user to the OpenID Connect auth page"""
        state = db.put_url(back, "openid_connect")
        # use this as the seed for the transaction ID
        transactionID = self.init_transactionID(hashable=str(state))
        transactionHeader = '[transaction ID: %s]' % transactionID
        client = self._get_client()
        response.status_code = 302
        response.location = client.construct_AuthorizationRequest(
            request_args={
                "response_type": ["code"],
                "response_mode": "query",
                "state": state,
                "redirect_uri": self.conf["redirect_uri"],
                "scope": ["openid", "profile"],
                "client_id": self.conf["client_id"],
            }).request(client.authorization_endpoint)
        logger.debug("%s Redirecting to %s" % (transactionHeader,
                                               response.location))

    def _authenticate(self, state, code, query_string):
        """Validate callback code and retrieve user info"""
        transactionID = self.init_transactionID(hashable=str(state))
        transactionHeader = '[transaction ID: %s]' % transactionID
        if not code:
            msg = '%s Invalid OAuth code' % transactionHeader
            logger.error(msg)
            raise base.UnauthenticatedError(msg)

        # Check query_string
        client = self._get_client()
        try:
            client.parse_response(AuthorizationResponse,
                                  info=query_string,
                                  sformat="urlencoded")
        except Exception as e:
            msg = "%s Couldn't parse callback response (%s)"
            logger.error(msg % (transactionHeader, repr(e)))
            logger.debug("%s QueryString error '%s'" % (transactionHeader,
                                                        query_string))
            raise base.UnauthenticatedError(
                '%s Invalid callback query string' % transactionHeader)

        # Request token
        try:
            token = client.do_access_token_request(
                scope="openid",
                state=state,
                authn_method="client_secret_post",
                request_args={
                    "code": code,
                    "redirect_uri": self.conf["redirect_uri"],
                    "client_id": self.conf["client_id"],
                    "client_secret": self.conf["client_secret"],
                }
            )
        except Exception as e:
            msg = "%s Couldn't obtain user token (%s)"
            logger.error(msg % (transactionHeader, repr(e)))
            raise base.UnauthenticatedError(
                '%s Couldn\'t fetch user-info' % transactionHeader)

        user_info = token.to_dict().get("id_token")
        if not isinstance(user_info, dict):
            user_info = {}

        field_mapping = self.conf.get('mapping', DEFAULT_FIELD_MAPPING)

        login = user_info.get(field_mapping.get('login'))
        if field_mapping.get('login') == 'email':
            login = login.split('@')[0]
        email = user_info.get(field_mapping.get('email'))
        name = user_info.get(field_mapping.get('name'))
        uid = user_info.get(field_mapping.get('uid'))
        ssh_keys = user_info.get(field_mapping.get('ssh_keys'), [])
        if not login or not email or '@' not in email or not name or not uid:
            logger.error(
                "%s Invalid user token or mapping" % transactionHeader)
            logger.debug(
                "%s User token error '%s'" % (transactionHeader,
                                              user_info))
            raise base.UnauthenticatedError(
                '%s Couldn\'t decode token' % transactionHeader)

        # All the user info we need are in the token, no need to request more
        # info = client.do_user_info_request(token = token["access_token"])

        return {
            'login': login,
            'email': email,
            'name': name,
            'ssh_keys': ssh_keys,
            'external_auth': {'domain': self.get_domain(),
                              'external_id': uid}}

    def authenticate(self, **context):
        if context.get('calling_back', False):
            state = context["state"]
            transactionID = self.init_transactionID(hashable=str(state))
            transactionHeader = '[transaction ID: %s]' % transactionID
            logger.debug(
                '%s Incoming callback from %s' % (transactionHeader,
                                                  self.get_domain())
            )
            return self._authenticate(
                state,
                context.get("code"),
                request.query_string)
        else:
            self._redirect(context['back'], context['response'])
