#!/usr/bin/env python
#
# Copyright (C) 2018 Red Hat
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
from urlparse import urlparse

from pecan import request
from pecan.core import redirect

from cauth.auth import base


logger = logging.getLogger(__name__)


class BaseHTTPdModuleAuthPlugin(base.AuthProtocolPlugin):

    """This authentication plugin expects the flow to be handled by a HTTPd
    module (for example mod_auth_mellon). The module sets environment
    variables, which this plugin turns into auth info to be consumed by
    cauth. The variables must be mapped to auth info values in the config
    file."""

    _config_section = "HTTPd_auth"

    @classmethod
    def get_args(cls):
        return {}

    def get_domain(self):
        domain = urlparse(request.environ['HTTP_REFERER'])
        return domain.netloc

    def authenticate(self, **auth_context):
        if 'endpoint_redirect' not in auth_context:
            redirect('%s' % (self._config_section))
        else:
            return self._authenticate()

    def _authenticate(self):
        transactionID = self.init_transactionID()
        transactionHeader = '[transaction ID: %s]' % transactionID
        mapping = self.conf['mapping']
        logger.debug(
            '%s environment variables: %s' % (transactionHeader,
                                              repr(request.environ)))
        try:
            username = request.environ[mapping['login']]
            email = request.environ[mapping['email']]
            fullname = request.environ[mapping['fullname']]
            external_id = request.environ[mapping['uid']]
        except KeyError as e:
            msg = '%s Invalid mapping data%s'
            logger.error(msg % (transactionHeader, ': %s' % e))
            raise base.UnauthenticatedError(msg % (transactionHeader, ''))
        ssh_keys = []
        if 'ssh_keys' in mapping.to_dict():
            idp_keys = request.environ[mapping['ssh_keys']]
            for key in idp_keys.split(self.conf.get('key_delimiter', ',')):
                ssh_keys.append({'key': key})
        logger.info(
            '%s %s successfully authenticated' % (transactionHeader,
                                                  username)
        )
        return {'login': username,
                'email': email,
                'name': fullname,
                'ssh_keys': ssh_keys,
                'external_auth': {'domain': self.get_domain(),
                                  'external_id': external_id}}


class SAML2AuthPlugin(BaseHTTPdModuleAuthPlugin):
    _config_section = "SAML2"
