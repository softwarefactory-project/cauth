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


import abc
import six

from cauth.utils.transaction import TransactionLogger


class AuthProtocolNotAvailableError(Exception):
    pass


class UnauthenticatedError(Exception):
    pass


@six.add_metaclass(abc.ABCMeta)
class AuthProtocolPlugin(TransactionLogger):
    """Base plugin for authentication protocols.
    """
    _config_section = "base"

    def __init__(self, conf):
        try:
            self.configure_plugin(conf.auth)
        except AttributeError:
            raise Exception(repr(conf))

    def configure_plugin(self, conf):
        try:
            self.conf = conf[self._config_section]
            self.name = self._config_section
        except KeyError:
            msg = ("The %s authentication protocol "
                   "is not available" % self._config_section)
            raise AuthProtocolNotAvailableError(msg)

    @classmethod
    def get_args(cls):
        """Get a dictionary of arguments expected by the plugin.
        :returns: {'arg1': {'description': 'my fancy argument'},
                   'arg2': {'description': 'my other fancy argument'}}"""

    @abc.abstractmethod
    def authenticate(self, **auth_context):
        """authenticate the user for the given auth protocol.
        :param auth_context: the authentication context
        :returns: a dictionary with the user's information:
               {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys,
                'external_auth': {'domain': domain,
                                  'external_id': external_id}}
        :raises: UnauthenticatedError
        """

    @abc.abstractmethod
    def get_domain(self):
        """returns a conf value specific to the authentication method acting
        as a namespace. Typically, it will be return the configured
        authentication endpoint url."""
