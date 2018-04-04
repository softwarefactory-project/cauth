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

from copy import deepcopy

from cauth.auth import base


"""Dummy plugins used for testing."""


class SpockAuth(base.AuthProtocolPlugin):
    _config_section = "spock"
    spock = {'login': 'Spock',
             'name': 'Mr Spock',
             'email': 'spock@uss.enterprise',
             'ssh_keys': [],
             'external_auth': {'domain': 'this_universe',
                               'external_id': '123'}, }
    domain = 'this_universe'

    def authenticate(self, **auth_context):
        return deepcopy(self.spock)

    def get_domain(self):
        return self.domain


class EvilSpockAuth(SpockAuth):
    _config_section = "evilspock"
    spock = {'login': 'Spock',
             'name': 'Mr Spock with a goatee',
             'email': 'spock@uss.enterprise',
             'ssh_keys': [],
             'external_auth': {'domain': 'goatee_universe',
                               'external_id': '321'}, }
    domain = 'goatee_universe'
