#!/usr/bin/env python
#
# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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

import hashlib
import logging

from stevedore import driver
from pecan import conf

from cauth.service import base
from cauth.model import db as auth_map
from cauth.utils import exceptions


logger = logging.getLogger(__name__)


def differentiate(login, domain, uid):
    suffix = hashlib.sha1((domain + '/' + str(uid)).encode()).hexdigest()
    return login + '_' + suffix[:6]


class UserDetailsCreator:
    def __init__(self, conf):
        self.services = []
        for service in conf.services:
            try:
                plugin = driver.DriverManager(
                    namespace='cauth.service',
                    name=service,
                    invoke_on_load=True,
                    invoke_args=(conf,)).driver
                self.services.append(plugin)
            except base.ServiceConfigurationError as e:
                logger.error(e.message)

    def create_user(self, user):
        external_info = user.get('external_auth', {})
        c_id = -1
        # skip if authenticating with an API key
        if external_info:
            if external_info.get('domain') == 'CAUTH_API_KEY':
                c_id = external_info['external_id']
            else:
                external_info['username'] = user['login']
                try:
                    c_id = auth_map.get_or_create_authenticated_user(
                        **external_info)
                except exceptions.UsernameConflictException as e:
                    strategy = conf.auth.get('login_collision_strategy')
                    if strategy == 'DIFFERENTIATE':
                        msg = ('login "%s" already registered for domain '
                               '%s, uid %s, differentiating login as %s')
                        old_login = user['login']
                        user['login'] = differentiate(
                            user['login'],
                            external_info.get('domain', ''),
                            external_info['external_id'])
                        external_info['username'] = user['login']
                        msg = msg % (old_login,
                                     e.external_auth_details['domain'],
                                     e.external_auth_details['external_id'],
                                     user['login'],)
                        logger.info(msg)
                        c_id = auth_map.get_or_create_authenticated_user(
                            **external_info)
                    elif strategy == 'FORBID':
                        raise
                    else:
                        msg = ('Incorrect login collision strategy '
                               '"%s", defaulting to "FORBID"')
                        logger.info(msg % strategy)
                        raise
            del user['external_auth']
            user['external_id'] = c_id
        for service in self.services:
            try:
                service.register_new_user(user)
            except base.UserRegistrationError as e:
                logger.info('When adding user %s (ID %s): %s' % (user['login'],
                                                                 c_id,
                                                                 e.message))
        return c_id
