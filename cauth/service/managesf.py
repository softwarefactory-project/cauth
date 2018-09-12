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


import json
import logging
import time
import urllib

import jwt
from pecan import conf as orig_conf
import requests

from cauth.service import base
from cauth.utils.common import create_ticket


logger = logging.getLogger(__name__)


class ManageSFServicePlugin(base.BaseServicePlugin):
    """This plugin deals with the ManageSF wrapper."""

    _config_section = "managesf"

    def set_api_key(self, user, key):
        pass

    def delete_api_key(self, user):
        pass

    def get_resources(self):
        url = "%s/manage/v2/resources/" % self.conf['url']
        validity = time.time() + orig_conf.app['cookie_period']
        # an admin cookie should not be necessary though
        ticket = create_ticket(uid='admin',
                               validuntil=validity)
        cookie = {'auth_pubtkt': urllib.quote_plus(ticket)}
        logger.debug("Fetching resources tree")
        resp = requests.get(url, cookies=cookie)
        return resp.json()

    def create_zuul_jwt(self, user):
        if not getattr(orig_conf, 'zuul', False):
            return {}
        # fetch resources tree
        authz = {'iss': self.conf['url'],
                 'zuul.tenants': {},
                 'exp': 0}
        resources = self.get_resources().get('resources', {})
        # iterate on tenants first
        tenants = resources.get('tenants', {})
        for tenant in tenants:
            tenant_name = tenants[tenant]['name']
            # admin and service user are privileged by default
            if (user['login'] in ['admin', 'SF_SERVICE_USER'] or
               user['email'] in tenants[tenant].get('privileged-users', [])):
                authz['zuul.tenants'][tenant_name] = '*'
        # iterate on projects if user is not an admin or service user
        if user['login'] not in ['admin', 'SF_SERVICE_USER']:
            projects = resources.get('projects', {})
            for project in projects:
                project_name = projects[project]['name']
                tenant_name = projects[project]['tenant']
                if user['email'] in projects[project].get('privileged-users',
                                                          []):
                    if authz['zuul.tenants'].get(tenant_name) != '*':
                        d = authz['zuul.tenants'].get(tenant_name, [])
                        d.append(project_name)
                        authz['zuul.tenants'][tenant_name] = d
        authz['exp'] = time.time() + orig_conf.app['cookie_period']
        try:
            token = jwt.encode(authz,
                               key=orig_conf.zuul['JWTsecret'],
                               # TODO this is hardcoded in zuul for now
                               algorithm='HS256').decode('utf-8')
        except Exception as e:
            logger.error('JWT creation failed: %s' % e)
            return {}
        logger.debug('jwt created: %s[TRUNCATED]' % token[:10])
        return {'jwt': token}

    def register_new_user(self, user):
        _user = {"full_name": user['name'],
                 "email": str(user['email']),
                 "username": user['login'],
                 "ssh_keys": user.get('ssh_keys', []),
                 "external_id": user['external_id']
                 }
        data = json.dumps(_user, default=lambda o: o.__dict__)

        headers = {"Content-type": "application/json"}
        url = "%s/manage/services_users/" % self.conf['url']
        # assuming the admin user is called admin
        validity = time.time() + orig_conf.app['cookie_period']
        ticket = create_ticket(uid='admin',
                               validuntil=validity)
        cookie = {'auth_pubtkt': urllib.quote_plus(ticket)}
        logger.debug('user declaration to managesf: %s' % data)
        resp = requests.post(url, data=data, headers=headers,
                             cookies=cookie)
        logger.debug('managesf responded with code: %s' % resp.status_code)
        # TODO plug ACL info retrieval
        return self.create_zuul_jwt(user)
