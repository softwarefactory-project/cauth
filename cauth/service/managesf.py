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

from cauth.service import base


class ManageSFServicePlugin(base.BaseServicePlugin):
    """This plugin deals with the ManageSF wrapper."""

    _config_section = "managesf"
    log = logging.getLogger(__name__)

    def set_api_key(self, user, key):
        pass

    def delete_api_key(self, user):
        pass

    def register_new_user(self, user):
        _user = {"full_name": user['name'],
                 "email": str(user['email']),
                 "username": user['login'],
                 "ssh_keys": user.get('ssh_keys', []),
                 "external_id": user['external_id']
                 }

        url = "%s/services_users/" % self.conf['url']
        self.log.debug('user declaration to managesf: %s' % _user)
        resp = requests.post(url, json=_user,
                             headers={"X-Remote-User": "admin"})
        self.log.debug('managesf responded with code: %s' % resp.status_code)
