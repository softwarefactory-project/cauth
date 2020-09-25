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

import pymysql
import requests

from cauth.service import base


logger = logging.getLogger(__name__)


class GerritServicePlugin(base.BaseServicePlugin):
    """This plugin deals with the Gerrit code review service."""

    _config_section = "gerrit"

    def set_api_key(self, user, password):
        """add http password for username."""
        if user == "admin":
            return
        url = self.conf['url'] + "a/accounts/%s/password.http" % user
        resp = requests.put(url, json={'http_password': password},
                            auth=("admin", self.conf["password"]))
        if resp.ok:
            logger.info('Set http password of %s' % user)
        else:
            msg = 'Failed to add http password of %s: %s' % (user, resp)
            logger.error(msg)

    def delete_api_key(self, user):
        """remove http password for username."""
        if user == "admin":
            return
        url = self.conf['url'] + "a/accounts/%s/password.http" % user
        resp = requests.delete(url, json={'generate': True},
                               auth=("admin", self.conf["password"]))
        if resp.ok:
            logger.info('Removed http password of %s' % user)
        else:
            msg = 'Failed to remove http password of %s: %s' % (user, resp)
            logger.error(msg)

    def register_new_user(self, user):
        # This is managed by the manageSF driver service/managesf.py
        pass
