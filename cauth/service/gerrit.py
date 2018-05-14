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

    def add_sshkeys(self, username, keys):
        """add keys for username."""
        url = self.conf['url'] + "a/accounts/%s/sshkeys" % username
        for key in keys:
            logger.debug("Adding key %s for user %s" % (key.get('key'),
                                                        username))
            response = requests.post(url, data=key.get('key'),
                                     auth=("admin", self.conf['password']))

            if not response.ok:
                msg = 'Failed to add ssh key %s of %s: %s' % (key.get('key'),
                                                              username,
                                                              response)
                logger.error(msg)

    def add_account_as_external(self, account_id, username):
        # TODO(mhu) there's got to be a cleaner way. pygerrit ?
        db = pymysql.connect(passwd=self.conf['db_password'],
                             db=self.conf['db_name'],
                             host=self.conf['db_host'],
                             user=self.conf['db_user'])
        c = db.cursor()
        sql = ("INSERT IGNORE INTO account_external_ids VALUES"
               "(%d, NULL, NULL, 'gerrit:%s');" %
               (account_id, username))
        try:
            c.execute(sql)
            db.commit()
            return True
        except Exception:
            msg = "Could not insert user %s in account_external_ids" % username
            logger.exception(msg)
            return False

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
        if not self.conf.get("register_user", True):
            return
        _user = {"name": unicode(user['name']), "email": str(user['email'])}
        data = json.dumps(_user, default=lambda o: o.__dict__)

        headers = {"Content-type": "application/json"}
        url = "%s/accounts/%s" % (self.conf['url'], user['login'])
        response = requests.put(url, data=data, headers=headers,
                                auth=("admin", self.conf['password']))
        if not response.ok:
            msg = 'Failed to register new user %s: %s' % (user['email'],
                                                          response)
            logger.error(msg)
            return False

        response = requests.get(url, headers=headers,
                                auth=("admin", self.conf['password']))
        data = response.content[4:]  # there is some garbage at the beginning
        try:
            account_id = json.loads(data)['_account_id']
        except (KeyError, ValueError):
            msg = 'Failed to retreive account %s from server' % user['email']
            logger.exception(msg)
            return False

        fetch_ssh_keys = False
        if account_id:
            fetch_ssh_keys = self.add_account_as_external(account_id,
                                                          user['login'])
        if user.get('ssh_keys', None) and fetch_ssh_keys:
            self.add_sshkeys(user['login'], user['ssh_keys'])
