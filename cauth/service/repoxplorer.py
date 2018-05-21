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


import json
import logging
import urllib

import requests

from cauth.service import base


logger = logging.getLogger(__name__)


class RepoxplorerServicePlugin(base.BaseServicePlugin):
    """This plugin deals with repoXplorer user backend."""

    _config_section = "repoxplorer"

    def register_new_user(self, user):
        _user = {"uid": user['login'],
                 "name": user['name'],
                 "default-email": str(user['email']),
                 "emails": [],
                 }
        emails = [
            {"email": email} for email in user.get("emails", [])]
        _user["emails"] = emails

        data = json.dumps(_user, default=lambda o: o.__dict__)

        headers = {
            "Remote-User": "admin",
            "Content-type": "application/json",
            "Admin-Token": self.conf["admin_token"]}
        url = "%s/api/v1/users/%s" % (
            self.conf["url"], urllib.quote_plus(user["login"]))

        # Check user already exists in the DB
        resp = requests.get(url, headers=headers)
        if resp.status_code == 404:
            mode = 'creation'
            req = requests.put
        else:
            mode = 'update'
            req = requests.post

        logger.debug('user %s to repoxplorer:'
                     ' %s with payload: %s' % (mode, url, data))
        resp = req(url, data=data, headers=headers)
        logger.debug('repoxplorer responded with code: %s' % resp.status_code)

    def set_api_key(self, user, key):
        pass

    def delete_api_key(self, user):
        pass
