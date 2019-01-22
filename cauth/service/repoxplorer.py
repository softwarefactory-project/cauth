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

try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus

import requests

from cauth.service import base


logger = logging.getLogger(__name__)


class RepoxplorerServicePlugin(base.BaseServicePlugin):
    """This plugin deals with repoXplorer user backend."""

    _config_section = "repoxplorer"
    log = logging.getLogger("cauth.RepoxplorerServicePlugin")

    def register_new_user(self, user):
        transactionID = user.get('transactionID', '')
        _user = {"uid": user['login'],
                 "name": user['name'],
                 "default-email": str(user['email']),
                 "emails": [],
                 }
        emails = [
            {"email": email} for email in user.get("emails", [])]

        # If IDP driver does not add any email to emails
        # add the default email of the user
        if not emails:
            emails = [{"email": str(user['email'])}]

        _user["emails"] = emails

        headers = {
            "Remote-User": "admin",
            "Content-type": "application/json",
            "Admin-Token": self.conf["admin_token"]}
        url = "%s/api/v1/users/%s" % (
            self.conf["url"], quote_plus(user["login"]))

        # Check user already exists in the DB
        try:
            resp = requests.get(url, headers=headers, timeout=5)
        except Exception as exc:
            self.twarning(
                "Skip user %s registration, repoxplorer backend down (%s)",
                transactionID, quote_plus(user["login"]), exc)
            return

        if resp.status_code == 404:
            mode = 'creation'
            req = requests.put
        elif resp.status_code == 200:
            mode = 'update'
            req = requests.post
            puser = resp.json()
            # Keep user defined name
            _user["name"] = puser["name"]
            # Detect email to add or to remove
            prev_emails = set([e['email'] for e in puser['emails']])
            new_emails = set([e['email'] for e in _user['emails']])
            to_add = new_emails - prev_emails
            to_del = prev_emails - new_emails
            # Keep previous emails data, by amending with data from idp
            _user["emails"] = []
            for e in puser["emails"]:
                if e['email'] in to_del:
                    continue
                _user["emails"].append(e)
            for e in to_add:
                _user["emails"].append({'email': e})
        else:
            self.twarning(
                "Skip user %s registration, unexpected status code (%s)",
                transactionID, quote_plus(user["login"]),
                resp.status_code)
            return

        data = json.dumps(_user, default=lambda o: o.__dict__)
        logger.debug('Add user %s to repoxplorer:'
                     ' %s with payload: %s' % (mode, url, data))
        try:
            resp = req(url, data=data, headers=headers, timeout=5)
        except Exception as exc:
            self.twarning(
                "Skip user %s registration, repoxplorer backend down (%s)",
                transactionID, quote_plus(user["login"]), exc)
            return

        self.tdebug('repoxplorer responded with code: %s',
                    transactionID, resp.status_code)

    def set_api_key(self, user, key):
        pass

    def delete_api_key(self, user):
        pass
