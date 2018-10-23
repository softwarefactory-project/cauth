#!/usr/bin/env python
#
# Copyright (C) 2016 Red Hat
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
import time
import urllib

from cauth.auth import base
from cauth.utils import common
from cauth.utils import transaction

from cauth.model import db


"""API key authentication plugin."""


class APIKeyAuthPlugin(base.AuthProtocolPlugin):
    """User authentication with an API key.
    """

    log = logging.getLogger("cauth.APIKeyAuthPlugin")
    _config_section = "managesf"

    def __init__(self, conf):
        # the manageSF conf section is by root, not in the auth section
        self.configure_plugin(conf)

    @classmethod
    def get_args(cls):
        return {'api_key': {'description': 'the user API key'}, }

    def authenticate(self, **auth_context):
        transactionID = transaction.ensure_tid(auth_context)
        self.tdebug("Attempting authentication by API key", transactionID)
        api_key = auth_context.get('api_key', None)
        if not api_key:
            self.tdebug("Missing API key", transactionID)
            raise base.UnauthenticatedError('Missing API key')
        # do we have the key ?
        cauth_id = db.get_cauth_id_from_api_key(api_key)
        if not cauth_id:
            self.tdebug("API key not found", transactionID)
            raise base.UnauthenticatedError('API key not found')
        # fetch the user info from manageSF
        url = urllib.basejoin(
                self.conf['url'], "/services_users/?cauth_id=%s" % cauth_id)
        headers = {"Content-type": "application/json",
                   "X-Remote-User": "admin"}
        # short lived so that intercepting the cookie has limited impact
        validity = time.time() + 10
        ticket = common.create_ticket(uid='admin',
                                      validuntil=validity)
        cookie = {'auth_pubtkt': urllib.quote_plus(ticket)}
        self.tdebug("Retrieving user info from %s for cauth_id %s ...",
                    transactionID, self.conf['url'], cauth_id)
        resp = requests.get(url, headers=headers,
                            cookies=cookie)
        if resp.status_code > 399:
            msg = "manageSF responsed with error %i: \"%s\"" % (
                resp.status_code, resp.text)
            self.terror(msg, transactionID)
            raise base.UnauthenticatedError(msg)
        user_info = {'login': resp.json()['username'],
                     'email': resp.json()['email'],
                     'name': resp.json()['fullname'],
                     'ssh_keys': [],
                     'external_auth': {'domain': self.get_domain(),
                                       'external_id': cauth_id}}
        self.tinfo("cauth id %s for user %s (%s) authenticated "
                   "successfully with API key", transactionID,
                   cauth_id, user_info['login'], user_info['email'])
        return user_info

    def get_domain(self):
        return "CAUTH_API_KEY"
