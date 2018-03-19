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
from urllib import unquote

from stevedore import driver
from pecan import expose, response, abort, request, conf
from pecan.rest import RestController

from cauth.service import base
from cauth.model import db


logger = logging.getLogger(__name__)


class APIKeyController(RestController):
    def __init__(self):
        super(APIKeyController, self).__init__()
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

    # Obviously these operations can only be done once authenticated
    def get_pubtkt_infos(self):
        try:
            auth_pubtkt = unquote(request.cookies['auth_pubtkt'])
        except KeyError:
            return {}
        infos = dict(vals.split('=', 1) for vals in auth_pubtkt.split(';'))
        return infos

    def guess_cauth_id(self):
        return self.get_pubtkt_infos().get('cid')

    def guess_username(self):
        return self.get_pubtkt_infos().get('uid')

    def check_identity(self, cauth_id):
        try:
            if self.guess_cauth_id() != cauth_id:
                abort(401, 'Wrong user')
            else:
                return True
        except Exception:
            logger.exception("Couldn't check identity of %s" % cauth_id)
            abort(401, 'Wrong user')

    @expose('json')
    def get(self, **kwargs):
        cauth_id = kwargs.get('cauth_id')
        if not cauth_id:
            cauth_id = self.guess_cauth_id()
        if not cauth_id:
            abort(401, 'Authenticate first')
        self.check_identity(cauth_id)
        key = db.get_api_key_from_cauth_id(cauth_id)
        if key:
            return {'api_key': key}
        else:
            abort(404, 'User has no API key')

    @expose('json')
    def post(self, cauth_id=None):
        if not cauth_id:
            cauth_id = self.guess_cauth_id()
        self.check_identity(cauth_id)
        username = self.guess_username()
        try:
            key = db.create_api_key(cauth_id)
            logger.debug('Created API Key for cauth_id %s' % cauth_id)
            response.status_code = 201
            for service in self.services:
                service.set_api_key(username, key)
            return {'api_key': key}
        except db.APIKeyUnicityError:
            abort(409, 'An API key already exists for this user')

    @expose()
    def delete(self, cauth_id=None):
        if not cauth_id:
            cauth_id = self.guess_cauth_id()
        self.check_identity(cauth_id)
        db.delete_api_key(cauth_id)
        username = self.guess_username()
        for service in self.services:
            service.delete_api_key(username)
        logger.debug('Deleted API Key for cauth_id %s' % cauth_id)
        response.status_code = 204
