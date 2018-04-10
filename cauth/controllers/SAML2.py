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

import logging

from pecan import expose, response, conf, render
from stevedore import driver

from cauth.auth import base
from cauth.utils import common


logger = logging.getLogger(__name__)


class SAML2Controller(object):
    def __init__(self):
        self.auth_plugin = driver.DriverManager(
            namespace='cauth.authentication',
            name='SAML2',
            invoke_on_load=True,
            invoke_args=(conf,)).driver

    @expose()
    def index(self, **kwargs):
        auth_context = kwargs.copy()
        auth_context['endpoint_redirect'] = True
        back = auth_context.get('back', '/')
        try:
            valid_user = self.auth_plugin.authenticate(**auth_context)
        except base.UnauthenticatedError as e:
            response.status = 401
            auth_methods = [k for k, v in conf.get('auth', {})]
            return render('login.html',
                          dict(back=back,
                               message='Authorization failure: %s' % e,
                               auth_methods=auth_methods))
        logger.info(
            '%s (%s) successfully authenticated with SAML2.'
            % (valid_user['login'], valid_user['email']))
        common.setup_response(valid_user,
                              back)
