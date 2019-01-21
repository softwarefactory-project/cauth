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

import logging

from pecan import expose, response, conf, abort, render
from stevedore import driver

from cauth.auth import base
from cauth.model import db
from cauth.utils import common
from cauth.utils import transaction


class PersonalAccessTokenGithubController(transaction.TransactionLogger):
    log = logging.getLogger("cauth.PersonalAccessTokenGithubController")

    @expose()
    def index(self, **kwargs):
        if 'back' not in kwargs:
            self.logger.error(
                'Client requests authentication without back url.')
            abort(422)
        auth_context = kwargs
        auth_context['response'] = response
        transactionID = transaction.ensure_tid(auth_context)
        self.tdebug('Client index authentication.', transactionID)

        auth_plugin = driver.DriverManager(
            namespace='cauth.authentication',
            name='GithubPersonalAccessToken',
            invoke_on_load=True,
            invoke_args=(conf,)).driver

        try:
            valid_user = auth_plugin.authenticate(**auth_context)
        except base.UnauthenticatedError as e:
            response.status = 401
            auth_methods = [k for k, v in conf.get('auth', {})]
            return render('login.html',
                          dict(back=auth_context['back'],
                               message='Authorization failure: %s' % e,
                               auth_methods=auth_methods))
        self.tinfo("%s (%s) authenticated with Github Personal Access Token.",
                   transactionID, valid_user['login'], valid_user['email'])
        common.setup_response(valid_user,
                              auth_context['back'])


class GithubController(transaction.TransactionLogger):
    log = logging.getLogger("cauth.GithubController")

    def __init__(self):
        self.auth_plugin = driver.DriverManager(
            namespace='cauth.authentication',
            name='Github',
            invoke_on_load=True,
            invoke_args=(conf,)).driver

    @expose()
    def callback(self, **kwargs):
        auth_context = kwargs
        auth_context['response'] = kwargs
        auth_context['calling_back'] = True
        transactionID = transaction.ensure_tid(auth_context)
        self.tdebug('Client callback authentication.', transactionID)
        try:
            # Verify the state previously put in the db
            state = auth_context.get('state', None)
            back, _ = db.get_url(state)
            if not back:
                err = 'GITHUB callback called with an unknown state.'
                self.terror(err, transactionID)
                raise base.UnauthenticatedError(err)
            auth_context['back'] = back
            valid_user = self.auth_plugin.authenticate(**auth_context)
        except base.UnauthenticatedError as e:
            response.status = 401
            auth_methods = [k for k, v in conf.get('auth', {})]
            return render('login.html',
                          dict(back=back,
                               message='Authorization failure: %s' % e,
                               auth_methods=auth_methods))
        self.tinfo('%s (%s) successfully authenticated with github.',
                   transactionID, valid_user['login'], valid_user['email'])
        common.setup_response(valid_user,
                              back)

    @expose()
    def index(self, **kwargs):
        auth_context = kwargs
        auth_context['response'] = response
        transactionID = transaction.ensure_tid(auth_context)
        self.tdebug('Client index authentication.', transactionID)
        # we don't expect a return value, we set up the redirect here
        self.auth_plugin.authenticate(**auth_context)
