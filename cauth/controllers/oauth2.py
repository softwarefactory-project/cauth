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

from pecan import expose, response, conf, render
from stevedore import driver

from cauth.auth import base
from cauth.model import db
from cauth.utils import common
from cauth.utils import transaction


OAUTH_PROVIDERS_PLUGINS = ['Github',
                           'Google',
                           'BitBucket', ]


class OAuth2Controller(transaction.TransactionLogger):
    log = logging.getLogger("cauth.Oauth2Controller")

    def __init__(self):
        self.auth_plugins = {}
        for p in OAUTH_PROVIDERS_PLUGINS:
            try:
                self.auth_plugins[p] = driver.DriverManager(
                    namespace='cauth.authentication',
                    name=p,
                    invoke_on_load=True,
                    invoke_args=(conf,)).driver
                self.log.debug('Loaded OAuth2 plugin %s' % p)
            except Exception:
                pass
        if not self.auth_plugins:
            msg = ('no valid configuration found for any of the '
                   'supported OAuth '
                   'providers (%s)' % ', '.join(OAUTH_PROVIDERS_PLUGINS))
            raise base.AuthProtocolNotAvailableError(msg)

    @expose()
    def callback(self, **kwargs):
        auth_context = kwargs
        auth_context['response'] = kwargs
        auth_context['calling_back'] = True
        transactionID = transaction.ensure_tid(auth_context)
        try:
            # Verify the state previously put in the db
            state = auth_context.get('state', None)
            back, provider = db.get_url(state)
            if not back:
                err = 'OAuth callback with forged state, discarding'
                self.tdebug(err, transactionID)
                raise base.UnauthenticatedError(err)
            auth_plugin = self.auth_plugins.get(provider)
            if not auth_plugin:
                msg = 'Unknown OAuth provider: %s' % provider
                self.terror(msg, transactionID)
                raise base.UnauthenticatedError(msg)
            self.tdebug('Callback called by OAuth provider %s',
                        transactionID, provider)
            auth_context['back'] = back
            valid_user = auth_plugin.authenticate(**auth_context)
            raise base.UnauthenticatedError("Failure to authenticate")
        except base.UnauthenticatedError as e:
            response.status = 401
            auth_methods = [k for k, v in conf.get('auth', {})]
            return render('login.html',
                          dict(back=back,
                               message='Authorization failure: %s' % e,
                               auth_methods=auth_methods))
        except Exception:
            msg = "Failure to authenticate"
            self.texception(msg, transactionID)
            response.status = 401
            auth_methods = [k for k, v in conf.get('auth', {})]
            return render('login.html',
                          dict(back=back,
                               message=msg,
                               auth_methods=auth_methods))
        self.tinfo("%s (%s) successfully authenticated with %s.",
                   transactionID,
                   valid_user["login"],
                   valid_user.get('email'),
                   auth_plugin.name)
        common.setup_response(valid_user,
                              back)

#    @expose()
#    def index(self, **kwargs):
#        auth_context = kwargs
#        auth_context['response'] = response
#        # we don't expect a return value, we set up the redirect here
#        self.auth_plugin.authenticate(**auth_context)
