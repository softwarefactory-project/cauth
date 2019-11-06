#!/usr/bin/env python
#
# Copyright (C) 2016 Red Hat
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
from urllib.parse import unquote

from pecan import expose, request, response, conf
from pecan.rest import RestController

from cauth.auth import base as exceptions
from cauth.controllers import base, github, introspection, openid, oauth2
from cauth.controllers import apikey, openid_connect, SAML2
from cauth.utils.common import LOGOUT_MSG
from cauth.utils import transaction


logger = logging.getLogger(__name__)


class LogoutController(RestController, transaction.TransactionLogger):
    log = logging.getLogger("cauth.LogoutController")

    @expose(template='login.html')
    def get(self, **kwargs):
        transactionID = transaction.make_tid()
        try:
            auth_pubtkt = unquote(request.cookies['auth_pubtkt'])
        except KeyError:
            auth_pubtkt = "cid=NONE"
        infos = dict(vals.split('=', 1) for vals in auth_pubtkt.split(';'))
        username = infos.get("uid", infos.get("cid"))
        response.delete_cookie('auth_pubtkt')
        auth_methods = [k for k, v in conf.get('auth', {})]
        self.tinfo("%s successfully logout",
                   transactionID, username)
        return dict(back='/', message=LOGOUT_MSG, auth_methods=auth_methods)


class RootController(object):
    login = base.BaseLoginController()
    try:
        login.github = github.GithubController()
        login.githubAPIkey = github.PersonalAccessTokenGithubController()
    except exceptions.AuthProtocolNotAvailableError as e:
        logger.debug("%s - skipping callback endpoint" % e)
    try:
        login.oauth2 = oauth2.OAuth2Controller()
    except exceptions.AuthProtocolNotAvailableError as e:
        logger.debug("%s - skipping callback endpoint" % e)
    try:
        login.openid = openid.OpenIDController()
    except exceptions.AuthProtocolNotAvailableError as e:
        logger.debug("%s - skipping callback endpoint" % e)
    try:
        login.openid_connect = openid_connect.OpenIDConnectController()
    except exceptions.AuthProtocolNotAvailableError as e:
        logger.debug("%s - skipping callback endpoint" % e)
    try:
        login.SAML2 = SAML2.SAML2Controller()
    except exceptions.AuthProtocolNotAvailableError as e:
        logger.debug("%s - skipping callback endpoint" % e.message)
    about = introspection.IntrospectionController()
    apikey = apikey.APIKeyController()

    logout = LogoutController()
