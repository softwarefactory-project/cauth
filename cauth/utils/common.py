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

import base64
import hashlib
import time
import sys

try:
    from urllib import quote_plus, unquote_plus
except ImportError:
    from urllib.parse import quote_plus, unquote_plus

from M2Crypto import RSA
from pecan import response, conf, render
from cauth.utils import userdetails, exceptions


PY3 = sys.version_info[0] == 3
LOGOUT_MSG = "You have been successfully logged " \
             "out of all the Software factory services."


def signature(data):
    rsa_priv = RSA.load_key(conf.app['priv_key_path'])
    if PY3:
        data = data.encode('utf-8')
    dgst = hashlib.sha1(data).digest()
    sig = rsa_priv.sign(dgst, 'sha1')
    sig = base64.b64encode(sig)
    return sig


def create_ticket(**kwargs):
    ticket = ''
    for k in sorted(kwargs.keys()):
        if ticket is not '':
            ticket = ticket + ';'
        ticket = ticket + '%s=%s' % (k, kwargs[k])

    ticket = ticket + ";sig=%s" % signature(ticket)
    return ticket


def pre_register_user(user):
    if user.get('name', None) is None:
        user['name'] = 'User %s' % user['login']
    if user.get('email', None) is None:
        user['email'] = '%s@%s' % (user['login'], conf.app['cookie_domain'])

    udc = userdetails.UserDetailsCreator(conf)
    return udc.create_user(user)


def setup_response(user, back):
    try:
        c_id = pre_register_user(user)
    except exceptions.UsernameConflictException as e:
        response.status_code = 401
        msg = ('Error: this username is already registered with a '
               'different Identity Provider (%s - uid: %s).<br />'
               'Please contact an administrator.')
        msg = msg % (e.external_auth_details['domain'],
                     e.external_auth_details['external_id'])
        response.body = render('login.html',
                               dict(back=back,
                                    message=msg))
        return
    # c_id is added to the cauth cookie so that the storyboard client can
    # authenticate to storyboard_api.
    # the c_id is stored in browser local storage after authentication.
    ticket = create_ticket(uid=user['login'],
                           cid=c_id,
                           validuntil=(
                               time.time() + conf.app['cookie_period']))
    enc_ticket = quote_plus(ticket)
    response.set_cookie('auth_pubtkt',
                        value=enc_ticket,
                        max_age=conf.app['cookie_period'],
                        overwrite=True)
    response.status_code = 303
    loc = unquote_plus(back)
    if not PY3:
        loc = loc.decode("utf8")
    response.location = loc
