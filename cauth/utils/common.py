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
import urllib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from pecan import response, conf, render
from cauth.utils import userdetails, exceptions
from cauth.utils.localgroups import LocalGroupsManager


LOGOUT_MSG = "You have been successfully logged " \
             "out of all the Software factory services."


PUBTKT_VALID_SIGN_ALGORITHMS = ['SHA1', 'DSS1', 'SHA224',
                                'SHA256', 'SHA384', 'SHA512']


def signature(data):
    private_key = serialization.load_pem_private_key(
        open(conf.app['priv_key_path'], 'rb').read(),
        password=None,
        backend=default_backend()
    )
    algo_name = conf.auth.get('pubtkt_sign_algorithm', 'SHA1')
    try:
        if algo_name.upper() not in PUBTKT_VALID_SIGN_ALGORITHMS:
            raise AttributeError()
        algo = getattr(hashlib, algo_name.lower())
        dgst = algo(data).digest()
        _hash = getattr(hashes, algo_name.upper())
        if algo_name.lower() == 'sha1':
            _padding = padding.PKCS1v15()
        else:
            _padding = padding.PSS(
                mgf=padding.MGF1(_hash()),
                salt_length=padding.PSS.MAX_LENGTH)
        signature = private_key.sign(
            dgst,
            _padding,
            _hash()
        )
        return base64.b64encode(signature)
    except AttributeError:
        raise Exception("Unknown algorithm %s" % algo_name)


def create_ticket(**kwargs):
    ticket = ''
    for k in sorted(kwargs.keys()):
        if ticket != '':
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
    lgm = LocalGroupsManager(conf)
    local_groups = lgm.get_user_groups(user)
    idp_groups = user.get('groups', [])
    ticket = create_ticket(
        uid=user['login'],
        cid=c_id,
        # TODO separator should be configurable
        # also we add [] to ensure we don't introduce pbs if groups are empty
        groups='[' + '::'.join(local_groups + idp_groups) + ']',
        validuntil=(time.time() + conf.app['cookie_period']))
    enc_ticket = urllib.quote_plus(ticket)
    response.set_cookie('auth_pubtkt',
                        value=enc_ticket,
                        max_age=conf.app['cookie_period'],
                        overwrite=True)
    response.status_code = 303
    response.location = urllib.unquote_plus(back).decode("utf8")
