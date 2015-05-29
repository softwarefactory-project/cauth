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

import crypt
import time
import hashlib
import base64
import urllib
import ldap
import logging
import requests
from requests.exceptions import ConnectionError

from basicauth import encode
from M2Crypto import RSA

from pecan import expose, response, conf, abort, render
from pecan.rest import RestController

from cauth.model import db
from cauth.controllers import userdetails

LOGOUT_MSG = "You have been successfully logged " \
             "out of all the Software factory services."

logger = logging.getLogger(__name__)


def signature(data):
    rsa_priv = RSA.load_key(conf.app['priv_key_path'])
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


def pre_register_user(username, email=None, lastname=None, keys=None):
    if lastname is None:
        lastname = 'User %s' % username
    if not email:
        email = '%s@%s' % (username, conf.app['cookie_domain'])

    logger.info('Register user details for %s (email: %s).'
                % (username, email))
    udc = userdetails.UserDetailsCreator(conf)
    udc.create_user(username, email, lastname, keys)


def setup_response(username, back, email=None, lastname=None, keys=None):
    pre_register_user(username, email, lastname, keys)
    ticket = create_ticket(uid=username,
                           validuntil=(
                               time.time() + conf.app['cookie_period']))
    enc_ticket = urllib.quote_plus(ticket)
    response.set_cookie('auth_pubtkt',
                        value=enc_ticket,
                        domain=conf.app['cookie_domain'],
                        max_age=conf.app['cookie_period'],
                        overwrite=True)
    response.status_code = 303
    response.location = urllib.unquote_plus(back).decode("utf8")


class PersonalAccessTokenGithubController(object):
    """Allows a github user to authenticate with a personal access token,
    see https://github.com/blog/1509-personal-api-tokens and make sure the
    token has at least the following rights:
    'user:email, read:public_key, read:org'"""

    def organization_allowed(self, token):
        allowed_orgs = conf.auth['github'].get('allowed_organizations')

        if allowed_orgs:
            basic_auth = requests.auth.HTTPBasicAuth(token,
                                                     'x-oauth-basic')
            resp = requests.get("https://api.github.com/user/orgs",
                                auth=basic_auth)
            user_orgs = resp.json()
            user_orgs = [org['login'] for org in user_orgs]

            allowed_orgs = allowed_orgs.split(',')
            allowed_orgs = filter(None, allowed_orgs)
            allowed = set(user_orgs) & set(allowed_orgs)
            if not allowed:
                return False
        return True

    @expose()
    def index(self, **kwargs):
        if 'back' not in kwargs:
            logger.error('Client requests authentication without back url.')
            abort(422)
        back = kwargs['back']
        if 'token' not in kwargs:
            logger.error('Client requests authentication without token.')
            abort(422)
        token = kwargs['token']
        resp = requests.get("https://api.github.com/user",
                            auth=requests.auth.HTTPBasicAuth(token,
                                                             'x-oauth-basic'))
        data = resp.json()
        login = data.get('login')
        email = data.get('email')
        name = data.get('name')
        resp = requests.get("https://api.github.com/user/keys",
                            auth=requests.auth.HTTPBasicAuth(token,
                                                             'x-oauth-basic'))
        ssh_keys = resp.json()

        if not self.organization_allowed(token):
            abort(401)
        msg = 'Client %s (%s) auth with Github Personal Access token success.'
        logger.info(msg % (login, email))
        setup_response(login, back, email, name, ssh_keys)


class GithubController(object):
    def get_access_token(self, code):
        github = conf.auth['github']
        url = "https://github.com/login/oauth/access_token"
        params = {
            "client_id": github['client_id'],
            "client_secret": github['client_secret'],
            "code": code,
            "redirect_uri": github['redirect_uri']}
        headers = {'Accept': 'application/json'}
        try:
            resp = requests.post(url, params=params, headers=headers)
        except ConnectionError:
            return None

        jresp = resp.json()
        if 'access_token' in jresp:
            return jresp['access_token']
        elif 'error' in jresp:
            logger.error("An error occured (%s): %s" % (
                jresp.get('error', None),
                jresp.get('error_description', None)))
        return None

    def organization_allowed(self, token):
        allowed_orgs = conf.auth['github'].get('allowed_organizations')
        if allowed_orgs:
            resp = requests.get("https://api.github.com/user/orgs",
                                headers={'Authorization': 'token ' + token})

            user_orgs = resp.json()
            user_orgs = [org['login'] for org in user_orgs]

            allowed_orgs = allowed_orgs.split(',')
            allowed_orgs = filter(None, allowed_orgs)
            allowed = set(user_orgs) & set(allowed_orgs)
            if not allowed:
                return False
        return True

    @expose()
    def callback(self, **kwargs):
        if 'error' in kwargs:
            logger.error('GITHUB callback called with an error (%s): %s' % (
                kwargs.get('error', None),
                kwargs.get('error_description', None)))
        state = kwargs.get('state', None)
        code = kwargs.get('code', None)
        if not state or not code:
            logger.error(
                'GITHUB callback called without state or code as params.')
            abort(400)

        # Verify the state previously put in the db
        back = db.get_url(state)
        if not back:
            logger.error('GITHUB callback called with an unknown state.')
            abort(401)

        token = self.get_access_token(code)
        if not token:
            logger.error('Unable to request a token on GITHUB.')
            abort(401)

        resp = requests.get("https://api.github.com/user",
                            headers={'Authorization': 'token ' + token})
        data = resp.json()
        login = data.get('login')
        email = data.get('email')
        name = data.get('name')

        resp = requests.get("https://api.github.com/users/%s/keys" % login,
                            headers={'Authorization': 'token ' + token})
        ssh_keys = resp.json()

        if not self.organization_allowed(token):
            abort(401)

        logger.info(
            'Client (username: %s, email: %s) auth on GITHUB success.'
            % (login, email))
        setup_response(login, back, email, name, ssh_keys)

    @expose()
    def index(self, **kwargs):
        if 'back' not in kwargs:
            logger.error(
                'Client requests authentication via GITHUB' +
                'without back in params.')
            abort(422)
        back = kwargs['back']
        state = db.put_url(back)
        scope = 'user:email, read:public_key, read:org'
        github = conf.auth['github']
        logger.info(
            'Client requests authentication via GITHUB -' +
            'redirect to %s.' % github['redirect_uri'])
        response.status_code = 302
        response.location = github['auth_url'] + "?" + \
            urllib.urlencode({'client_id': github['client_id'],
                              'redirect_uri': github['redirect_uri'],
                              'state': state,
                              'scope': scope})


class LoginController(RestController):
    def check_ldap_user(self, config, username, password):
        try:
            conn = ldap.initialize(config['host'])
            conn.set_option(ldap.OPT_REFERRALS, 0)
        except ldap.LDAPError:
            logger.error('Client unable to bind on LDAP unexpected behavior.')
            return None

        who = config['dn'] % {'username': username}
        try:
            conn.simple_bind_s(who, password)
        except (ldap.INVALID_CREDENTIALS, ldap.SERVER_DOWN):
            logger.error('Client unable to bind on LDAP invalid credentials.')
            return None

        result = conn.search_s(who, ldap.SCOPE_SUBTREE, '(cn=*)',
                               attrlist=[config['sn'], config['mail']])
        if len(result) == 1:
            user = result[0]  # user is a tuple
            mail = user[1].get(config['mail'], [None])
            lastname = user[1].get(config['sn'], [None])
            return mail[0], lastname[0], []

        logger.error('LDAP client search failed')
        return None

    def check_localdb_user(self, config, username, password):
        bind_url = urllib.basejoin(config['managesf_url'], '/manage/bind')
        headers = {"Authorization": encode(username, password)}
        response = requests.get(bind_url, headers=headers)

        if response.status_code > 399:
            logger.error('localdb auth failed: %s' % response)
            return None
        infos = response.json()
        return infos['email'], infos['fullname'], [{'key': infos['sshkey']}, ]

    def check_valid_user(self, username, password):
        user = conf.auth.get('users', {}).get(username)
        if user:
            salted_password = user.get('password')
            if salted_password == crypt.crypt(password, salted_password):
                return user.get('mail'), user.get('lastname'), []

        localdb = conf.auth.get('localdb')
        if localdb:
            return self.check_localdb_user(localdb, username, password)

        ldap = conf.auth.get('ldap')
        if ldap:
            return self.check_ldap_user(ldap, username, password)

        logger.error('User not authenticated')
        return None

    @expose()
    def post(self, **kwargs):
        logger.info('Client requests authentication.')
        if 'back' not in kwargs:
            logger.error('Client requests authentication without back url.')
            abort(422)
        back = kwargs['back']
        if 'username' in kwargs and 'password' in kwargs:
            username = kwargs['username']
            password = kwargs['password']
            valid_user = self.check_valid_user(username, password)
            if not valid_user:
                logger.error('Client requests authentication with wrong'
                             ' credentials.')
                response.status = 401
                return render('login.html',
                              dict(back=back, message='Authorization failed.'))
            email, lastname, sshkey = valid_user
            logger.info('Client requests authentication success %s' % username)
            setup_response(username, back, email, lastname, sshkey)
        else:
            logger.error('Client requests authentication without credentials.')
            response.status = 401
            return render('login.html', dict(back=back,
                                             message='Authorization failed.'))

    @expose(template='login.html')
    def get(self, **kwargs):
        if 'back' not in kwargs:
            kwargs['back'] = '/auth/logout'

        logger.info('Client requests the login page.')
        return dict(back=kwargs["back"], message='')

    github = GithubController()
    githubAPIkey = PersonalAccessTokenGithubController()


class LogoutController(RestController):
    @expose(template='login.html')
    def get(self, **kwargs):
        response.delete_cookie('auth_pubtkt', domain=conf.app.cookie_domain)
        return dict(back='/', message=LOGOUT_MSG)


class RootController(object):
    login = LoginController()
    logout = LogoutController()
