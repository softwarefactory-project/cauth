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

import string

from unittest import TestCase
from mock import patch
from M2Crypto import RSA, BIO
import yaml

from webtest import TestApp
from pecan import load_app

from cauth.tests.fixtures.auth import dummies
from cauth.utils import common, exceptions
from cauth.utils import localgroups
from cauth.utils.userdetails import differentiate
from cauth.tests.common import dummy_conf, FakeResponse, githubmock_request
from cauth.model import db

import os
import pkg_resources

import httmock
import urlparse
import urllib2


def raise_(ex):
    raise ex


def gen_rsa_key():
    conf = dummy_conf()
    if not os.path.isfile(conf.app['priv_key_path']):
        key = RSA.gen_key(2048, 65537, callback=lambda x, y, z: None)
        memory = BIO.MemoryBuffer()
        key.save_key_bio(memory, cipher=None)
        p_key = memory.getvalue()
        file(conf.app['priv_key_path'], 'w').write(p_key)


def gen_groups_config(groups_config=None):
    conf = dummy_conf()
    if groups_config is None:
        groups_config = {'groups': {}}
    if os.path.isfile(conf.groups['local_groups']['config_file']):
        os.unlink(conf.groups['local_groups']['config_file'])
    with file(conf.groups['local_groups']['config_file'], 'w') as f:
        yaml.dump(groups_config, f)


class FunctionalTest(TestCase):
    def setUp(self):
        c = dummy_conf()
        gen_rsa_key()
        config = {'managesf': c.managesf,
                  'app': c.app,
                  'auth': c.auth,
                  'services': c.services,
                  'sqlalchemy': c.sqlalchemy}
        # deactivate loggin that polute test output
        # even nologcapture option of nose effetcs
        # 'logging': c.logging}
        self.app = TestApp(load_app(config))

    def tearDown(self):
        pass


class TestUtils(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        gen_rsa_key()

    @classmethod
    def tearDownClass(cls):
        pass

    def test_signature(self):
        self.assertIsNot(None, common.signature('data'))

    def test_pre_register_user(self):
        p = 'cauth.utils.userdetails.UserDetailsCreator.create_user'
        with patch(p) as cu:
            common.pre_register_user({'login': 'john'})
            cu.assert_called_once_with(
                {'login': 'john',
                 'email': 'john@%s' % self.conf.app['cookie_domain'],
                 'name': 'User john'})

    def test_create_ticket(self):
        with patch('cauth.utils.common.signature') as sign:
            sign.return_value = '123'
            self.assertEqual('a=arg1;b=arg2;sig=123',
                             common.create_ticket(a='arg1', b='arg2'))


class TestLocalGroups(TestCase):
    def conf_setup(self):
        c = dummy_conf()
        cfg = {'managesf': c.managesf,
               'app': c.app,
               'auth': c.auth,
               'services': c.services,
               'sqlalchemy': c.sqlalchemy,
               'groups': c.groups}
        return cfg

    def test_get_user_groups(self):
        groups_config = {'group1': {'description': 'group1',
                                    'members': ['user1@tests.dom',
                                                'user2@tests.dom']},
                         'group2': {'description': 'group2',
                                    'members': ['user2@tests.dom',
                                                'user3@tests.dom']}
                         }
        gen_groups_config(groups_config)
        lgm = localgroups.LocalGroupsManager(self.conf_setup())
        user1 = {'login': 'user1',
                 'email': 'user1@tests.dom'}
        self.assertTrue(
            'group1' in lgm.get_user_groups(user1),
            lgm.get_user_groups(user1))
        user2 = {'login': 'user2',
                 'email': 'user2@tests.dom'}
        self.assertTrue(
            all(x in lgm.get_user_groups(user2)
                for x in ['group1', 'group2']),
            lgm.get_user_groups(user2))

    def test_groups_in_ticket(self):
        groups_config = {'group1': {'description': 'group1',
                                    'members': ['user1@tests.dom',
                                                'user2@tests.dom']},
                         'group2': {'description': 'group2',
                                    'members': ['user2@tests.dom',
                                                'user3@tests.dom']}
                         }
        gen_groups_config(groups_config)
        test_conf = self.conf_setup()
        del test_conf['auth']['localdb']
        app = TestApp(load_app(test_conf))
        # user1
        payload = {'method': 'Password',
                   'back': 'r/',
                   'args': {'username': 'user1',
                            'password': 'userpass'}, }
        reg = ('cauth.service.managesf.ManageSFServicePlugin'
               '.register_new_user')
        with patch(reg):
            response = app.post_json('/login',
                                     payload)
        self.assertEqual(response.status_int, 303)
        self.assertEqual('http://localhost/r/', response.headers['Location'])
        self.assertIn('Set-Cookie', response.headers)
        auth_tkt = response.headers['Set-Cookie'].split(';')[0]
        cookie = auth_tkt.split('=')[-1]
        try:
            cookie_dict = dict(x.split('=', 1)
                               for x in urllib2.unquote(cookie).split(';'))
        except Exception:
            raise Exception(urllib2.unquote(cookie).split(';'))
        self.assertTrue('sf_groups' in cookie_dict, cookie_dict)
        groups = cookie_dict['sf_groups'][1:-1].split('::')
        self.assertTrue('group1' in groups, cookie_dict)


class TestCauthApp(FunctionalTest):
    def test_get_login(self):
        response = self.app.get('/login', params={'back': 'r/'})
        self.assertGreater(response.body.find('value="r/"'), 0)
        self.assertGreater(response.body.find('Login via Github'), 0)
        self.assertEqual(response.status_int, 200)

    def test_post_login(self):
        # Ldap and Gitub Oauth backend are mocked automatically
        # if the domain is tests.dom
        reg = 'cauth.service.managesf.ManageSFServicePlugin.register_new_user'
        with patch(reg):
            with patch('requests.get'):
                response = self.app.post('/login',
                                         params={'username': 'user1',
                                                 'password': 'userpass',
                                                 'back': 'r/'})
        self.assertEqual(response.status_int, 303)
        self.assertEqual('http://localhost/r/', response.headers['Location'])
        self.assertIn('Set-Cookie', response.headers)
        with patch('requests.get') as g:
            g.return_value = FakeResponse(401)
            # baduser is not known from the mocked backend
            with patch('cauth.utils.userdetails'):
                response = self.app.post('/login',
                                         params={'username': 'baduser',
                                                 'password': 'userpass',
                                                 'back': 'r/'},
                                         status="*")
            self.assertEqual(response.status_int, 401,
                             response.body)

            # Try with no creds
            with patch('cauth.utils.userdetails'):
                response = self.app.post('/login', params={'back': 'r/'},
                                         status="*")
            self.assertEqual(response.status_int, 401,
                             response.body)

    def test_json_password_login(self):
        """Test passing login info as a JSON payload"""
        payload = {'method': 'Password',
                   'back': 'r/',
                   'args': {'username': 'user1',
                            'password': 'userpass'}, }
        reg = 'cauth.service.managesf.ManageSFServicePlugin.register_new_user'
        with patch(reg), patch('requests.get'):
            response = self.app.post_json('/login',
                                          payload)
        self.assertEqual(response.status_int, 303)
        self.assertEqual('http://localhost/r/', response.headers['Location'])
        self.assertIn('Set-Cookie', response.headers)
        payload = {'method': 'Password',
                   'back': 'r/',
                   'args': {'username': 'baduser',
                            'password': 'userpass'}, }
        with patch('requests.get') as g:
            g.return_value = FakeResponse(401)
            # baduser is not known from the mocked backend
            response = self.app.post_json('/login',
                                          payload,
                                          status="*")
            self.assertEqual(response.status_int, 401)
            # Try with no creds
            with patch('cauth.utils.userdetails'):
                response = self.app.post_json('/login',
                                              {'method': 'Password',
                                               'args': {},
                                               'back': 'r/'},
                                              status="*")
            self.assertEqual(response.status_int, 401)

    def test_username_already_registered(self):
        """Test that username collisions result in a 401 response"""
        payload = {'method': 'Password',
                   'back': 'r/',
                   'args': {'username': 'user_collide',
                            'password': 'userpass'}, }
        gcau = 'cauth.model.db.get_or_create_authenticated_user'
        with patch(gcau) as g, patch('requests.get'):
            g.side_effect = exceptions.UsernameConflictException(
                message="",
                external_auth_details={'domain': 'SOME_DOMAIN',
                                       'external_id': 'SOMEID',
                                       'username': 'user_collide'})
            response = self.app.post_json('/login',
                                          payload,
                                          status="*")
        self.assertEqual(response.status_int, 401)
        self.assertTrue("SOME_DOMAIN" in response.text, response)

    def test_unknown_auth_method_login(self):
        """Test rejection upon trying to authenticate with an unknown method"""
        payload = {'method': 'ErMahGerd',
                   'back': 'r/',
                   'args': {'ErMahGarg1': 'berks',
                            'ErmahGarg2': 'blorks'}, }
        with patch('requests.get'):
            # baduser is not known from the mocked backend
            with patch('cauth.utils.userdetails'):
                response = self.app.post_json('/login',
                                              payload,
                                              status="*")
            self.assertEqual(response.status_int, 401)

    def test_github_login(self):
        with httmock.HTTMock(githubmock_request):
            with patch('cauth.utils.userdetails'):
                response = self.app.get('/login/github/index',
                                        params={'username': 'user6',
                                                'back': 'r/',
                                                'password': 'userpass'})
                self.assertEqual(response.status_int, 302)
                parsed = urlparse.urlparse(response.headers['Location'])
                parsed_qs = urlparse.parse_qs(parsed.query)
                self.assertEqual('https', parsed.scheme)
                self.assertEqual('github.com', parsed.netloc)
                self.assertEqual('/login/oauth/authorize', parsed.path)
                self.assertEqual(
                    ['user:email, read:public_key'],
                    parsed_qs.get('scope'))
                self.assertEqual(
                    ['http://tests.dom/auth/login/oauth2/callback"'],
                    parsed_qs.get('redirect_uri'))

    def test_json_github_login(self):
        with httmock.HTTMock(githubmock_request):
            with patch('cauth.utils.userdetails'):
                payload = {'back': 'r/',
                           'method': 'Github',
                           'args': {}, }
                response = self.app.post_json('/login',
                                              payload)
                self.assertEqual(response.status_int, 302)
                parsed = urlparse.urlparse(response.headers['Location'])
                parsed_qs = urlparse.parse_qs(parsed.query)
                self.assertEqual('https', parsed.scheme)
                self.assertEqual('github.com', parsed.netloc)
                self.assertEqual('/login/oauth/authorize', parsed.path)
                self.assertEqual(
                    ['user:email, read:public_key'],
                    parsed_qs.get('scope'))
                self.assertEqual(
                    ['http://tests.dom/auth/login/oauth2/callback"'],
                    parsed_qs.get('redirect_uri'))

    def test_json_github_API_token_login(self):
        payload = {'method': 'GithubPersonalAccessToken',
                   'back': 'r/',
                   'args': {'token': 'user6_token'}, }
        # TODO(mhu) possible refactoring with previous function
        with patch('cauth.utils.userdetails.UserDetailsCreator.create_user'):
            with patch('requests.get'):
                response = self.app.post_json('/login',
                                              payload)
        self.assertEqual(response.status_int, 303)
        self.assertEqual('http://localhost/r/', response.headers['Location'])
        self.assertIn('Set-Cookie', response.headers)

    def test_get_logout(self):
        # Ensure client SSO cookie content is deleted
        response = self.app.get('/logout')
        self.assertEqual(response.status_int, 200)
        self.assertTrue('auth_pubtkt=;' in response.headers['Set-Cookie'])
        self.assertGreater(response.body.find(common.LOGOUT_MSG), 0)

    def test_introspection(self):
        response = self.app.get('/about/').json
        self.assertEqual('cauth',
                         response['service']['name'])
        self.assertEqual(set(['Password',
                              'Github',
                              'GithubPersonalAccessToken',
                              'OpenID',
                              'APIKey',
                              'SAML2']),
                         set(response['service']['auth_methods']))

    def test_api_key_crud_flow(self):
        payload = {'method': 'Password',
                   'back': 'r/',
                   'args': {'username': 'user2',
                            'password': 'userpass'}, }
        to_patch = 'cauth.utils.userdetails.UserDetailsCreator.create_user'
        with patch(to_patch) as cu:
            cu.return_value = 42
            with patch('requests.get'):
                # Not authenticated
                key_get = self.app.get('/apikey', status="*")
                self.assertEqual(401,
                                 key_get.status_int)
                # Authenticate
                response = self.app.post_json('/login',
                                              payload)
                self.assertEqual(303,
                                 response.status_int)
                # No key to begin with
                key_get = self.app.get('/apikey', status="*")
                self.assertEqual(404,
                                 key_get.status_int)
                good_cookie = common.create_ticket(cid=42, uid='user2')
                self.app.set_cookie('auth_pubtkt', good_cookie)
                key_get = self.app.get('/apikey', status="*")
                self.assertEqual(404,
                                 key_get.status_int)
                # create the API key
                key_create = self.app.post('/apikey?cauth_id=42')
                self.assertEqual(201,
                                 key_create.status_int)
                self.assertTrue('api_key' in key_create.json,
                                key_create.json)
                api_key = key_create.json['api_key']
                # let's check the API key out
                self.assertEqual(db.API_KEY_LEN,
                                 len(api_key),
                                 api_key)
                pool = string.ascii_letters + string.digits
                self.assertTrue(all(x in pool for x in api_key))
                # user2 can fetch the API key now
                key_get = self.app.get('/apikey?cauth_id=42')
                self.assertEqual(200,
                                 key_get.status_int)
                self.assertEqual(api_key,
                                 key_get.json['api_key'])
                # find out which key we want from the cookie
                key_get = self.app.get('/apikey')
                self.assertEqual(200,
                                 key_get.status_int)
                self.assertEqual(api_key,
                                 key_get.json['api_key'])
                # Key already exists
                key_create = self.app.post('/apikey?cauth_id=42', status="*")
                self.assertEqual(409,
                                 key_create.status_int)
                # Try to fetch the key authenticated as someone else
                self.app.reset()
                bad_cookie = common.create_ticket(cid=99, uid='user3')
                self.app.set_cookie('auth_pubtkt', bad_cookie)
                key_get = self.app.get('/apikey/?cauth_id=42', status="*")
                self.assertEqual(401,
                                 key_get.status_int)
                # can't get the goodies without a cookie
                self.app.reset()
                key_get = self.app.get('/apikey/?cauth_id=42', status="*")
                self.assertEqual(401,
                                 key_get.status_int)
                key_get = self.app.get('/apikey', status="*")
                self.assertEqual(401,
                                 key_get.status_int)
                # Delete the key
                self.app.set_cookie('auth_pubtkt', good_cookie)
                key_delete = self.app.delete('/apikey')
                self.assertEqual(204,
                                 key_delete.status_int)
                key_get = self.app.get('/apikey', status="*")
                self.assertEqual(404,
                                 key_get.status_int)
                # clean up
                self.app.reset()

    def test_api_key_login(self):
        payload = {'method': 'Password',
                   'back': 'r/',
                   'args': {'username': 'user3',
                            'password': 'userpass'}, }
        to_patch = 'cauth.utils.userdetails.UserDetailsCreator.create_user'
        with patch(to_patch) as cu:
            cu.return_value = 123
            with patch('requests.get'):
                response = self.app.post_json('/login',
                                              payload)
                good_cookie = common.create_ticket(cid=123, uid='user3')
                self.app.set_cookie('auth_pubtkt', good_cookie)
                # create the API key
                key_create = self.app.post('/apikey')
                self.assertEqual(201,
                                 key_create.status_int)
                api_key = key_create.json['api_key']
                self.app.reset()
                payload['method'] = 'APIKey'
                payload['args'] = {'api_key': api_key}
                response = self.app.post_json('/login',
                                              payload)
        self.assertEqual(response.status_int, 303)
        self.assertEqual('http://localhost/r/', response.headers['Location'])
        self.assertIn('Set-Cookie', response.headers)

    def test_saml2_login(self):
        to_patch = 'cauth.utils.userdetails.UserDetailsCreator.create_user'
        payload = {'method': 'SAML2',
                   'back': '/r/',
                   'args': {}, }
        with patch(to_patch) as cu:
            cu.return_value = 123
            saml_env = {'MELLON_login': 'wanpanman',
                        'MELLON_fullname': 'Caped Baldy',
                        'MELLON_email': 'swole@hero.org',
                        'MELLON_uid': '123456789',
                        'MELLON_keys': 'xxx:yyy:zzz',
                        'MELLON_group': 'C-rank',
                        'MELLON_group_0': 'C-rank',
                        'MELLON_group_1': 'B-rank',
                        'MELLON_group_2': 'S-rank',
                        'HTTP_REFERER': 'http://monster.org/idp'}
            response = self.app.post_json('/login/SAML2/',
                                          payload,
                                          extra_environ=saml_env)
            cu_args, cu_kwargs = cu.call_args
            self.assertEqual(1, len(cu_args))
            saitama = cu_args[0]
            self.assertEqual('wanpanman', saitama.get('login'), saitama)
            self.assertEqual('swole@hero.org', saitama.get('email'), saitama)
            self.assertEqual('Caped Baldy', saitama.get('name'), saitama)
            self.assertEqual('swole@hero.org', saitama.get('email'), saitama)
            self.assertEqual(
                '123456789',
                saitama.get('external_auth', {}).get('external_id'),
                saitama)
            self.assertEqual(
                'monster.org',
                saitama.get('external_auth', {}).get('domain'),
                saitama)
            self.assertTrue(len(saitama.get('ssh_keys', [])) > 0, saitama)
            for key in [u['key'] for u in saitama['ssh_keys']]:
                self.assertTrue(key in ['xxx', 'yyy', 'zzz'], saitama)
        self.assertEqual(response.status_int, 303)
        self.assertEqual('http://localhost/r/', response.headers['Location'])
        self.assertIn('Set-Cookie', response.headers)
        # check groups
        auth_tkt = response.headers['Set-Cookie'].split(';')[0]
        cookie = auth_tkt.split('=')[-1]
        try:
            cookie_dict = dict(x.split('=', 1)
                               for x in urllib2.unquote(cookie).split(';'))
        except Exception:
            raise Exception(urllib2.unquote(cookie).split(';'))
        self.assertTrue('groups' in cookie_dict, cookie_dict)
        groups = cookie_dict['groups'][1:-1].split('::')
        for rank in ['C', 'B', 'S']:
            self.assertTrue(('%s-rank' % rank) in groups, cookie_dict)


# In order to test collision strategies we simulate two Identity Providers
# with the same username registered in both places.
# The IdP are spoofed with 2 dummy auth plugins that always
# authenticate the user as "Spock", thus triggering a collision scenario.

# Here we do black magic to inject our dummy auth plugins into the namespace
d = pkg_resources.Distribution(__file__)
base_path = 'cauth.tests.fixtures.auth.dummies'
ep_map = {'cauth.authentication': {}}
for plugin_name, plugin_class in [('spock', 'SpockAuth'),
                                  ('evilspock', 'EvilSpockAuth')]:
    ep = pkg_resources.EntryPoint.parse(
        '%s = %s:%s' % (plugin_name, base_path, plugin_class))
    ep_map['cauth.authentication'].update({plugin_name: ep})
d._ep_map = ep_map
# Add the fake distribution to the global working_set
pkg_resources.working_set.add(d)


class TestCollisionStrategies(TestCase):
    def app_setup(self, strategy):
        c = dummy_conf()
        c.auth['spock'] = {}
        c.auth['evilspock'] = {}
        c.auth['login_collision_strategy'] = strategy
        config = {'managesf': c.managesf,
                  'app': c.app,
                  'auth': c.auth,
                  'services': c.services,
                  'sqlalchemy': c.sqlalchemy}
        gen_rsa_key()
        app = TestApp(load_app(config))
        return app

    def test_FORBID(self):
        app = self.app_setup("FORBID")
        with patch('requests.get'), patch('requests.post'):
            response = app.post_json('/login',
                                     {'method': 'spock',
                                      'back': 'r/',
                                      'args': {}})
            self.assertEqual(response.status_int, 303)
            response = app.post_json('/login',
                                     {'method': 'evilspock',
                                      'back': 'r/',
                                      'args': {}},
                                     status='*')
            # Assert that the error message contains info about the existing
            # user, no auth cookie set
            self.assertNotIn('Set-Cookie', response.headers)
            self.assertIn(dummies.SpockAuth.domain,
                          response.text, response)
            self.assertIn(
                dummies.SpockAuth.spock['external_auth']['external_id'],
                response.text, response)

    def test_DIFFERENTIATE(self):
        app = self.app_setup("DIFFERENTIATE")
        with patch('requests.get'), patch('requests.post'):
            response = app.post_json('/login',
                                     {'method': 'spock',
                                      'back': 'r/',
                                      'args': {}})
            self.assertEqual(response.status_int, 303)
            response = app.post_json('/login',
                                     {'method': 'evilspock',
                                      'back': 'r/',
                                      'args': {}},
                                     status='*')
            self.assertEqual(response.status_int, 303, response)
            auth_tkt = response.headers['Set-Cookie'].split(';')[0]
            cookie = auth_tkt.split('=')[-1]
            cookie_fields = urllib2.unquote(cookie).split(';')
            cookie = dict(x.split('=', 1) for x in cookie_fields)
            diff = differentiate(
                dummies.EvilSpockAuth.spock['login'],
                dummies.EvilSpockAuth.domain,
                dummies.EvilSpockAuth.spock['external_auth']['external_id'])
            self.assertEqual(diff,
                             cookie['uid'],
                             cookie)
