# Copyright (C) 2015 eNovance SAS <licensing@enovance.com>
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

import json
from unittest import TestCase

from mock import patch, Mock
from stevedore import driver

from cauth.tests.common import dummy_conf, FakeResponse


class TestGerritPlugin(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()

    @classmethod
    def tearDownClass(cls):
        pass

    def gerrit_get_account_id_mock(self, *args, **kwargs):
        data = json.dumps({'_account_id': 42})
        # Simulate the garbage that occurs in live tests
        data = 'garb' + data
        return FakeResponse(200, data)

    def gerrit_get_account_id_mock2(self, *args, **kwargs):
        data = json.dumps({'_account_id': 0})
        # Simulate the garbage that occurs in live tests
        data = 'garb' + data
        return FakeResponse(200, data)

    def test_create_managesf_user(self):
        msf = driver.DriverManager(
            namespace='cauth.service',
            name='managesf',
            invoke_on_load=True,
            invoke_args=(self.conf,)).driver
        with patch('cauth.service.managesf.requests.post') as post:
            msf.register_new_user({'login': 'john',
                                   'email': 'john@tests.dom',
                                   'name': 'John Doe',
                                   'ssh_keys': [],
                                   'external_id': 42})
            url = "%s/services_users/" % self.conf.managesf['url']
            data = {"full_name": "John Doe",
                    "email": "john@tests.dom",
                    "username": "john",
                    "ssh_keys": [],
                    'external_id': 42}
            headers = {"X-Remote-User": "admin"}
            post.assert_called_with(url,
                                    json=data,
                                    headers=headers)

    def test_create_repoxplorer_user(self):
        msf = driver.DriverManager(
            namespace='cauth.service',
            name='repoxplorer',
            invoke_on_load=True,
            invoke_args=(self.conf,)).driver

        with patch('cauth.service.managesf.requests.get') as get:
            with patch('cauth.service.managesf.requests.put') as put:
                with patch('cauth.service.managesf.requests.post') as post:
                    get.side_effect = lambda *args, **kwargs: FakeResponse(404)
                    msf.register_new_user({'login': 'john',
                                           'email': 'john@tests.dom',
                                           'emails': ['john@tests.dom'],
                                           'name': 'John Doe',
                                           'ssh_keys': [],
                                           'external_id': 42})
                    self.assertTrue(put.called)
                    self.assertFalse(post.called)

                    put.reset_mock()
                    post.reset_mock()

                    puser = {
                        'uid': 'saboten',
                        'name': 'Cactus Saboten',
                        'default-email': 'saboten@domain1',
                        'emails': [
                            {'email': 'saboten@domain1',
                             'groups': [
                                {'group': 'ugroup',
                                 'start-date': '2016-01-01',
                                 'end-date': '2016-01-09'}
                                 ]
                             }
                        ]
                    }
                    get.side_effect = lambda *args, **kwargs: FakeResponse(
                        200, json.dumps(puser), True)
                    msf.register_new_user({'login': 'john',
                                           'email': 'john@tests.dom',
                                           'emails': ['john@tests.dom'],
                                           'name': 'John Doe',
                                           'ssh_keys': [],
                                           'external_id': 42})
                    self.assertFalse(put.called)
                    self.assertTrue(post.called)

                    put.reset_mock()
                    post.reset_mock()

                    get.side_effect = Exception('fake')
                    msf.register_new_user({'login': 'john',
                                           'email': 'john@tests.dom',
                                           'emails': ['john@tests.dom'],
                                           'name': 'John Doe',
                                           'ssh_keys': [],
                                           'external_id': 42})
                    self.assertFalse(put.called)
                    self.assertFalse(post.called)
