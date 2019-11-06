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


import yaml
import logging

from pecan import conf


class LocalGroup(object):
    def __init__(self, **kwargs):
        if not all(x in kwargs for x in ['name', 'description', 'members']):
            raise KeyError('missing init argument(s)')
        self.name = kwargs['name']
        self.description = kwargs['description']
        self.members = list(kwargs['members'])
        # what user property to check for membership lookup
        self.lookup_key = kwargs.get('lookup_key', 'email')


class LocalGroupsManager(object):
    """Loads local group definitions if any, and handles user lookups."""
    log = logging.getLogger("cauth.LocalGroupsManager")

    def __init__(self, config):
        self.groups = []
        self.groups_by_users = {}
        self.lookup_key = 'email'
        try:
            groups_config = config['groups']
        except Exception:
            self.log.info('No groups configuration found, '
                          'groups will not be available: %s' % conf)
            return
        try:
            local_groups_config = groups_config['local_groups']
        except Exception:
            self.log.info('No local groups configuration found, '
                          'groups will not be available')
            return
        if 'lookup_key' in local_groups_config:
            self.lookup_key = local_groups_config['lookup_key']
        self.log.debug('Loading "%s"' % local_groups_config['config_file'])
        try:
            with open(local_groups_config['config_file']) as gf:
                _groups = yaml.load(gf, Loader=yaml.SafeLoader)
            if not isinstance(_groups, dict):
                raise TypeError(
                    'Invalid groups definition file format: %s' % _groups)
            if 'groups' in _groups:
                self._cache_data(_groups['groups'])
            else:
                self._cache_data(_groups)
            self.log.debug('groups definition loaded')
        except Exception as e:
            self.log.error('Could not load groups definition file: %s' % e)

    def _cache_data(self, grps):
        for grp_name in grps:
            group = LocalGroup(name=grp_name, lookup_key=self.lookup_key,
                               **grps[grp_name])
            self.groups.append(group)
            for member in group.members:
                grp_list = self.groups_by_users.get(member, [])
                grp_list.append(group)
                self.groups_by_users[member] = grp_list

    def get_user_groups(self, user_data):
        self.log.debug(
            'looking up %s in %s' % (user_data, self.groups_by_users))
        if self.lookup_key not in user_data:
            self.log.error(
                'Lookup key "%s" missing for user %s' % (self.lookup_key,
                                                         user_data))
            return []
        return [x.name for x in
                self.groups_by_users.get(user_data[self.lookup_key], [])
                ]
