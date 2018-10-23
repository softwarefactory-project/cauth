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

import hashlib
import uuid


def make_tid():
    """Return a new random string"""
    return hashlib.md5(str(uuid.uuid4())).hexdigest()[:8]


def ensure_tid(auth_context):
    """Return auth_context transactionID, generate one if missing"""
    transactionID = auth_context.get('transactionID')
    if not transactionID:
        auth_context['transactionID'] = make_tid()
    elif len(transactionID) != 8:
        raise RuntimeError("Invalid transaction ID: %s" % transactionID)
    return auth_context['transactionID']


class TransactionLogger(object):
    """TransactionID aware logging
    """

    def logger(self, level, message, *args):
        message = "[TID: %s] " + message
        getattr(self.log, level)(message, *args)

    def tdebug(self, message, *args):
        self.logger("debug", message, *args)

    def tinfo(self, message, *args):
        self.logger("info", message, *args)

    def twarning(self, message, *args):
        self.logger("warning", message, *args)

    def terror(self, message, *args):
        self.logger("error", message, *args)

    def texception(self, message, *args):
        self.logger("exception", message, *args)
