# -*- coding: utf-8 -*-
'''
    :codeauthor: Bo Maryniuk (bo@suse.de)
    unit.utils.decorators_test
'''

# Import Python libs
from __future__ import absolute_import, print_function, unicode_literals

from hubblestack.utils.decorators.memoize import memoize
from unittest import skipIf, TestCase, mock

class DummyLogger(object):
    '''
    Dummy logger accepts everything and simply logs
    '''
    def __init__(self, messages):
        self._messages = messages

    def __getattr__(self, item):
        return self._log

    def _log(self, msg):
        self._messages.append(msg)


class DecoratorsTest(TestCase):
    '''
    Testing decorators.
    '''
    def old_function(self):
        return "old"

    def new_function(self):
        return "new"

    def _new_function(self):
        return "old"

    def setUp(self):
        '''
        Setup a test
        :return:
        '''
        self.globs = {
            '__virtualname__': 'test',
            '__opts__': {},
            '__pillar__': {},
            'old_function': self.old_function,
            'new_function': self.new_function,
            '_new_function': self._new_function,
        }
        self.addCleanup(delattr, self, 'globs')
        self.messages = list()
        self.addCleanup(delattr, self, 'messages')
        # # patcher = mock.patch.object(decorators, 'log', DummyLogger(self.messages))
        # patcher.start()
        # self.addCleanup(patcher.stop)

    def test_memoize_should_wrap_function(self):
        wrapped = memoize(self.old_function)
        assert wrapped.__module__ == self.old_function.__module__
