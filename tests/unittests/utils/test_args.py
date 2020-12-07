# -*- coding: utf-8 -*-

from collections import namedtuple
import logging

import hubblestack.utils.args

from tests.support.unit import TestCase, skipIf
from tests.support.mock import (
    DEFAULT,
    NO_MOCK,
    NO_MOCK_REASON,
    patch
)

log = logging.getLogger(__name__)


class ArgsTestCase(TestCase):
    '''
    TestCase for hubblestack.utils.args module
    '''

    def test_clean_kwargs(self):
        self.assertDictEqual(hubblestack.utils.args.clean_kwargs(foo='bar'), {'foo': 'bar'})
        self.assertDictEqual(hubblestack.utils.args.clean_kwargs(__pub_foo='bar'), {})
        self.assertDictEqual(hubblestack.utils.args.clean_kwargs(__foo_bar='gwar'), {})
        self.assertDictEqual(hubblestack.utils.args.clean_kwargs(foo_bar='gwar'), {'foo_bar': 'gwar'})
