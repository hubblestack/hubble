# -*- coding: utf-8 -*-
'''
Unit tests for hubblestack.utils._compat
'''

import logging
import sys

from tests.support.unit import TestCase

import hubblestack.utils._compat as compat


log = logging.getLogger(__name__)
PY3 = sys.version_info.major == 3


class CompatTestCase(TestCase):
    def test_ipv6_class__is_packed_binary(self):
        ipv6 = compat.IPv6AddressScoped('2001:db8::')
        self.assertEqual(str(ipv6), '2001:db8::')

    def test_ipv6_class__is_packed_binary_integer(self):
        ipv6 = compat.IPv6AddressScoped(42540766411282592856903984951653826560)
        self.assertEqual(str(ipv6), '2001:db8::')

    def test_ipv6_class__is_packed_binary__issue_51831(self):
        ipv6 = compat.IPv6AddressScoped(b'sixteen.digit.bn')
        self.assertEqual(str(ipv6), '7369:7874:6565:6e2e:6469:6769:742e:626e')
