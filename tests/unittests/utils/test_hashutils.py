# -*- coding: utf-8 -*-
import hubblestack.utils.hashutils

# Import Salt Testing libs
from tests.support.unit import TestCase


class HashutilsTestCase(TestCase):
    def test_get_hash_exception(self):
        self.assertRaises(
            ValueError, hubblestack.utils.hashutils.get_hash, "/tmp/foo/", form="INVALID"
        )
