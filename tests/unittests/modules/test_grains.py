# -*- coding: utf-8 -*-

import os

import hubblestack.modules.grains as grainsmod
from hubblestack.utils.odict import OrderedDict

'''
# Import 3rd-party libs

# Import Salt Testing libs
'''
from tests.support.runtests import RUNTIME_VARS
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.mock import MagicMock, patch
from tests.support.unit import TestCase


class GrainsModuleTestCase(TestCase, LoaderModuleMockMixin):
    def setup_loader_modules(self):
        conf_file = os.path.join(RUNTIME_VARS.TMP, "__salt_test_grains")
        cachedir = os.path.join(RUNTIME_VARS.TMP, "__salt_test_grains_cache_dir")
        if not os.path.isdir(cachedir):
            os.makedirs(cachedir)
        return {
            grainsmod: {
                "__opts__": {"conf_file": conf_file, "cachedir": cachedir},
                "__salt__": {"saltutil.refresh_grains": MagicMock()},
            }
        }

    def test_get_ordered(self):
        with patch.dict(
            grainsmod.__grains__,
            OrderedDict(
                [
                    ("a", "aval"),
                    (
                        "b",
                        OrderedDict(
                            [
                                ("z", "zval"),
                                (
                                    "l1",
                                    ["l21", "l22", OrderedDict([("l23", "l23val")])],
                                ),
                            ]
                        ),
                    ),
                    ("c", 8),
                ]
            ),
        ):
            res = grainsmod.get("b")
            self.assertEqual(type(res), OrderedDict)
            # Check that order really matters
            self.assertTrue(
                res
                == OrderedDict(
                    [
                        ("z", "zval"),
                        ("l1", ["l21", "l22", OrderedDict([("l23", "l23val")])]),
                    ]
                )
            )
            self.assertFalse(
                res
                == OrderedDict(
                    [
                        ("l1", ["l21", "l22", OrderedDict([("l23", "l23val")])]),
                        ("z", "zval"),
                    ]
                )
            )

    def test_get_unordered(self):
        with patch.dict(
            grainsmod.__grains__,
            OrderedDict(
                [
                    ("a", "aval"),
                    (
                        "b",
                        OrderedDict(
                            [
                                ("z", "zval"),
                                (
                                    "l1",
                                    ["l21", "l22", OrderedDict([("l23", "l23val")])],
                                ),
                            ]
                        ),
                    ),
                    ("c", 8),
                ]
            ),
        ):
            res = grainsmod.get("b", ordered=False)
            self.assertEqual(type(res), dict)
            # Check that order doesn't matter
            self.assertTrue(
                res
                == OrderedDict(
                    [
                        ("l1", ["l21", "l22", OrderedDict([("l23", "l23val")])]),
                        ("z", "zval"),
                    ]
                )
            )

    def test_equals(self):
        with patch.dict(
            grainsmod.__grains__,
            OrderedDict(
                [
                    ("a", "aval"),
                    (
                        "b",
                        OrderedDict(
                            [
                                ("z", "zval"),
                                (
                                    "l1",
                                    ["l21", "l22", OrderedDict([("l23", "l23val")])],
                                ),
                            ]
                        ),
                    ),
                    ("c", 8),
                ]
            ),
        ):
            res = grainsmod.equals("a", "aval")
            self.assertEqual(type(res), bool)
            self.assertTrue(res)
            res = grainsmod.equals("b:z", "zval")
            self.assertTrue(res)
            res = grainsmod.equals("b:z", "aval")
            self.assertFalse(res)
