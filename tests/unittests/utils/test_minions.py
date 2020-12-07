# -*- coding: utf-8 -*-


# Import Hubble Libs
import hubblestack.utils.minions

# Import Salt Testing Libs
from tests.support.unit import TestCase

NODEGROUPS = {
    "group1": "L@host1,host2,host3",
    "group2": ["G@foo:bar", "or", "web1*"],
    "group3": ["N@group1", "or", "N@group2"],
    "group4": ["host4", "host5", "host6"],
    "group5": "N@group4",
    "group6": "N@group3",
    "group7": ["host1"],
}

EXPECTED = {
    "group1": ["L@host1,host2,host3"],
    "group2": ["G@foo:bar", "or", "web1*"],
    "group3": [
        "(",
        "(",
        "L@host1,host2,host3",
        ")",
        "or",
        "(",
        "G@foo:bar",
        "or",
        "web1*",
        ")",
        ")",
    ],
    "group4": ["L@host4,host5,host6"],
    "group5": ["(", "L@host4,host5,host6", ")"],
    "group6": [
        "(",
        "(",
        "(",
        "L@host1,host2,host3",
        ")",
        "or",
        "(",
        "G@foo:bar",
        "or",
        "web1*",
        ")",
        ")",
        ")",
    ],
    "group7": ["L@host1"],
}


class MinionsTestCase(TestCase):
    """
    TestCase for hubblestack.utils.minions module functions
    """

    def test_nodegroup_comp(self):
        """
        Test a simple string nodegroup
        """
        for nodegroup in NODEGROUPS:
            expected = EXPECTED[nodegroup]
            ret = hubblestack.utils.minions.nodegroup_comp(nodegroup, NODEGROUPS)
            self.assertEqual(ret, expected)


class TargetParseTestCase(TestCase):
    def test_parse_grains_target(self):
        """
        Ensure proper parsing for grains
        """
        g_tgt = "G@a:b"
        ret = hubblestack.utils.minions.parse_target(g_tgt)
        self.assertDictEqual(ret, {"engine": "G", "pattern": "a:b", "delimiter": None})

    def test_parse_grains_pcre_target(self):
        """
        Ensure proper parsing for grains PCRE matching
        """
        p_tgt = "P@a:b"
        ret = hubblestack.utils.minions.parse_target(p_tgt)
        self.assertDictEqual(ret, {"engine": "P", "pattern": "a:b", "delimiter": None})

    def test_parse_pillar_pcre_target(self):
        """
        Ensure proper parsing for pillar PCRE matching
        """
        j_tgt = "J@a:b"
        ret = hubblestack.utils.minions.parse_target(j_tgt)
        self.assertDictEqual(ret, {"engine": "J", "pattern": "a:b", "delimiter": None})

    def test_parse_list_target(self):
        """
        Ensure proper parsing for list matching
        """
        l_tgt = "L@a:b"
        ret = hubblestack.utils.minions.parse_target(l_tgt)
        self.assertDictEqual(ret, {"engine": "L", "pattern": "a:b", "delimiter": None})

    def test_parse_nodegroup_target(self):
        """
        Ensure proper parsing for pillar matching
        """
        n_tgt = "N@a:b"
        ret = hubblestack.utils.minions.parse_target(n_tgt)
        self.assertDictEqual(ret, {"engine": "N", "pattern": "a:b", "delimiter": None})

    def test_parse_subnet_target(self):
        """
        Ensure proper parsing for subnet matching
        """
        s_tgt = "S@a:b"
        ret = hubblestack.utils.minions.parse_target(s_tgt)
        self.assertDictEqual(ret, {"engine": "S", "pattern": "a:b", "delimiter": None})

    def test_parse_minion_pcre_target(self):
        """
        Ensure proper parsing for minion PCRE matching
        """
        e_tgt = "E@a:b"
        ret = hubblestack.utils.minions.parse_target(e_tgt)
        self.assertDictEqual(ret, {"engine": "E", "pattern": "a:b", "delimiter": None})

    def test_parse_range_target(self):
        """
        Ensure proper parsing for range matching
        """
        r_tgt = "R@a:b"
        ret = hubblestack.utils.minions.parse_target(r_tgt)
        self.assertDictEqual(ret, {"engine": "R", "pattern": "a:b", "delimiter": None})

    def test_parse_multiword_target(self):
        """
        Ensure proper parsing for multi-word targets

        Refs https://github.com/saltstack/salt/issues/37231
        """
        mw_tgt = "G@a:b c"
        ret = hubblestack.utils.minions.parse_target(mw_tgt)
        self.assertEqual(ret["pattern"], "a:b c")


class NodegroupCompTest(TestCase):
    """
    Test nodegroup comparisons found in
    hubblestack.utils.minions.nodgroup_comp()
    """

    def test_simple_nodegroup(self):
        """
        Smoke test a very simple nodegroup. No recursion.
        """
        simple_nodegroup = {
            "group1": "L@foo.domain.com,bar.domain.com,baz.domain.com or bl*.domain.com"
        }

        ret = hubblestack.utils.minions.nodegroup_comp("group1", simple_nodegroup)
        expected_ret = [
            "L@foo.domain.com,bar.domain.com,baz.domain.com",
            "or",
            "bl*.domain.com",
        ]
        self.assertListEqual(ret, expected_ret)

    def test_simple_expression_nodegroup(self):
        """
        Smoke test a nodegroup with a simple expression. No recursion.
        """
        simple_nodegroup = {"group1": "[foo,bar,baz].domain.com"}

        ret = hubblestack.utils.minions.nodegroup_comp("group1", simple_nodegroup)
        expected_ret = ["E@[foo,bar,baz].domain.com"]
        self.assertListEqual(ret, expected_ret)

    def test_simple_recurse(self):
        """
        Test a case where one nodegroup contains a second nodegroup
        """
        referenced_nodegroups = {
            "group1": "L@foo.domain.com,bar.domain.com,baz.domain.com or bl*.domain.com",
            "group2": "G@os:Debian and N@group1",
        }

        ret = hubblestack.utils.minions.nodegroup_comp("group2", referenced_nodegroups)
        expected_ret = [
            "(",
            "G@os:Debian",
            "and",
            "(",
            "L@foo.domain.com,bar.domain.com,baz.domain.com",
            "or",
            "bl*.domain.com",
            ")",
            ")",
        ]
        self.assertListEqual(ret, expected_ret)

    def test_circular_nodegroup_reference(self):
        """
        Test to see what happens if A refers to B
        and B in turn refers back to A
        """
        referenced_nodegroups = {"group1": "N@group2", "group2": "N@group1"}

        # If this works, it should also print an error to the console
        ret = hubblestack.utils.minions.nodegroup_comp("group1", referenced_nodegroups)
        self.assertEqual(ret, [])
