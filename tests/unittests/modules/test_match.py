# -*- coding: utf-8 -*-
"""
    :codeauthor: Oleg Lipovchenko <oleg.lipovchenko@gmail.com>
"""

import hubblestack.loader
import hubblestack.matchers.compound_match as compound_match
import hubblestack.matchers.grain_match as grain_match
import hubblestack.matchers.list_match as list_match
import hubblestack.matchers.pcre_match as pcre_match
import hubblestack.modules.match as match

# Import Salt Testing libs
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.mock import MagicMock, patch
from tests.support.unit import TestCase

MATCHERS_DICT = {
    "compound_match.match": compound_match.match,
    "list_match.match": list_match.match,
    "pcre_match.match": pcre_match.match,
    "grain_match.match": grain_match.match
}

# the name of the minion to be used for tests
MINION_ID = "bar03"


@patch("hubblestack.loader.matchers", MagicMock(return_value=MATCHERS_DICT))
class MatchTestCase(TestCase, LoaderModuleMockMixin):
    """
    This class contains a set of functions that test salt.modules.match.
    """

    def setup_loader_modules(self):
        return {
            match: {"__opts__": {"extension_modules": "", "id": MINION_ID}},
            compound_match: {"__opts__": {"id": MINION_ID}},
            list_match: {"__opts__": {"id": MINION_ID}},
            grain_match: {"__opts__": {"id": MINION_ID}}
        }

    def test_compound_with_minion_id(self):
        """
        Make sure that when a minion_id IS past, that it is contained in opts
        """
        mock_compound_match = MagicMock()
        target = "bar04"
        new_minion_id = "new_minion_id"

        with patch.object(
            hubblestack.loader,
            "matchers",
            return_value={"compound_match.match": mock_compound_match},
        ) as matchers:
            match.compound(target, minion_id=new_minion_id)

            # The matcher should get called with MINION_ID
            matchers.assert_called_once()
            matchers_opts = matchers.call_args[0][0]
            self.assertEqual(matchers_opts.get("id"), new_minion_id)

            # The compound matcher should not get MINION_ID, no opts should be passed
            mock_compound_match.assert_called_once_with(target)

    def test_compound(self):
        """
        Test issue #55149
        """
        mock_compound_match = MagicMock()
        target = "bar04"

        with patch.object(
            hubblestack.loader,
            "matchers",
            return_value={"compound_match.match": mock_compound_match},
        ) as matchers:
            match.compound(target)

            # The matcher should get called with MINION_ID
            matchers.assert_called_once()
            self.assertEqual(len(matchers.call_args[0]), 1)
            self.assertEqual(matchers.call_args[0][0].get("id"), MINION_ID)

            # The compound matcher should not get MINION_ID, no opts should be passed
            mock_compound_match.assert_called_once_with(target)

    def test_watch_for_opts_mismatch_list_match(self):
        """
        Tests for situations where the list matcher might reference __opts__ directly
        instead of the local opts variable

        When metaproxies/proxy minions are in use, matchers get called with a different `opts`
        dictionary.  Inside the matchers we check to see if `opts` was passed
        and use it instead of `__opts__`.  If sometime in the future we update the matchers
        and use `__opts__` directly this breaks proxy matching.
        """
        self.assertTrue(list_match.match("bar03"))
        self.assertTrue(list_match.match("rest03", {"id": "rest03"}))
        self.assertFalse(list_match.match("rest03"))

    def test_watch_for_opts_mismatch_compound_match(self):
        """
        Tests for situations where the compound matcher might reference __opts__ directly
        instead of the local opts variable

        When metaproxies/proxy minions are in use, matchers get called with a different `opts`
        dictionary.  Inside the matchers we check to see if `opts` was passed
        and use it instead of `__opts__`.  If sometime in the future we update the matchers
        and use `__opts__` directly this breaks proxy matching.
        """
        self.assertTrue(compound_match.match("L@bar03"))
        self.assertTrue(compound_match.match("L@rest03", {"id": "rest03"}))
        self.assertFalse(compound_match.match("L@rest03"))
        self.assertFalse(compound_match.match("G@bar03"))

