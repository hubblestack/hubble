# -*- coding: utf-8 -*-
"""
Tests for hubblestack.utils.json
"""
# Import Python libs

import textwrap
import hubblestack.utils.files
import hubblestack.utils.json
import hubblestack.utils.stringutils

# Import Salt Testing libs
from tests.support.helpers import with_tempfile
from tests.support.unit import TestCase


class JSONTestCase(TestCase):
    data = {
        "спам": "яйца",
        "list": [1, 2, "three"],
        "dict": {"subdict": {"спам": "яйца"}},
        "True": False,
        "float": 1.5,
        "None": None,
    }

    serialized = hubblestack.utils.stringutils.to_str(
        '{"None": null, "True": false, "dict": {"subdict": {"спам": "яйца"}},'
        ' "float": 1.5, "list": [1, 2, "three"], "спам": "яйца"}'
    )

    serialized_indent4 = hubblestack.utils.stringutils.to_str(
        textwrap.dedent(
            """\
        {
            "None": null,
            "True": false,
            "dict": {
                "subdict": {
                    "спам": "яйца"
                }
            },
            "float": 1.5,
            "list": [
                1,
                2,
                "three"
            ],
            "спам": "яйца"
        }"""
        )
    )

    def test_dumps_loads(self):
        """
        Test dumping to and loading from a string
        """
        # Dump with no indentation
        ret = hubblestack.utils.json.dumps(self.data, sort_keys=True)
        # Make sure the result is as expected
        self.assertEqual(ret, self.serialized)
        # Loading it should be equal to the original data
        self.assertEqual(hubblestack.utils.json.loads(ret), self.data)

        # Dump with 4 spaces of indentation
        ret = hubblestack.utils.json.dumps(self.data, sort_keys=True, indent=4)
        # Make sure the result is as expected. Note that in Python 2, dumping
        # results in trailing whitespace on lines ending in a comma. So, for a
        # proper comparison, we will have to run rstrip on each line of the
        # return and then stitch it back together.
        ret = str("\n").join(
            [x.rstrip() for x in ret.splitlines()]
        )  # future lint: disable=blacklisted-function
        self.assertEqual(ret, self.serialized_indent4)
        # Loading it should be equal to the original data
        self.assertEqual(hubblestack.utils.json.loads(ret), self.data)

    @with_tempfile()
    def test_dump_load(self, json_out):
        """
        Test dumping to and loading from a file handle
        """
        with hubblestack.utils.files.fopen(json_out, "wb") as fp_:
            fp_.write(hubblestack.utils.stringutils.to_bytes(hubblestack.utils.json.dumps(self.data)))
        with hubblestack.utils.files.fopen(json_out, "rb") as fp_:
            ret = hubblestack.utils.json.loads(hubblestack.utils.stringutils.to_unicode(fp_.read()))
            # Loading should be equal to the original data
            self.assertEqual(ret, self.data)
