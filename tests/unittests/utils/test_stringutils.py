# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals
import re
import sys
import textwrap
import builtins

# Import Salt libs
from tests.support.mock import patch
from tests.support.unit import TestCase, LOREM_IPSUM
import hubblestack.utils.stringutils

UNICODE = '中国語 (繁体)'
STR = BYTES = UNICODE.encode('utf-8')
# This is an example of a unicode string with й constructed using two separate
# code points. Do not modify it.
EGGS = '\u044f\u0438\u0306\u0446\u0430'

LATIN1_UNICODE = 'räksmörgås'
LATIN1_BYTES = LATIN1_UNICODE.encode('latin-1')

DOUBLE_TXT = '''\
# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "$debian_chroot" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
'''

SINGLE_TXT = '''\
# set variable identifying the chroot you work in (used in the prompt below)
if [ -z '$debian_chroot' ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
'''

SINGLE_DOUBLE_TXT = '''\
# set variable identifying the chroot you work in (used in the prompt below)
if [ -z '$debian_chroot' ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "$debian_chroot" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
'''

SINGLE_DOUBLE_SAME_LINE_TXT = '''\
# set variable identifying the chroot you work in (used in the prompt below)
if [ -z '$debian_chroot' ] && [ -r "/etc/debian_chroot" ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
'''

MATCH = '''\
# set variable identifying the chroot you work in (used in the prompt below)
if [ -z '$debian_chroot' ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi


# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "$debian_chroot" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi


# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "$debian_chroot" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi


# set variable identifying the chroot you work in (used in the prompt below)
if [ -z '$debian_chroot' ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi


# set variable identifying the chroot you work in (used in the prompt below)
if [ -z '$debian_chroot' ] && [ -r "/etc/debian_chroot" ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
'''

class StringutilsTestCase(TestCase):
    def test_to_num(self):
        self.assertEqual(7, hubblestack.utils.stringutils.to_num('7'))
        self.assertIsInstance(hubblestack.utils.stringutils.to_num('7'), int)
        self.assertEqual(7, hubblestack.utils.stringutils.to_num('7.0'))
        self.assertIsInstance(hubblestack.utils.stringutils.to_num('7.0'), float)
        self.assertEqual(hubblestack.utils.stringutils.to_num('Seven'), 'Seven')
        self.assertIsInstance(hubblestack.utils.stringutils.to_num('Seven'), str)

    def test_is_binary(self):
        self.assertFalse(hubblestack.utils.stringutils.is_binary(LOREM_IPSUM))
        # Also test bytestring
        self.assertFalse(
            hubblestack.utils.stringutils.is_binary(
                hubblestack.utils.stringutils.is_binary(LOREM_IPSUM)
            )
        )

        zero_str = '{0}{1}'.format(LOREM_IPSUM, '\0')
        self.assertTrue(hubblestack.utils.stringutils.is_binary(zero_str))
        # Also test bytestring
        self.assertTrue(
            hubblestack.utils.stringutils.is_binary(
                hubblestack.utils.stringutils.to_bytes(zero_str)
            )
        )

        # To to ensure safe exit if str passed doesn't evaluate to True
        self.assertFalse(hubblestack.utils.stringutils.is_binary(''))
        self.assertFalse(hubblestack.utils.stringutils.is_binary(b''))

        nontext = 3 * (''.join([chr(x) for x in range(1, 32) if x not in (8, 9, 10, 12, 13)]))
        almost_bin_str = '{0}{1}'.format(LOREM_IPSUM[:100], nontext[:42])
        self.assertFalse(hubblestack.utils.stringutils.is_binary(almost_bin_str))
        # Also test bytestring
        self.assertFalse(
            hubblestack.utils.stringutils.is_binary(
                hubblestack.utils.stringutils.to_bytes(almost_bin_str)
            )
        )

        bin_str = almost_bin_str + '\x01'
        self.assertTrue(hubblestack.utils.stringutils.is_binary(bin_str))
        # Also test bytestring
        self.assertTrue(
            hubblestack.utils.stringutils.is_binary(
                hubblestack.utils.stringutils.to_bytes(bin_str)
            )
        )

    def test_get_context(self):
        expected_context = textwrap.dedent('''\
            ---
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque eget urna a arcu lacinia sagittis.
            Sed scelerisque, lacus eget malesuada vestibulum, justo diam facilisis tortor, in sodales dolor
            [...]
            ---''')
        ret = hubblestack.utils.stringutils.get_context(LOREM_IPSUM, 1, num_lines=1)
        self.assertEqual(ret, expected_context)

    def test_get_context_has_enough_context(self):
        template = '1\n2\n3\n4\n5\n6\n7\n8\n9\na\nb\nc\nd\ne\nf'
        context = hubblestack.utils.stringutils.get_context(template, 8)
        expected = '---\n[...]\n3\n4\n5\n6\n7\n8\n9\na\nb\nc\nd\n[...]\n---'
        self.assertEqual(expected, context)

    def test_get_context_at_top_of_file(self):
        template = '1\n2\n3\n4\n5\n6\n7\n8\n9\na\nb\nc\nd\ne\nf'
        context = hubblestack.utils.stringutils.get_context(template, 1)
        expected = '---\n1\n2\n3\n4\n5\n6\n[...]\n---'
        self.assertEqual(expected, context)

    def test_get_context_at_bottom_of_file(self):
        template = '1\n2\n3\n4\n5\n6\n7\n8\n9\na\nb\nc\nd\ne\nf'
        context = hubblestack.utils.stringutils.get_context(template, 15)
        expected = '---\n[...]\na\nb\nc\nd\ne\nf\n---'
        self.assertEqual(expected, context)

    def test_get_context_2_context_lines(self):
        template = '1\n2\n3\n4\n5\n6\n7\n8\n9\na\nb\nc\nd\ne\nf'
        context = hubblestack.utils.stringutils.get_context(template, 8, num_lines=2)
        expected = '---\n[...]\n6\n7\n8\n9\na\n[...]\n---'
        self.assertEqual(expected, context)

    def test_get_context_with_marker(self):
        template = '1\n2\n3\n4\n5\n6\n7\n8\n9\na\nb\nc\nd\ne\nf'
        context = hubblestack.utils.stringutils.get_context(template, 8, num_lines=2, marker=' <---')
        expected = '---\n[...]\n6\n7\n8 <---\n9\na\n[...]\n---'
        self.assertEqual(expected, context)

    def test_to_str(self):
        for x in (123, (1, 2, 3), [1, 2, 3], {1: 23}, None):
            self.assertRaises(TypeError, hubblestack.utils.stringutils.to_str, x)
        self.assertEqual(hubblestack.utils.stringutils.to_str('plugh'), 'plugh')
        self.assertEqual(hubblestack.utils.stringutils.to_str('áéíóúý', 'utf-8'), 'áéíóúý')
        self.assertEqual(hubblestack.utils.stringutils.to_str(BYTES, 'utf-8'), UNICODE)
        self.assertEqual(hubblestack.utils.stringutils.to_str(bytearray(BYTES), 'utf-8'), UNICODE)
        # Test situation when a minion returns incorrect utf-8 string because of... million reasons
        ut2 = b'\x9c'
        self.assertRaises(UnicodeDecodeError, hubblestack.utils.stringutils.to_str, ut2, 'utf-8')
        self.assertEqual(hubblestack.utils.stringutils.to_str(ut2, 'utf-8', 'replace'), u'\ufffd')
        self.assertRaises(UnicodeDecodeError, hubblestack.utils.stringutils.to_str, bytearray(ut2), 'utf-8')
        self.assertEqual(hubblestack.utils.stringutils.to_str(bytearray(ut2), 'utf-8', 'replace'), u'\ufffd')

    def test_to_bytes(self):
        for x in (123, (1, 2, 3), [1, 2, 3], {1: 23}, None):
            self.assertRaises(TypeError, hubblestack.utils.stringutils.to_bytes, x)
        self.assertEqual(hubblestack.utils.stringutils.to_bytes('xyzzy'), b'xyzzy')
        self.assertEqual(hubblestack.utils.stringutils.to_bytes(BYTES), BYTES)
        self.assertEqual(hubblestack.utils.stringutils.to_bytes(bytearray(BYTES)), BYTES)
        self.assertEqual(hubblestack.utils.stringutils.to_bytes(UNICODE, 'utf-8'), BYTES)

        # Test utf-8 fallback with ascii default encoding
        with patch.object(builtins, '__salt_system_encoding__', 'ascii'):
            self.assertEqual(hubblestack.utils.stringutils.to_bytes('Ψ'), b'\xce\xa8')

    def test_to_unicode(self):
        self.assertEqual(
            hubblestack.utils.stringutils.to_unicode(
                EGGS,
                normalize=True
            ),
            'яйца'
        )
        self.assertNotEqual(
            hubblestack.utils.stringutils.to_unicode(
                EGGS,
                normalize=False
            ),
            'яйца'
        )

        self.assertEqual(
            hubblestack.utils.stringutils.to_unicode(
                LATIN1_BYTES, encoding='latin-1'
            ),
            LATIN1_UNICODE
        )

        self.assertEqual(hubblestack.utils.stringutils.to_unicode('plugh'), 'plugh')
        self.assertEqual(hubblestack.utils.stringutils.to_unicode('áéíóúý'), 'áéíóúý')
        self.assertEqual(hubblestack.utils.stringutils.to_unicode(BYTES, 'utf-8'), UNICODE)
        self.assertEqual(hubblestack.utils.stringutils.to_unicode(bytearray(BYTES), 'utf-8'), UNICODE)

    def test_to_unicode_multi_encoding(self):
        result = hubblestack.utils.stringutils.to_unicode(LATIN1_BYTES, encoding=('utf-8', 'latin1'))
        assert result == LATIN1_UNICODE

    def test_expr_match(self):
        val = "foo/bar/baz"
        # Exact match
        self.assertTrue(hubblestack.utils.stringutils.expr_match(val, val))
        # Glob match
        self.assertTrue(hubblestack.utils.stringutils.expr_match(val, "foo/*/baz"))
        # Glob non-match
        self.assertFalse(hubblestack.utils.stringutils.expr_match(val, "foo/*/bar"))
        # Regex match
        self.assertTrue(hubblestack.utils.stringutils.expr_match(val, r"foo/\w+/baz"))
        # Regex non-match
        self.assertFalse(hubblestack.utils.stringutils.expr_match(val, r"foo/\w/baz"))

    def test_check_whitelist_blacklist(self):
        """
        Ensure that whitelist matching works on both PY2 and PY3
        """
        whitelist = ["one/two/three", r"web[0-9]"]
        blacklist = ["four/five/six", r"web[5-9]"]

        # Tests with string whitelist/blacklist
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_one", whitelist=whitelist[1], blacklist=None,
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_one", whitelist=whitelist[1], blacklist=[],
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web1", whitelist=whitelist[1], blacklist=None,
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web1", whitelist=whitelist[1], blacklist=[],
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web5", whitelist=None, blacklist=blacklist[1],
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web5", whitelist=[], blacklist=blacklist[1],
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_five", whitelist=None, blacklist=blacklist[1],
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_five", whitelist=[], blacklist=blacklist[1],
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web5", whitelist=whitelist[1], blacklist=blacklist[1],
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web4", whitelist=whitelist[1], blacklist=blacklist[1],
            )
        )

        # Tests with list whitelist/blacklist
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_one", whitelist=whitelist, blacklist=None,
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_one", whitelist=whitelist, blacklist=[],
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web1", whitelist=whitelist, blacklist=None,
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web1", whitelist=whitelist, blacklist=[],
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web5", whitelist=None, blacklist=blacklist,
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web5", whitelist=[], blacklist=blacklist,
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_five", whitelist=None, blacklist=blacklist,
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_five", whitelist=[], blacklist=blacklist,
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web5", whitelist=whitelist, blacklist=blacklist,
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web4", whitelist=whitelist, blacklist=blacklist,
            )
        )

        # Tests with set whitelist/blacklist
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_one", whitelist=set(whitelist), blacklist=None,
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_one", whitelist=set(whitelist), blacklist=set(),
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web1", whitelist=set(whitelist), blacklist=None,
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web1", whitelist=set(whitelist), blacklist=set(),
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web5", whitelist=None, blacklist=set(blacklist),
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web5", whitelist=set(), blacklist=set(blacklist),
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_five", whitelist=None, blacklist=set(blacklist),
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web_five", whitelist=set(), blacklist=set(blacklist),
            )
        )
        self.assertFalse(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web5", whitelist=set(whitelist), blacklist=set(blacklist),
            )
        )
        self.assertTrue(
            hubblestack.utils.stringutils.check_whitelist_blacklist(
                "web4", whitelist=set(whitelist), blacklist=set(blacklist),
            )
        )

        # Test with invalid type for whitelist/blacklist
        self.assertRaises(
            TypeError,
            hubblestack.utils.stringutils.check_whitelist_blacklist,
            "foo",
            whitelist=123,
        )
        self.assertRaises(
            TypeError,
            hubblestack.utils.stringutils.check_whitelist_blacklist,
            "foo",
            blacklist=123,
        )

