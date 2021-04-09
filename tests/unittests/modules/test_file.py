# -*- coding: utf-8 -*-

# Import python libs
import os
import shutil
import tempfile
import textwrap

import hubblestack.modules.cmdmod as cmdmod
import hubblestack.modules.file as filemod
import hubblestack.modules.selinux
import hubblestack.utils.files
import hubblestack.utils.platform
import hubblestack.utils.stringutils
import hubblestack.modules.config as configmod
from hubblestack.exceptions import HubbleInvocationError

# Import Salt libs
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.mock import MagicMock, Mock, patch

# Import Salt Testing libs
from tests.support.runtests import RUNTIME_VARS
from tests.support.unit import TestCase, skipIf

try:
    import pytest
except ImportError:
    pytest = None


class DummyStat(object):
    st_mode = 33188
    st_ino = 115331251
    st_dev = 44
    st_nlink = 1
    st_uid = 99200001
    st_gid = 99200001
    st_size = 41743
    st_atime = 1552661253
    st_mtime = 1552661253
    st_ctime = 1552661253


class FileModuleTestCase(TestCase, LoaderModuleMockMixin):
    def setup_loader_modules(self):
        return {
            filemod: {
                "__mods__": {
                    "cmd.run": cmdmod.run,
                    "cmd.run_all": cmdmod.run_all,
                },
                "__opts__": {
                    "test": False,
                    "file_roots": {"base": "tmp"},
                    "pillar_roots": {"base": "tmp"},
                    "cachedir": "tmp",
                    "grains": {},
                },
                "__grains__": {"kernel": "Linux"},
                "__utils__": {"stringutils.get_diff": hubblestack.utils.stringutils.get_diff},
            }
        }

    def test_user_to_uid_int(self):
        """
        Tests if user is passed as an integer
        """
        user = 5034
        ret = filemod.user_to_uid(user)
        self.assertEqual(ret, user)

    def test_group_to_gid_int(self):
        """
        Tests if group is passed as an integer
        """
        group = 5034
        ret = filemod.group_to_gid(group)
        self.assertEqual(ret, group)

    def test_stats(self):
        with patch(
            "os.path.expanduser", MagicMock(side_effect=lambda path: path)
        ), patch("os.path.exists", MagicMock(return_value=True)), patch(
            "os.stat", MagicMock(return_value=DummyStat())
        ):
            ret = filemod.stats("dummy", None, True)
            self.assertEqual(ret["mode"], "0644")
            self.assertEqual(ret["type"], "file")


class FileBasicsTestCase(TestCase, LoaderModuleMockMixin):
    def setup_loader_modules(self):
        return {
            filemod: {
                "__mods__": {
                    "cmd.run": cmdmod.run,
                    "cmd.run_all": cmdmod.run_all,
                },
                "__opts__": {
                    "test": False,
                    "file_roots": {"base": "tmp"},
                    "pillar_roots": {"base": "tmp"},
                    "cachedir": "tmp",
                    "grains": {},
                },
                "__grains__": {"kernel": "Linux"},
            }
        }

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory)
        self.addCleanup(delattr, self, "directory")
        with tempfile.NamedTemporaryFile(delete=False, mode="w+") as self.tfile:
            self.tfile.write("Hi hello! I am a file.")
            self.tfile.close()
        self.addCleanup(os.remove, self.tfile.name)
        self.addCleanup(delattr, self, "tfile")
        self.myfile = os.path.join(RUNTIME_VARS.TMP, "myfile")
        with hubblestack.utils.files.fopen(self.myfile, "w+") as fp:
            fp.write(hubblestack.utils.stringutils.to_str("Hello\n"))
        self.addCleanup(os.remove, self.myfile)
        self.addCleanup(delattr, self, "myfile")


class LsattrTests(TestCase, LoaderModuleMockMixin):
    def setup_loader_modules(self):
        return {
            filemod: {"__mods__": {"cmd.run": cmdmod.run}},
        }

    def run(self, result=None):
        patch_aix = patch("hubblestack.utils.platform.is_aix", Mock(return_value=False),)
        patch_exists = patch("os.path.exists", Mock(return_value=True),)
        patch_which = patch("hubblestack.utils.path.which", Mock(return_value="fnord"),)
        with patch_aix, patch_exists, patch_which:
            super(LsattrTests, self).run(result)

    def test_if_lsattr_is_missing_it_should_return_None(self):
        patch_which = patch("hubblestack.utils.path.which", Mock(return_value=None),)
        with patch_which:
            actual = filemod.lsattr("foo")
            assert actual is None, actual

    def test_on_aix_lsattr_should_be_None(self):
        patch_aix = patch("hubblestack.utils.platform.is_aix", Mock(return_value=True),)
        with patch_aix:
            # SaltInvocationError will be raised if filemod.lsattr
            # doesn't early exit
            actual = filemod.lsattr("foo")
            self.assertIsNone(actual)

    def test_SaltInvocationError_should_be_raised_when_file_is_missing(self):
        patch_exists = patch("os.path.exists", Mock(return_value=False),)
        with patch_exists, self.assertRaises(HubbleInvocationError):
            filemod.lsattr("foo")

    def test_if_chattr_version_is_less_than_required_flags_should_ignore_extended(self):
        fname = "/path/to/fnord"
        with_extended = (
            textwrap.dedent(
                """
            aAcCdDeijPsStTu---- {}
            """
            )
            .strip()
            .format(fname)
        )
        expected = set("acdijstuADST")
        patch_has_ext = patch(
            "hubblestack.modules.file._chattr_has_extended_attrs", Mock(return_value=False),
        )
        patch_run = patch.dict(
            filemod.__mods__, {"cmd.run": Mock(return_value=with_extended)},
        )
        with patch_has_ext, patch_run:
            actual = set(filemod.lsattr(fname)[fname])
            msg = "Actual: {!r} Expected: {!r}".format(
                actual, expected
            )  # pylint: disable=E1322
            assert actual == expected, msg

    def test_if_chattr_version_is_high_enough_then_extended_flags_should_be_returned(
        self,
    ):
        fname = "/path/to/fnord"
        with_extended = (
            textwrap.dedent(
                """
            aAcCdDeijPsStTu---- {}
            """
            )
            .strip()
            .format(fname)
        )
        expected = set("aAcCdDeijPsStTu")
        patch_has_ext = patch(
            "hubblestack.modules.file._chattr_has_extended_attrs", Mock(return_value=True),
        )
        patch_run = patch.dict(
            filemod.__mods__, {"cmd.run": Mock(return_value=with_extended)},
        )
        with patch_has_ext, patch_run:
            actual = set(filemod.lsattr(fname)[fname])
            msg = "Actual: {!r} Expected: {!r}".format(
                actual, expected
            )  # pylint: disable=E1322
            assert actual == expected, msg

    def test_if_supports_extended_but_there_are_no_flags_then_none_should_be_returned(
        self,
    ):
        fname = "/path/to/fnord"
        with_extended = (
            textwrap.dedent(
                """
            ------------------- {}
            """
            )
            .strip()
            .format(fname)
        )
        expected = set("")
        patch_has_ext = patch(
            "hubblestack.modules.file._chattr_has_extended_attrs", Mock(return_value=True),
        )
        patch_run = patch.dict(
            filemod.__mods__, {"cmd.run": Mock(return_value=with_extended)},
        )
        with patch_has_ext, patch_run:
            actual = set(filemod.lsattr(fname)[fname])
            msg = "Actual: {!r} Expected: {!r}".format(
                actual, expected
            )  # pylint: disable=E1322
            assert actual == expected, msg


@skipIf(hubblestack.utils.platform.is_windows(), "Chattr shouldn't be available on Windows")
class ChattrTests(TestCase, LoaderModuleMockMixin):
    def setup_loader_modules(self):
        return {
            filemod: {
                "__mods__": {"cmd.run": cmdmod.run},
                "__opts__": {"test": False},
            },
        }

    def run(self, result=None):
        patch_aix = patch("hubblestack.utils.platform.is_aix", Mock(return_value=False),)
        patch_exists = patch("os.path.exists", Mock(return_value=True),)
        patch_which = patch("hubblestack.utils.path.which", Mock(return_value="some/tune2fs"),)
        with patch_aix, patch_exists, patch_which:
            super(ChattrTests, self).run(result)

    def test_chattr_version_returns_None_if_no_tune2fs_exists(self):
        patch_which = patch("hubblestack.utils.path.which", Mock(return_value=""),)
        with patch_which:
            actual = filemod._chattr_version()
            self.assertIsNone(actual)

    def test_on_aix_chattr_version_should_be_None_even_if_tune2fs_exists(self):
        patch_which = patch("hubblestack.utils.path.which", Mock(return_value="fnord"),)
        patch_aix = patch("hubblestack.utils.platform.is_aix", Mock(return_value=True),)
        mock_run = MagicMock(return_value="fnord")
        patch_run = patch.dict(filemod.__mods__, {"cmd.run": mock_run})
        with patch_which, patch_aix, patch_run:
            actual = filemod._chattr_version()
            self.assertIsNone(actual)
            mock_run.assert_not_called()

    def test_chattr_version_should_return_version_from_tune2fs(self):
        expected = "1.43.4"
        sample_output = textwrap.dedent(
            """
            tune2fs 1.43.4 (31-Jan-2017)
            Usage: tune2fs [-c max_mounts_count] [-e errors_behavior] [-f] [-g group]
            [-i interval[d|m|w]] [-j] [-J journal_options] [-l]
            [-m reserved_blocks_percent] [-o [^]mount_options[,...]]
            [-p mmp_update_interval] [-r reserved_blocks_count] [-u user]
            [-C mount_count] [-L volume_label] [-M last_mounted_dir]
            [-O [^]feature[,...]] [-Q quota_options]
            [-E extended-option[,...]] [-T last_check_time] [-U UUID]
            [-I new_inode_size] [-z undo_file] device
            """
        )
        patch_which = patch("hubblestack.utils.path.which", Mock(return_value="fnord"),)
        patch_run = patch.dict(
            filemod.__mods__, {"cmd.run": MagicMock(return_value=sample_output)},
        )
        with patch_which, patch_run:
            actual = filemod._chattr_version()
            self.assertEqual(actual, expected)

    def test_if_tune2fs_has_no_version_version_should_be_None(self):
        patch_which = patch("hubblestack.utils.path.which", Mock(return_value="fnord"),)
        patch_run = patch.dict(
            filemod.__mods__, {"cmd.run": MagicMock(return_value="fnord")},
        )
        with patch_which, patch_run:
            actual = filemod._chattr_version()
            self.assertIsNone(actual)

    def test_chattr_has_extended_attrs_should_return_False_if_chattr_version_is_None(
        self,
    ):
        patch_chattr = patch(
            "hubblestack.modules.file._chattr_version", Mock(return_value=None),
        )
        with patch_chattr:
            actual = filemod._chattr_has_extended_attrs()
            assert not actual, actual

    def test_chattr_has_extended_attrs_should_return_False_if_version_is_too_low(self):
        below_expected = "0.1.1"
        patch_chattr = patch(
            "hubblestack.modules.file._chattr_version", Mock(return_value=below_expected),
        )
        with patch_chattr:
            actual = filemod._chattr_has_extended_attrs()
            assert not actual, actual

    def test_chattr_has_extended_attrs_should_return_False_if_version_is_equal_threshold(
        self,
    ):
        threshold = "1.41.12"
        patch_chattr = patch(
            "hubblestack.modules.file._chattr_version", Mock(return_value=threshold),
        )
        with patch_chattr:
            actual = filemod._chattr_has_extended_attrs()
            assert not actual, actual

    def test_chattr_has_extended_attrs_should_return_True_if_version_is_above_threshold(
        self,
    ):
        higher_than = "1.41.13"
        patch_chattr = patch(
            "hubblestack.modules.file._chattr_version", Mock(return_value=higher_than),
        )
        with patch_chattr:
            actual = filemod._chattr_has_extended_attrs()
            assert actual, actual

    # We're skipping this on Windows as it tests the check_perms function in
    # file.py which is specifically for Linux. The Windows version resides in
    # win_file.py
    @skipIf(hubblestack.utils.platform.is_windows(), "Skip on Windows")
    def test_check_perms_should_report_no_attr_changes_if_there_are_none(self):
        filename = "/path/to/fnord"
        attrs = "aAcCdDeijPsStTu"

        higher_than = "1.41.13"
        patch_chattr = patch(
            "hubblestack.modules.file._chattr_version", Mock(return_value=higher_than),
        )
        patch_exists = patch("os.path.exists", Mock(return_value=True),)
        patch_stats = patch(
            "hubblestack.modules.file.stats",
            Mock(return_value={"user": "foo", "group": "bar", "mode": "123"}),
        )
        patch_run = patch.dict(
            filemod.__mods__,
            {"cmd.run": MagicMock(return_value="--------- " + filename)},
        )
        with patch_chattr, patch_exists, patch_stats, patch_run:
            actual_ret, actual_perms = filemod.check_perms(
                name=filename,
                ret=None,
                user="foo",
                group="bar",
                mode="123",
                attrs=attrs,
                follow_symlinks=False,
            )
            assert actual_ret.get("changes", {}).get("attrs") is None, actual_ret

    # We're skipping this on Windows as it tests the check_perms function in
    # file.py which is specifically for Linux. The Windows version resides in
    # win_file.py
    @skipIf(hubblestack.utils.platform.is_windows(), "Skip on Windows")
    def test_check_perms_should_report_attrs_new_and_old_if_they_changed(self):
        filename = "/path/to/fnord"
        attrs = "aAcCdDeijPsStTu"
        existing_attrs = "aeiu"
        expected = {
            "attrs": {"old": existing_attrs, "new": attrs},
        }

        higher_than = "1.41.13"
        patch_chattr = patch(
            "hubblestack.modules.file._chattr_version", Mock(return_value=higher_than),
        )
        patch_stats = patch(
            "hubblestack.modules.file.stats",
            Mock(return_value={"user": "foo", "group": "bar", "mode": "123"}),
        )
        patch_cmp = patch(
            "hubblestack.modules.file._cmp_attrs",
            MagicMock(
                side_effect=[
                    filemod.AttrChanges(added="aAcCdDeijPsStTu", removed="",),
                    filemod.AttrChanges(None, None,),
                ]
            ),
        )
        patch_chattr = patch("hubblestack.modules.file.chattr", MagicMock(),)

        def fake_cmd(cmd, *args, **kwargs):
            if cmd == ["lsattr", "/path/to/fnord"]:
                return textwrap.dedent(
                    """
                    {}---- {}
                    """.format(
                        existing_attrs, filename
                    )
                ).strip()
            else:
                assert False, "not sure how to handle {}".format(cmd)

        patch_run = patch.dict(
            filemod.__mods__, {"cmd.run": MagicMock(side_effect=fake_cmd)},
        )
        patch_ver = patch(
            "hubblestack.modules.file._chattr_has_extended_attrs",
            MagicMock(return_value=True),
        )
        with patch_chattr, patch_stats, patch_cmp, patch_run, patch_ver:
            actual_ret, actual_perms = filemod.check_perms(
                name=filename,
                ret=None,
                user="foo",
                group="bar",
                mode="123",
                attrs=attrs,
                follow_symlinks=False,
            )
            self.assertDictEqual(actual_ret["changes"], expected)


@skipIf(hubblestack.modules.selinux.getenforce() != "Enforcing", "Skip if selinux not enabled")
class FileSelinuxTestCase(TestCase, LoaderModuleMockMixin):
    def setup_loader_modules(self):
        return {
            filemod: {
                "__mods__": {
                    "cmd.run": cmdmod.run,
                    "cmd.run_all": cmdmod.run_all,
                    "cmd.retcode": cmdmod.retcode,
                    "selinux.fcontext_add_policy": MagicMock(
                        return_value={"retcode": 0, "stdout": ""}
                    ),
                },
                "__opts__": {"test": False},
            }
        }

    def setUp(self):
        # Read copy 1
        self.tfile1 = tempfile.NamedTemporaryFile(delete=False, mode="w+")

        # Edit copy 2
        self.tfile2 = tempfile.NamedTemporaryFile(delete=False, mode="w+")

        # Edit copy 3
        self.tfile3 = tempfile.NamedTemporaryFile(delete=False, mode="w+")

    def tearDown(self):
        os.remove(self.tfile1.name)
        del self.tfile1
        os.remove(self.tfile2.name)
        del self.tfile2
        os.remove(self.tfile3.name)
        del self.tfile3

    def test_selinux_getcontext(self):
        """
            Test get selinux context
            Assumes default selinux attributes on temporary files
        """
        result = filemod.get_selinux_context(self.tfile1.name)
        self.assertEqual(result, "unconfined_u:object_r:user_tmp_t:s0")

    def test_selinux_setcontext(self):
        """
            Test set selinux context
            Assumes default selinux attributes on temporary files
        """
        result = filemod.set_selinux_context(self.tfile2.name, user="system_u")
        self.assertEqual(result, "system_u:object_r:user_tmp_t:s0")

    def test_selinux_setcontext_persist(self):
        """
            Test set selinux context with persist=True
            Assumes default selinux attributes on temporary files
        """
        result = filemod.set_selinux_context(
            self.tfile2.name, user="system_u", persist=True
        )
        self.assertEqual(result, "system_u:object_r:user_tmp_t:s0")

    def test_file_check_perms(self):
        expected_result = (
            {
                "comment": "The file {0} is set to be changed".format(self.tfile3.name),
                "changes": {
                    "selinux": {"New": "Type: lost_found_t", "Old": "Type: user_tmp_t"},
                    "mode": "0644",
                },
                "name": self.tfile3.name,
                "result": True,
            },
            {"luser": "root", "lmode": "0600", "lgroup": "root"},
        )

        # Disable lsattr calls
        with patch("hubblestack.utils.path.which") as m_which:
            m_which.return_value = None
            result = filemod.check_perms(
                self.tfile3.name,
                {},
                "root",
                "root",
                644,
                seuser=None,
                serole=None,
                setype="lost_found_t",
                serange=None,
            )
            self.assertEqual(result, expected_result)
