#!/usr/bin/env python
# coding: utf-8

from hubblestack.utils.platform import is_windows
from hubblestack.utils.user import get_user
from hubblestack.utils.files import remove


def test_run(__mods__):
    """
    test return of whoami in both safecommand module and run_catchlog
    """

    if not is_windows():
        usr = get_user()
        cmd_results = __mods__["safecommand.run"]("whoami")
        safe_catchlog = __mods__["run_catchlog.run"]("whoami")
        assert usr == safe_catchlog["events"][0] == cmd_results


def test_catchlog(__mods__):
    """
    Ensure that run picks up error file as well as search string
    """

    with open("testing.txt", "w") as fh:
        fh.writelines("err blah testing")
    ret = __mods__["run_catchlog.run"]("echo", file_check="testing.txt", search="err")
    assert ret["events"][1] == "[file_error_line]: err blah testing"
    remove("testing.txt")
