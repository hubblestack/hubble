#!/usr/bin/env python
# coding: utf-8

from hubblestack.modules import run_catchlog
from hubblestack.modules import safecommand
from hubblestack.utils.platform import is_windows
from hubblestack.utils.user import get_user
from hubblestack.utils.files import remove


def test_run():
    """
    test return of whoami in both safecommand module and run_catchlog
    """

    if not is_windows():
        usr = get_user()
        cmd_results = safecommand.run("whoami")
        safe_catchlog = run_catchlog.run("whoami")
        assert usr == safe_catchlog == cmd_results


def test_catchlog():
    """
    Ensure that run picks up error file as well as search string
    """

    with open("testing.txt", "w") as fh:
        fh.writelines("err blah testing")
    ret = run_catchlog.run(file_check="testing.txt", search="err")
    assert ret["events"] == ["[file_error_line]: err blah testing"]
    remove("testing.txt")
