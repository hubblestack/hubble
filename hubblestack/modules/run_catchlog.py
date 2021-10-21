# -*- encoding: utf-8 -*-
"""
Run catchlog
============

"""
import logging
import time

log = logging.getLogger(__name__)


def run(*args, file_check=None, offset=30, search="Error", **kwargs):
    """
    This function allows a specific command to be run and searches for a
    keyword within a log file specified.

    args:
         The rest of the args for the command. Can be a string or a list.
    file_check:
        File to check for errors
    :offset:
        The last x lines of file
    """

    now = int(time.time())
    events = []
    ret = {"time": now, "sourcetype": "hubble_run_catchlog", "events": events}

    output = __mods__["safecommand.run"](*args, **kwargs)
    events.append(output)

    if file_check:
        try:
            with open(file_check, "r") as fh:
                for line in [line for line in fh.readlines()[-offset:] if search in line]:
                    events.append("[file_error_line]: " + line)
        except FileNotFoundError as e:
            events.append(f"{file_check} file not found")
            log.debug("%s file not found", file_check)
    return ret
