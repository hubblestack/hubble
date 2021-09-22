import hubblestack.fdg.process_status as process_status
import logging
import time

log = logging.getLogger(__name__)

__virtual_name__ = "process_tree"

SOURCETYPE = "hubble_process_tree"


def __virtual__():
    process_status.__mods__ = __mods__
    return __virtual_name__


def _get_processes():
    query = (
        "SELECT main.pid ppid, main.name pname, kids.pid pid, kids.name name "
        "FROM processes as main join processes as kids on kids.parent = main.pid "
        "ORDER BY ppid"
    )
    res = process_status._run_query(query)
    try:
        ret = process_status._convert_to_str(res["data"])
    except (KeyError, TypeError):
        log.error("Invalid data type returned by osquery call %s.", res, exc_info=True)
        return None
    return ret


def tree(sourcetype=SOURCETYPE):
    """Return a list of dicts containing the `pid`, `name` and `children` of all
    the processes.
    `children` is a list of dicts containing the fields `name` and `pid`"""
    processes = _get_processes()
    now = int(time.time())
    # sanity check
    if not processes:
        return None
    events, prev_children = [], []
    prev_pid = 0
    prev_name = ""
    for process in processes:
        pid = process["ppid"]
        if pid != prev_pid:
            if prev_pid != 0:
                # finished collecting the children of the process with pid 'prev_pid'
                events.append({"pid": prev_pid, "name": prev_name, "children": prev_children})
            # reset
            prev_pid = pid
            prev_name = process["pname"]
            prev_children = []
        prev_children.append({"pid": process["pid"], "name": process["name"]})
    if prev_pid != 0:
        events.append({"pid": prev_pid, "name": prev_name, "children": prev_children})

    if events:
        return {"time": now, "sourcetype": sourcetype, "events": events}
    return None
