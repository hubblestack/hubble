import hubblestack.fdg.process_status as process_status
import logging
import time

log = logging.getLogger(__name__)

__virtual_name__ = "process_tree"

SOURCETYPE = "hubble_process_tree"


def __virtual__():
    return __virtual_name__


def _get_processes():
    query = (
        "SELECT main.pid ppid, main.name pname, kids.pid pid, kids.name name "
        "FROM processes AS main JOIN processes AS kids ON kids.parent = main.pid "
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
    # sanity check
    if not processes:
        return None

    processes = {p["pid"]: p for p in processes}

    def ancestors(pid):
        ret = list()
        tmp = processes.get(pid)
        while tmp is not None:
            ret.append({"pid": tmp["pid"], "name": tmp["name"]})
            tmp = processes.get(tmp["ppid"])
        return ret

    now = int(time.time())
    events = [{"pid": p["pid"], "name": p["name"], "ancestors": ancestors(p["pid"])} for p in processes.values()]
    return {"time": now, "sourcetype": sourcetype, "events": events}
