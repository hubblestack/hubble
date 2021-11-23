import hubblestack.fdg.process_status as process_status
import logging
import time

log = logging.getLogger(__name__)

__virtual_name__ = "process_tree"

SOURCETYPE = "hubble_process_tree"


def __virtual__():
    return __virtual_name__


def _get_processes():
    if not hasattr(process_status, "__mods__"):
        process_status.__mods__ = __mods__
    res = process_status._run_query("SELECT parent as ppid, name, pid from processes order by pid")
    try:
        ret = process_status._convert_to_str(res["data"])
    except (KeyError, TypeError):
        log.error("Invalid data type returned by osquery call %s.", res, exc_info=True)
        return None
    return ret


def tree(sourcetype=SOURCETYPE):
    """Return a list of dicts containing the `pid`, `name` and `ancestors` of all
    the processes.
    `ancestors` is a list of dicts containing the fields `name` and `pid`
    """
    processes = _get_processes()

    # sanity check
    if not processes:
        return None

    processes = {p["pid"]: p for p in processes}

    def ancestors(pid):
        ret = list()
        tmp = processes.get(processes.get(pid).get("ppid"))
        while tmp is not None:
            ret.append({"pid": tmp["pid"], "name": tmp["name"]})
            tmp = processes.get(tmp.get("ppid"))
        return ret

    now = int(time.time())
    events = [{"pid": p["pid"], "name": p["name"], "ancestors": ancestors(p["pid"])} for p in processes.values()]
    return {"time": now, "sourcetype": sourcetype, "events": events}
