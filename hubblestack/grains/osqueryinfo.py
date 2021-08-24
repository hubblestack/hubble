# -*- coding: utf-8 -*-
""" Handle metadata about osquery: return version and path as grains """
import psutil

import hubblestack.utils.path
import hubblestack.modules.cmdmod

__mods__ = {'cmd.run': hubblestack.modules.cmdmod._run_quiet}


def _osquery_host_state():
    """
    Query host NETLINK subscriber interface for Auditd subscriptions that would
    hinder osquery data collection.
    """
    # should check if systemd-journald-audit.socket is configured too
    grains ={
        "auditd_stats": "auditd_present:False,auditd_status:None,auditd_pid:-1"
    }
    excluded_pids = (0, 1, psutil.Process().pid)
    with open("/proc/net/netlink", "r") as content:
        next(content)
        for line in content:
            pid = line.strip().split()[2]

            pid = int(pid)
            if pid in excluded_pids or pid > 2147483647:
                # our target process cannot be a kernel process, python itself
                # or have an ID higher then 2 ^ 31
                continue
            if psutil.pid_exists(pid):
                proc = psutil.Process(pid)
                if proc.name().rsplit('/', 1)[-1] == "auditd":
                    grains["auditd_stats"] = f"auditd_present:True," \
                    f"auditd_status:{proc.status()},auditd_pid:{proc.pid()}"
                    break
    return grains


def osquerygrain():
    """
    Return osquery version, osquery bin path, and host state regarding osquery
    data collection readiness in grain
    """
    # Provides:
    #   osqueryversion
    #   osquerybinpath
    grains = {}
    option = '--version'

    # Prefer our /opt/osquery/osqueryi if present
    osqueryipaths = ('/opt/osquery/osqueryi', 'osqueryi', '/usr/bin/osqueryi')
    for path in osqueryipaths:
        if hubblestack.utils.path.which(path):
            for item in __mods__['cmd.run']('{0} {1}'.format(path, option)).split():
                if item[:1].isdigit():
                    grains['osqueryversion'] = item
                    grains['osquerybinpath'] = hubblestack.utils.path.which(path)
                    break
            break
    grains.update(_osquery_host_state())
    return grains
