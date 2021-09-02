# -*- coding: utf-8 -*-
""" Handle metadata about osquery: return version and path as grains """
import logging
import subprocess
import psutil

import hubblestack.utils.path
import hubblestack.modules.cmdmod

__mods__ = {"cmd.run": hubblestack.modules.cmdmod._run_quiet}

log = logging.getLogger(__name__)


def _osquery_host_state():
    """
    Query host's NETLINK subscriber interface for Auditd subscriptions that would
    hinder osquery data collection.

    The exclusion list comprises kernel PIDs like 0 and 1, and also numbers higher than
    the system's max_pid value.
    """
    grains = {"auditd_info": "auditd_present:False,auditd_status:None"}
    try:
        auditd_socket_status = subprocess.check_output(["systemctl", "status", "systemd-journald-audit.socket"])
        if b"active (running)" in auditd_socket_status:
            grains["auditd_info"] = "auditd_present:True,auditd_status:running"
            return grains
    except FileNotFoundError:
        log.debug("Unable to query systemd for auditd info, checking netlink...")

    excluded_pids = (0, 1, psutil.Process().pid)
    with open("/proc/sys/kernel/pid_max") as fobj:
        max_pid = int(fobj.read().strip())

    with open("/proc/net/netlink", "r") as content:
        next(content)  # skip the header
        for line in content:
            pid = line.strip().split()[2]

            pid = int(pid)
            if pid in excluded_pids or pid > max_pid:
                continue
            if psutil.pid_exists(pid):
                proc = psutil.Process(pid)
                if proc.name().rsplit("/", 1)[-1] == "auditd":
                    grains["auditd_info"] = f"auditd_present:True," f"auditd_status:{proc.status()}"
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
    option = "--version"

    # Prefer our /opt/osquery/osqueryi if present
    osqueryipaths = ("/opt/osquery/osqueryi", "osqueryi", "/usr/bin/osqueryi")
    for path in osqueryipaths:
        if hubblestack.utils.path.which(path):
            for item in __mods__["cmd.run"]("{0} {1}".format(path, option)).split():
                if item[:1].isdigit():
                    grains["osqueryversion"] = item
                    grains["osquerybinpath"] = hubblestack.utils.path.which(path)
                    break
            break
    grains.update(_osquery_host_state())
    return grains
