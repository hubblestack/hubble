# -*- coding: utf-8 -*-
""" Handle metadata about osquery: return version and path as grains """
import logging
import subprocess

import psutil

import hubblestack.utils.path
import hubblestack.modules.cmdmod

__mods__ = {"cmd.run": hubblestack.modules.cmdmod._run_quiet}

log = logging.getLogger(__name__)


def osquery_host_state():
    """
    Query host's NETLINK subscriber interface for Auditd subscriptions that would
    hinder osquery data collection.

    The exclusion list comprises kernel PIDs like 0 and 1, and also numbers higher than
    the system's max_pid value.
    """
    deets = {
        "auditd_present": False,
        "systemd_journald_audit_socket": "unknown",
        "auditd_service": "unknown",
        "netlink_eth9_pids": "none found",
    }
    grains = {"auditd_info": deets}

    for grain_key, systemd_name in (
        ("systemd_journald_audit_socket", "systemd-journald-audit.socket"),
        ("auditd_service", "auditd.service"),
    ):
        try:
            auditd_socket_status = subprocess.check_output(["systemctl", "status", systemd_name])
            if b"active (running)" in auditd_socket_status:
                deets["auditd_present"] = True
                deets[grain_key] = True
            else:
                deets["auditd_present"] = True
                deets[grain_key] = "inactive"
        except subprocess.CalledProcessError:
            log.info("%s doesn't seem to be running according to systemd", systemd_name)
        except Exception as e:
            log.info("Unknown exception checking systemctl for %s status: %s", systemd_name, e)

    try:
        with open("/proc/sys/kernel/pid_max") as fobj:
            max_pid = int(fobj.read().strip())
    except FileNotFoundError:
        log.info("Unable to learn pid_max from /proc/sys/kernel/pid_max, guessing it's something like 128k")
        max_pid = 128e3

    excluded_pids = (0, 1, psutil.Process().pid)
    try:
        with open("/proc/net/netlink", "r") as content:
            next(content)  # skip the header
            for line in content:
                sline = line.strip().split()
                try:
                    eth = int(sline[1])
                    pid = int(sline[2])
                except TypeError:
                    continue

                if eth != 9:  # 9 is the auditd interface number. we believe it never changes
                    continue

                if pid in excluded_pids or pid > max_pid:
                    continue

                if psutil.pid_exists(pid):
                    proc = psutil.Process(pid)
                    name = proc.name()
                    if name.rsplit("/", 1)[-1] == "auditd":
                        if not isinstance(deets["netlink_eth9_pids"], list):
                            deets["netlink_eth9_pids"] = list()
                        deets["auditd_present"] = True
                        deets["netlink_eth9_pids"].append({"pid": pid, "name": name})
    except FileNotFoundError:
        log.info("Unable to interrogate /proc/net/netlink for eth=9 socket info")
        deets["netlink_missing"] = True

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
    return grains
