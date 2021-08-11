# -*- coding: utf-8 -*-
""" Handle metadata about osquery: return version and path as grains """
import psutil
import subprocess

import hubblestack.utils.path
import hubblestack.modules.cmdmod

__mods__ = {'cmd.run': hubblestack.modules.cmdmod._run_quiet}


def _osquery_host_state():
    """
    Query host NETLINK subscriber interface for Auditd subscriptions that would
    hinder osquery data collection.
    """
    netlink_pids_raw = subprocess.check_output(["cat", "/proc/net/netlink"])
    netlink_pids = [
        line.split()[2] for line in netlink_pids_raw.strip().split(b'\n')[1:]
    ]
    for pid in netlink_pids:
        pid = int(pid)
        # PIDs 0 and 1 should be excluded as they are kernel processes
        if pid in (0, 1):
            continue
        try:
            proc = psutil.Process(pid)
            # this is useless if there are any processes, other than auditd,
            # that might prevent osquery from working.
            # the osquery docs only mention auditd as a blocker
            # but one cannot be too sure. but this makes everyone of them
            # a suspect
            if proc.name().rsplit('/', 1)[-1] == 'auditd' and proc.status() == psutil.STATUS_RUNNING:
                return {"osquery_readiness": False}
        except psutil.NoSuchProcess:
            continue
    return {"osquery_readiness": True}


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
