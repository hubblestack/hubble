# -*- coding: utf-8 -*-
""" Handle metadata about osquery: return version and path as grains """
import os
import socket

import hubblestack.utils.path
import hubblestack.modules.cmdmod

__mods__ = {'cmd.run': hubblestack.modules.cmdmod._run_quiet}


def _osquery_host_state():
    """
    Query host kernel process for NETLINK subscribers.
    """
    grains = {}
    sock = socket.socket(
        socket.AF_NETLINK,
        socket.SOCK_RAW,
        socket.NETLINK_ROUTE
    )
    sock.settimeout(10)
    sock.bind(os.getpid(), 0)
    sock.sendto(
        b"\x14\x00\x00\x00\x12\x00\x01\x03\x00\x00\x00\x00\xd5\x1b\x00\x00\x11\x00\x00\x00",
        (0, 0)
    )
    try:
        resp = sock.recvfrom(1024)
        if resp:
            grains["osquery_ready"] = True
    except:
        grains["osquery_ready"] = False
    finally:
        sock.close()
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
