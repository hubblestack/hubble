# -*- coding: utf-8 -*-
"""
Custom grains around fqdn
"""
import salt.grains.core
import salt.modules.cmdmod
import salt.utils
import salt.utils.platform
import socket

__salt__ = {'cmd.run': salt.modules.cmdmod._run_quiet,
            'cmd.run_all': salt.modules.cmdmod.run_all}


def fqdn():
    """
    Generate a secondary fqdn with `hostname --fqdn` since socket.getfqdn()
    appears to be susceptible to issues with DNS
    """
    grains = {}
    local_fqdn = None
    if not salt.utils.platform.is_windows():
        local_fqdn = __salt__['cmd.run']('hostname --fqdn')
    if local_fqdn and 'hostname: ' not in local_fqdn:
        grains['local_fqdn'] = local_fqdn
    return grains


def dest_ip():
    """
    Generate a best-guess at the IP on the interface that is the default
    gateway for the host. This is because the current methods can result in
    various IPs due to round robin DNS.
    """
    grains = {}
    interfaces = salt.grains.core.ip4_interfaces()['ip4_interfaces']
    try:
        ret = __salt__['cmd.run_all']('ip route show to 0/0')
        if ret['retcode'] == 0:
            interface = None
            try:
                interface = ret['stdout'].split(' ')[4]
            except:
                pass
            if interface and interface in interfaces and interfaces[interface]:
                for ip in interfaces[interface]:
                    if ip != '127.0.0.1':
                        return {'local_ip4': ip}
    except:
        pass

    # Fallback to "best guess"
    filtered_interfaces = {}
    # filter out empty, lo, and docker0
    for interface, ips in interfaces.iteritems():
        if not ips:
            continue
        if interface in ('lo', 'docker0'):
            continue
        filtered_interfaces[interface] = ips
    # Use eth0 if present
    if 'eth0' in filtered_interfaces:
        for ip in filtered_interfaces['eth0']:
            if ip != '127.0.0.1':
                return {'local_ip4': ip}
    # Use .*0 if present
    for interface, ips in filtered_interfaces.iteritems():
        if '0' in interface:
            for ip in ips:
                if ip != '127.0.0.1':
                    return {'local_ip4': ip}
    # Use whatever isn't 127.0.0.1
    for interface, ips in filtered_interfaces.iteritems():
        for ip in ips:
            if ip != '127.0.0.1':
                return {'local_ip4': ip}
    # Give up
    return {'local_ip4', ''}
