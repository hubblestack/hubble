# -*- coding: utf-8 -*-
"""
Populates grains which describe whether a server has a default gateway
configured or not. Uses `ip -4 route show` and `ip -6 route show` and greps
for a `default` at the beginning of any line.

If the `ip` command is unavailable, no grains will be populated.

Note: These grains will be present in salt 2018.2+, at which point this file
can be removed.

List of grains:

    ip4_gw: True  # True/False if default ipv4 gateway
    ip6_gw: True  # True/False if default ipv6 gateway
    ip_gw: True    # True if either of the above is True, False otherwise
"""


import logging

import salt.utils
import salt.utils.path

import salt.modules.cmdmod

__salt__ = {'cmd.run': salt.modules.cmdmod._run_quiet}
log = logging.getLogger(__name__)


def default_gateway():
    """
    Populates grains which describe whether a server has a default gateway
    configured or not. Uses `ip -4 route show` and `ip -6 route show` and greps
    for a `default` at the beginning of any line. Assuming the standard
    `default via <ip>` format for default gateways, it will also parse out the
    ip address of the default gateway, and put it in ip4_gw or ip6_gw.

    If the `ip` command is unavailable, no grains will be populated.

    List of grains:

        ip4_gw: True  # ip/True/False if default ipv4 gateway
        ip6_gw: True  # ip/True/False if default ipv6 gateway
        ip_gw: True   # True if either of the above is True, False otherwise
    """
    grains = {}
    if not salt.utils.path.which('ip'):
        return {}
    grains['ip_gw'] = False
    grains['ip4_gw'] = False
    grains['ip6_gw'] = False
    if __salt__['cmd.run']('ip -4 route show | grep "^default"', python_shell=True):
        grains['ip_gw'] = True
        grains['ip4_gw'] = True
        try:
            gateway_ip = __salt__['cmd.run']('ip -4 route show | grep "^default via"',
                                             python_shell=True).split(' ')[2].strip()
            grains['ip4_gw'] = gateway_ip if gateway_ip else True
        except Exception:
            pass
    if __salt__['cmd.run']('ip -6 route show | grep "^default"', python_shell=True):
        grains['ip_gw'] = True
        grains['ip6_gw'] = True
        try:
            gateway_ip = __salt__['cmd.run']('ip -6 route show | grep "^default via"',
                                             python_shell=True).split(' ')[2].strip()
            grains['ip6_gw'] = gateway_ip if gateway_ip else True
        except Exception:
            pass

    return grains
