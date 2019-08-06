# coding: utf-8
"""
Overriding the get_fqhostname function of salt.utils.network
The fix has been copied from https://github.com/saltstack/salt/pull/49726
"""

import socket
import logging
import socket
import salt.utils.network

import salt.utils.network

log = logging.getLogger(__name__)


def get_fqhostname():
    # Overriding the default function of salt becuase it lacks handling of
    # socket.error exception
    # The fix has been copied from https://github.com/saltstack/salt/pull/49726
    """
    Returns the fully qualified hostname
    """
    # try getaddrinfo()
    fqdn = None
    try:
        addrinfo = socket.getaddrinfo(
            socket.gethostname(), 0, socket.AF_UNSPEC, socket.SOCK_STREAM,
            socket.SOL_TCP, socket.AI_CANONNAME
        )
        for info in addrinfo:
            # info struct [family, socktype, proto, canonname, sockaddr]
            # On Windows `canonname` can be an empty string
            # This can cause the function to return `None`
            if len(info) > 3 and info[3]:
                fqdn = info[3]
                break
    except socket.gaierror:
        pass  # NOTE: this used to log.error() but it was later disabled
    except socket.error as err:
        log.debug('socket.getaddrinfo() failure while finding fqdn: %s', err)
    if fqdn is None:
        fqdn = socket.getfqdn()
    return fqdn

# install override
salt.utils.network.get_fqhostname = get_fqhostname
