# -*- coding: utf-8 -*-
'''
Compendium of generic DNS utilities
# Examples:
dns.lookup(name, rdtype, ...)
dns.query(name, rdtype, ...)

dns.srv_rec(data)
dns.srv_data('my1.example.com', 389, prio=10, weight=100)
dns.srv_name('ldap/tcp', 'example.com')

'''

# Import Python libs
import base64
import binascii
import hashlib
import itertools
import logging
import random
import re
import shlex
import socket
import ssl
import string
import functools

import hubblestack.utils.files
import hubblestack.utils.network
import hubblestack.utils.stringutils
from hubblestack.utils._compat import ipaddress

log = logging.getLogger(__name__)

def parse_resolv(src='/etc/resolv.conf'):
    '''
    Parse a resolver configuration file (traditionally /etc/resolv.conf)
    '''

    nameservers = []
    ip4_nameservers = []
    ip6_nameservers = []
    search = []
    sortlist = []
    domain = ''
    options = []

    try:
        with hubblestack.utils.files.fopen(src) as src_file:
            # pylint: disable=too-many-nested-blocks
            for line in src_file:
                line = hubblestack.utils.stringutils.to_unicode(line).strip().split()

                try:
                    (directive, arg) = (line[0].lower(), line[1:])
                    # Drop everything after # or ; (comments)
                    arg = list(itertools.takewhile(lambda x: x[0] not in ('#', ';'), arg))
                    if directive == 'nameserver':
                        addr = arg[0]
                        try:
                            ip_addr = ipaddress.ip_address(addr)
                            version = ip_addr.version
                            ip_addr = str(ip_addr)
                            if ip_addr not in nameservers:
                                nameservers.append(ip_addr)
                            if version == 4 and ip_addr not in ip4_nameservers:
                                ip4_nameservers.append(ip_addr)
                            elif version == 6 and ip_addr not in ip6_nameservers:
                                ip6_nameservers.append(ip_addr)
                        except ValueError as exc:
                            log.error('%s: %s', src, exc)
                    elif directive == 'domain':
                        domain = arg[0]
                    elif directive == 'search':
                        search = arg
                    elif directive == 'sortlist':
                        # A sortlist is specified by IP address netmask pairs.
                        # The netmask is optional and defaults to the natural
                        # netmask of the net. The IP address and optional
                        # network pairs are separated by slashes.
                        for ip_raw in arg:
                            try:
                                ip_net = ipaddress.ip_network(ip_raw)
                            except ValueError as exc:
                                log.error('%s: %s', src, exc)
                            else:
                                if '/' not in ip_raw:
                                    # No netmask has been provided, guess
                                    # the "natural" one
                                    if ip_net.version == 4:
                                        ip_addr = str(ip_net.network_address)
                                        # pylint: disable=protected-access
                                        mask = hubblestack.utils.network.natural_ipv4_netmask(ip_addr)
                                        ip_net = ipaddress.ip_network(
                                            '{0}{1}'.format(ip_addr, mask),
                                            strict=False
                                        )
                                    if ip_net.version == 6:
                                        # TODO
                                        pass

                                if ip_net not in sortlist:
                                    sortlist.append(ip_net)
                    elif directive == 'options':
                        # Options allows certain internal resolver variables to
                        # be modified.
                        if arg[0] not in options:
                            options.append(arg[0])
                except IndexError:
                    continue

        if domain and search:
            # The domain and search keywords are mutually exclusive.  If more
            # than one instance of these keywords is present, the last instance
            # will override.
            log.debug(
                '%s: The domain and search keywords are mutually exclusive.',
                src
            )

        return {
            'nameservers':     nameservers,
            'ip4_nameservers': ip4_nameservers,
            'ip6_nameservers': ip6_nameservers,
            'sortlist':        [ip.with_netmask for ip in sortlist],
            'domain':          domain,
            'search':          search,
            'options':         options
        }
    except IOError:
        return {}
