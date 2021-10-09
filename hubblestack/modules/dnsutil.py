#!/usr/bin/env python
# coding: utf-8

import socket
import datetime
from hubblestack.utils.stdreq import get_fqdn


class HostNotFoundError(Exception):
    """exception for catching internal host not found results from A()"""

    pass


def unique_identifying_dns_ping(dom="superfake.tld"):
    """
    Send a dns A lookup out to the cloud. We don't really care about the
    result. The idea is to generate identifiable traffic to audit (or at least
    compare) to captured network traffic data.

    The first positional param (actually a keyword param "dom"), allows for
    changing the top level domain of the query. The default is "superfake.tld".
    Probably this is fine for situations where NXDOMAIN results are acceptable,
    since it's unlikely .tld will ever be a real top level domain.
    """

    now = datetime.datetime.utcnow()
    parts = (
        get_fqdn(),
        now.strftime("%Y%m%d-%H%M%S"),
        dom,
    )
    name = ".".join([x.replace(".", "-") for x in parts])
    try:
        res = A(name)
    except HostNotFoundError:
        res = "<not found>"

    event = dict(name=name, result=res)

    # this structure is meant to be groked by hubblestack/returners/splunk_generic_return.py
    return {"time": int(now.timestamp()), "sourcetype": "hubble_dns_uidp", "events": [event]}


def A(name):  # pylint: disable=invalid-name
    """
    Return the A record(s) for ``host``.

    Always returns a list.

    CLI Example:

    .. code-block:: bash

        hubble dnsutil.A google.com
    """

    try:
        addresses = [sock[4][0] for sock in socket.getaddrinfo(name, None, socket.AF_INET, 0, socket.SOCK_RAW)]
        return addresses
    except socket.gaierror as e:
        raise HostNotFoundError(f"Unable to resolve {name}") from e


def AAAA(name):  # pylint: disable=invalid-name
    """
    Return the AAAA record(s) for ``host``.

    Always returns a list.

    CLI Example:

    .. code-block:: bash

        hubble dnsutil.AAAA google.com
    """
    try:
        addresses = [sock[4][0] for sock in socket.getaddrinfo(name, None, socket.AF_INET6, 0, socket.SOCK_RAW)]
        return addresses
    except socket.gaierror as e:
        raise HostNotFoundError(f"Unable to resolve {name}") from e


def PTR(addr):  # pylint: disable=invalid-name
    """
    Return the PTR record(s) for ``ip_addr``.

    Always returns a list.

    CLI Example:

    .. code-block:: bash

        hubble dnsutil.PTR 8.8.8.8
    """
    rev = ".".join(reversed(host.split("."))) + ".in-addr.arpa" if not addr.endswith("in-addr.arpa") else addr
    try:
        name = [sock[4][0] for sock in socket.getaddrinfo(rev, None, socket.AF_INET, 0, socket.SOCK_RAW)]
        return name
    except socket.gaierror as e:
        raise HostNotFoundError(f"Unable to resolve {rev}") from e
