#!/usr/bin/env python
# coding: utf-8

import socket
import uuid
import datetime


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
        uuid.uuid4(),  # uuid1 contains host network addr, uuid4 is "random"
        now.strftime("%Y%m%d-%H%M%S"),
        dom,
    )
    name = ".".join([str(x) for x in parts])
    try:
        res = A(name)
    except HostNotFoundError:
        res = "NXDOMAIN"

    event = dict(name=name, result=res)

    # this structure is meant to be groked by hubblestack/returners/splunk_generic_return.py
    return {"time": int(now.timestamp()), "sourcetype": "hubble_dns_uidp", "events": [event]}


def A(name):  # pylint: disable=invalid-name
    """
    Return the A record(s) for ``name``.

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
    Return the AAAA record(s) for ``name``.

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
    Return a PTR record for ``addr``.

    This function differs somewhat from A and AAAA above. It works on both ipv4
    and ipv6 addresses without having to reverse anything or spell out
    ".in-addr.arpa", but it also returns scalars rather than lists.

    socket.gethostbyaddr() does not return the convenient list of results that
    socket.getaddrinfo() does; so without implementing a heavy-weight actual
    DNS client, enumerating the list of PTR records isn't a resonable thing to
    do.

    ∴ PTR() returns a single scalar name, not a list; probably a round-robin
    result, assuming no other caching is taking place.

    CLI Example:

    .. code-block:: bash

        hubble dnsutil.PTR 8.8.8.8
        hubble dnsutil.PTR 2001:4860:4860::8888
    """
    try:
        name, *_ = socket.gethostbyaddr(addr)
        return name
    except socket.gaierror as e:
        raise HostNotFoundError(f"Unable to resolve {rev}") from e
