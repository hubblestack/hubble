#!/usr/bin/env python
# coding: utf-8

import socket
import pytest
from hubblestack.modules import dnsutil
from hubblestack.modules.dnsutil import HostNotFoundError


def test_dnsutil_A():
    lh = dnsutil.A("localhost")
    dg = dnsutil.A("dns.google")
    assert "127.0.0.1" in lh
    assert "8.8.8.8" in dg
    assert "8.8.4.4" in dg
    assert "::1" not in lh
    assert "2001:4860:4860::8888" not in dg
    assert "2001:4860:4860::8844" not in dg


def test_dnsutil_AAAA():
    lh = dnsutil.AAAA("localhost")
    dg = dnsutil.AAAA("dns.google")
    assert "::1" in lh
    assert "2001:4860:4860::8888" in dg
    assert "2001:4860:4860::8844" in dg
    assert "127.0.0.1" not in lh
    assert "8.8.8.8" not in dg
    assert "8.8.4.4" not in dg


def test_dnsutil_PTR():
    lh = dnsutil.PTR("127.0.0.1")
    dg = dnsutil.PTR("8.8.8.8")
    g6 = dnsutil.PTR("2001:4860:4860::8888")

    assert "localhost" == lh
    assert "dns.google" == dg
    assert "dns.google" == g6


def test_uidp(__opts__):
    res = dnsutil.unique_identifying_dns_ping()
    assert int(res["time"]) > 0
    assert res["sourcetype"] == "hubble_dns_uidp"
    assert len(res["events"]) == 1
    ev = res["events"][0]
    assert ev["result"] == "NXDOMAIN"
    assert ev["name"].endswith(".superfake.tld")
