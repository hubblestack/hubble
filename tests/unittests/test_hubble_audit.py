#!/usr/bin/env python
# coding: utf-8


def test_hubble_audit_in_mods(__mods__):
    assert 'hubble.audit' in __mods__

def test_hubble_audit_returns_dict(__mods__):
    res = __mods__['hubble.audit']()
    assert isinstance(res, dict)
