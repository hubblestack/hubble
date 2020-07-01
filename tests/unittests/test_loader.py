#!/usr/bin/env python
# coding: utf-8

import os
import pytest

import hubblestack.loader as L
import hubblestack.daemon as D

@pytest.fixture(scope='module')
def module_dirs():
    D.load_config(args=[])
    md = L._module_dirs(D.__opts__, 'modules', 'module')
    return md

def test_module_dirs(module_dirs):
    for item in module_dirs:
        assert 'var/cache/salt' not in item

def test_can_find_uniquely_hubblestack_module(module_dirs):
    found = False
    for path in module_dirs:
        if os.path.isfile( os.path.join(path, 'pulsar.py') ):
            found = True
            break
    assert found

# XXX: we'll want to remove this test when we stop looking for installed saltstack
def test_can_find_uniquely_saltstack_module(module_dirs):
    found = False
    for path in module_dirs:
        if os.path.isfile( os.path.join(path, 'saltutil.py') ):
            found = True
            break
    assert found

# XXX: this should get removed for the same reason as above
def test_can_load_salt_and_hubblestack_mods(hubblestack_loaders):
    pass
    #assert 'pulsar.process' in __mods__
    #assert 'cp.cache_file' in __mods__
