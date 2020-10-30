#!/usr/bin/env python
# coding: utf-8

import os
import pytest

import hubblestack.loader as L
import hubblestack.daemon as D

@pytest.fixture(scope='module')
def module_dirs(config_file):
    D.load_config(args=['-c', config_file])
    md = L._module_dirs(D.__opts__, 'modules', 'module')
    return md

def test_module_dirs(module_dirs):
    """ interrogate module_dirs() to make sure none of its entries contain any
        paths that might result in us accidentally loading salt modules from
        some unreleated salt installation
    """
    for item in module_dirs:
        assert 'var/cache/salt' not in item

def test_can_find_hubblestack_module_file(module_dirs):
    """ test to make sure we can find specifically hubblestack modules in at
        least one of the module_dirs()
    """
    found = False
    for path in module_dirs:
        if os.path.isfile( os.path.join(path, 'pulsar.py') ):
            found = True
            break
    assert found

def test_can_find_hubblestack_module(__mods__):
    assert 'pulsar.canary' in __mods__
