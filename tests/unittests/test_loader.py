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

def test_can_find_uniquely_hubblestack_module(module_dirs):
    """ test to make sure we can find specifically hubblestack modules in at
        least one of the module_dirs()
    """
    found = False
    for path in module_dirs:
        if os.path.isfile( os.path.join(path, 'pulsar.py') ):
            found = True
            break
    assert found

# XXX: we'll want to remove this test when we stop looking for installed saltstack
def test_can_find_uniquely_saltstack_module(module_dirs):
    """ check to make sure that we can still find salt modules somewhere in module_dirs()
        ... although we'll want to remove this test eventually, around about
        the time we remove the ability to load saltstack modules from salt
        installs.
    """
    found = False
    for path in module_dirs:
        if os.path.isfile( os.path.join(path, 'saltutil.py') ):
            found = True
            break
    assert found

# XXX: this should get removed for the same reason as above
# Interestingly, the 2020 pip resolver is also an issue here... salt 2009.2.3
# requires tornado < 5.0; but something else requires tornado latest (6.0.4ish)
# and this causes the below test to fail. It's really not worth fixing this
# close to the full saltless merge, so we'll just skip this for now. It still
# works if the tornado package is young enough.
@pytest.importorskip('tornado.stack_context')
def test_can_load_salt_and_hubblestack_mods(__mods__):
    assert 'pulsar.process' in __mods__
    import salt.modules.saltutil as smsu
    assert hasattr(smsu, 'sync_all')
    assert 'saltutil.sync_all' in __mods__
