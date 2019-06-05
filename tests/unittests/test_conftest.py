# coding: utf-8

import os

def test_unders(salt_loaders):
    __opts__, __salt__, __grains__, __utils__ = salt_loaders
    assert __grains__['id'] == 'test-minion'

    config = __opts__['conf_file']
    assert config and os.path.isfile(config)

    file_roots = __opts__.get('file_roots', {})
    fr_base = file_roots.get('base')
    assert file_roots and fr_base

    assert os.path.isfile(os.path.join(fr_base[0], 'top.nebula'))
    assert os.path.isdir(os.path.join(fr_base[0], 'hubblestack_nebula_v2'))
    assert os.path.isfile(os.path.join(fr_base[0],
        'hubblestack_nebula_v2', 'hubblestack_nebula_queries.yaml'))

    mdirs = __opts__.get('modules_dirs')
    assert 'test.ping' in __salt__
    assert 'hstatus.msg_counts' in __salt__
