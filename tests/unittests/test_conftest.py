# coding: utf-8

import os

def test_unders(HSL):
    __opts__, __mods__, __grains__, __utils__ = HSL
    assert __grains__['id'] == 'test-minion'

    config = __opts__['conf_file']
    assert config and os.path.isfile(config)

    file_roots = __opts__.get('file_roots', {})
    fr_base = file_roots.get('base')
    assert file_roots and fr_base

    def find_file(x):
        for path in fr_base:
            filepath = os.path.join(path, x)
            if os.path.isfile(filepath) or os.path.isdir(filepath):
                return filepath

    for i in ('top.nebula', 'hubblestack_nebula_v2', 'hubblestack_nebula_v2/hubblestack_nebula_queries.yaml'):
        assert find_file(i) == 'tests/unittests/resources/' + i

    mdirs = __opts__.get('modules_dirs')
    assert 'test.ping' in __mods__
    assert 'hstatus.msg_counts' in __mods__
