import os
import json
import pytest

from tests.support.unit import TestCase, skipIf
import hubblestack.utils.platform

__mods__ = None

def dump_var_file(var, name='var', dumpster='tests/unittests/output'):
    if not os.path.isdir(dumpster):
        os.makedirs(dumpster)
    if not name.endswith('.json'):
        name += '.json'
    with open(os.path.join(dumpster,name), 'w') as fh:
        json.dump(var, fh)

@pytest.mark.usefixtures('osqueryd') # starts osqueryd in the background
class TestNebula():
    def test___virtual__(self):
        import hubblestack.modules.nebula_osquery
        var = hubblestack.modules.nebula_osquery.__virtual__()
        assert var == 'nebula'

    def test_loader(self, __mods__):
        assert 'nebula.queries' in __mods__

    def test_hubble_versions(self, __mods__):
        var = __mods__['nebula.hubble_versions']()
        assert ((var.get('hubble_versions')).get('result')) is True

    @skipIf(hubblestack.utils.platform.is_darwin(), "System is not MacOs")
    def test_queries(self, __mods__, __grains__):
        query_group = 'day'
        query_file = 'salt://hubblestack_nebula_v2/hubblestack_nebula_queries.yaml'
        var = __mods__['nebula.queries'](query_group, query_file,
            verbose=False, report_version_with_day=False)
        dump_var_file(var, 'queries')
        os_info = [ x for x in var if 'os_info' in x ]
        assert os_info
        assert 'os_info' in os_info[0]
        assert 'data' in os_info[0]['os_info']
        assert 'version' in os_info[0]['os_info']['data'][0]
        ## TODO: Fix this for MacOs
        assert __grains__['os'] in os_info[0]['os_info']['data'][0]['name']

    def test_queries_for_report_version_with_day(self, __mods__):
        query_group = 'day'
        query_file = 'salt://hubblestack_nebula_v2/hubblestack_nebula_queries.yaml'
        var = __mods__['nebula.queries'](query_group, query_file,
            verbose=False, report_version_with_day=True)
        dump_var_file(var, 'queries_for_report_version_with_day')
        hvnode = [ x for x in var if 'hubble_versions' in x ]
        assert len(hvnode) == 1
        assert 'hubble_versions' in hvnode[0]
        hubble_versions = hvnode[0]['hubble_versions']
        assert 'data' in hubble_versions
        assert len(hubble_versions['data']) == 1
        for m in 'pulsar nebula nova quasar'.split():
            assert m in hubble_versions['data'][0]

    @skipIf(hubblestack.utils.platform.is_darwin(), "System is not MacOs")
    def test_top(self, __mods__, __grains__):
        query_group = 'day'
        topfile = 'salt://top.nebula'
        verbose = False,
        report_version_with_day = True
        var = __mods__['nebula.top'](query_group, topfile, verbose,
            report_version_with_day)
        dump_var_file(var, 'top')
        os_info = [ x for x in var if 'os_info' in x ]
        assert os_info
        assert 'os_info' in os_info[0]
        assert 'data' in os_info[0]['os_info']
        assert 'version' in os_info[0]['os_info']['data'][0]
        ## TODO: Fix this for MacOs
        assert __grains__['os'] in os_info[0]['os_info']['data'][0]['name']
