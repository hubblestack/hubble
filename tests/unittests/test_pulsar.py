import sys, os
myPath = os.path.abspath(os.getcwd())
sys.path.insert(0, myPath)
import pytest
import hubblestack.extmods.modules.pulsar
import collections
from salt.exceptions import CommandExecutionError

class TestPulsar():

    def test_virtual(self):
        var = hubblestack.extmods.modules.pulsar.__virtual__()
        assert var == True

    def test_enqueue(self):
        hubblestack.extmods.modules.pulsar.__context__ = {}
        var = hubblestack.extmods.modules.pulsar._enqueue
        assert var != 0

    def test_get_notifier(self):
        hubblestack.extmods.modules.pulsar.__context__ = {}
        var = hubblestack.extmods.modules.pulsar._get_notifier
        assert var != 0

    def test_dict_update_for_merge_dict(self):
        dest = {'key1' : 'val1'}
        upd = {'key_2' : 'val_2'}
        test_dict = {'key1' : 'val1', 'key_2' : 'val_2'}
        var = hubblestack.extmods.modules.pulsar._dict_update(dest, upd, recursive_update=True, merge_lists=False)
        assert var == test_dict

    def test_dict_update_for_classic_dictUpdate(self):
        dest = {'key1' : 'val1'}
        upd = {'key_2' : 'val_2'}
        test_dict = {'key1' : 'val1', 'key_2' : 'val_2'}
        var = hubblestack.extmods.modules.pulsar._dict_update(dest, upd, recursive_update=False, merge_lists=False)
        assert var == test_dict

    def test_dict_update_for_dest_TypeError(self):
        dest = 'TestValue1'
        upd = {'key_1' : 'val_1', 'key_2' : 'val_2'}
        try:
            var = hubblestack.extmods.modules.pulsar._dict_update(dest, upd, recursive_update=True, merge_lists=False)
        except TypeError:
            pass

    def test_dict_update_for_upd_TypeError(self):
        dest = {'key_1' : 'val_1', 'key_2' : 'val_2'}
        upd = 'TestValue2'
        try:
            var = hubblestack.extmods.modules.pulsar._dict_update(dest, upd, recursive_update=True, merge_lists=False)
        except TypeError:
            pass

    def test_dict_update_recurssive(self):
        ret = {}
        dest = {'data':
                        {'blacklist': {'talk1': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}},
                         'whitelist': {'ssh_ignore_rhosts': {'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}}}
        upd = {'data':
                        {'blacklist': {'talk2': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}}}}
        data_list = [dest, upd]
        for data in data_list:
            val = hubblestack.extmods.modules.pulsar._dict_update(dest, data, recursive_update=True, merge_lists=True)
        assert (len(val['data']['blacklist'])) == 2

    def test_process(self):
        configfile='tests/unittests/resources/hubblestack_pulsar_config.yaml'
        verbose = False
        def config_get(value, default):
            return default
        __salt__ = {}
        __salt__['config.get'] = config_get
        hubblestack.extmods.modules.pulsar.__salt__ = __salt__
        hubblestack.extmods.modules.pulsar.__opts__ = {}
        var = hubblestack.extmods.modules.pulsar.process(configfile,verbose)
        hubblestack.extmods.modules.pulsar.__salt__ = {}
        assert len(var) == 0
        assert isinstance(var, list)

    def test_top_result_for_list(self):
        topfile = 'tests/unittests/resources/top.pulsar'
        def cp_cache_file(value):
            return 'tests/unittests/resources/top.pulsar'
        def match_compound(value):
            return value
        __salt__ = {}
        __salt__['cp.cache_file'] = cp_cache_file
        __salt__['match.compound'] = match_compound
        hubblestack.extmods.modules.pulsar.__salt__ = __salt__
        get_top_data_config = hubblestack.extmods.modules.pulsar.get_top_data(topfile)
        configs = ['salt://hubblestack_pulsar/' + config.replace('.', '/') + '.yaml'
                   for config in get_top_data_config]
        assert configs[0] == 'salt://hubblestack_pulsar/hubblestack_pulsar_config.yaml'

    def test_get_top_data(self):
        topfile = 'tests/unittests/resources/top.pulsar'
        def cp_cache_file(topfile):
            return topfile
        def match_compound(value):
            return value
        __salt__ = {}
        __salt__['cp.cache_file'] = cp_cache_file
        __salt__['match.compound'] = match_compound
        hubblestack.extmods.modules.pulsar.__salt__ = __salt__
        result = hubblestack.extmods.modules.pulsar.get_top_data(topfile)
        hubblestack.extmods.modules.pulsar.__salt__ = {}
        assert isinstance(result, list)
        assert result[0] == 'hubblestack_pulsar_config'

    def test_get_top_data_for_CommandExecutionError(self):
        topfile = '/testfile'
        def cp_cache_file(topfile):
            return '/testfile'
        def match_compound(value):
            return value
        __salt__ = {}
        __salt__['cp.cache_file'] = cp_cache_file
        __salt__['match.compound'] = match_compound
        hubblestack.extmods.modules.pulsar.__salt__ = __salt__
        try:
            result = hubblestack.extmods.modules.pulsar.get_top_data(topfile)
            hubblestack.extmods.modules.pulsar.__salt__ = {}
        except CommandExecutionError:
            pass

