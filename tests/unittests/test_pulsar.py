import pytest
import hubblestack.extmods.modules.pulsar
import collections

class TestPulsar():

    def test_virtual(self):
        var = hubblestack.extmods.modules.pulsar.__virtual__()
        assert var == True

    def test_get_mask(self):
        mask = 0
        testValue = hubblestack.extmods.modules.pulsar._get_mask(mask)
        assert self.mask_value() == testValue

    def mask_value(self):
        return 0

    def test_enqueue(self):
        var = hubblestack.extmods.modules.pulsar._enqueue
        assert var != 0

    def test_get_notofier(self):
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

    def test_dict_update_for_upd_TypeError(self):
        dest = {'key_1' : 'val_1', 'key_2' : 'val_2'}
        upd = 'TestValue2'
        try:
            var = hubblestack.extmods.modules.pulsar._dict_update(dest, upd, recursive_update=True, merge_lists=False)
        except TypeError:
            pass

    def test_dict_update_for_upd_AttributeError(self):
        dest = {'key_1' : 'val_1', 'key_2' : 'val_2'}
        upd = {}
        try:
            var = hubblestack.extmods.modules.pulsar._dict_update(dest, upd, recursive_update=False, merge_lists=False)
        except AttributeError:
            pass


    def test_process(self):
        configfile='resources/data.yaml'
        verbose = False
        def config_get(value, default):
            return default
        __salt__ = {}
        __salt__['config.get'] = config_get
        hubblestack.extmods.modules.pulsar.__salt__ = __salt__
        hubblestack.extmods.modules.pulsar.__opts__ = {}
        var = hubblestack.extmods.modules.pulsar.process(configfile,verbose)
        hubblestack.extmods.modules.pulsar.__salt__ = {}
        assert var != 0

    def test_process_for_regex_exclusion_list(self):
        configfile='resources/data.yaml'
        verbose = False
        def config_get(value, default):
            return default
        __salt__ = {}
        __salt__['config.get'] = config_get
        hubblestack.extmods.modules.pulsar.__salt__ = __salt__
        hubblestack.extmods.modules.pulsar.__opts__ = {}
        hubblestack.extmods.modules.pulsar.process(configfile,verbose)
        hubblestack.extmods.modules.pulsar.__salt__ = {}
        assert hubblestack.extmods.modules.pulsar.CONFIG != 0

    def test_top(self):
        topfile = 'resources/top.pulsar'
        def config_get(value, default):
            return default
        def cp_cache_file(topfile):
            return topfile
        def match_compound(value):
            return value
        __salt__ = {}
        __salt__['config.get'] = config_get
        __salt__['cp.cache_file'] = cp_cache_file
        __salt__['match.compound'] = match_compound
        hubblestack.extmods.modules.pulsar.__salt__ = __salt__
        result = hubblestack.extmods.modules.pulsar.top(topfile)
        hubblestack.extmods.modules.pulsar.__salt__ = {}
        assert result != 0

    def test_top_result_for_list(self):
        topfile = 'resources/top.pulsar'
        def config_get(value, default):
            return default
        def cp_cache_file(topfile):
            return topfile
        def match_compound(value):
            return value
        __salt__ = {}
        __salt__['config.get'] = config_get
        __salt__['cp.cache_file'] = cp_cache_file
        __salt__['match.compound'] = match_compound
        hubblestack.extmods.modules.pulsar.__salt__ = __salt__
        result = hubblestack.extmods.modules.pulsar.top(topfile)
        hubblestack.extmods.modules.pulsar.__salt__ = {}
        assert isinstance(result, list)

    def test_get_top_data(self):
        topfile = 'resources/top.pulsar'
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
        assert result != 0

    def test_get_top_data_for_NameError(self):
         topfile = '/testfile'
         def cp_cache_file(topfile):
             return topfile
         def match_compound(value):
             return value
         __salt__ = {}
         __salt__['cp.cache_file'] = cp_cache_file
         __salt__['match.compound'] = match_compound
         hubblestack.extmods.modules.pulsar.__salt__ = __salt__
         try:
             result = hubblestack.extmods.modules.pulsar.get_top_data(topfile)
             hubblestack.extmods.modules.pulsar.__salt__ = {}
         except NameError:
             pass


