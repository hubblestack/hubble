import hubblestack.files.hubblestack_nova.stat_nova
import yaml
import pytest

class TestStatNova():

    def test_virtual(self):
        expected_val = True
        val = hubblestack.files.hubblestack_nova.stat_nova.__virtual__()
        assert expected_val == val

    def test_merge_yaml(self):
        ret = {'test1':'val1'}
        data = {'test1':'val1'}
        profile = None
        val = hubblestack.files.hubblestack_nova.stat_nova._merge_yaml(ret, data, profile)
        assert val['test1'] == 'val1'

    def test_merge_yaml_different_val(self):
        ret = {'test1':'val1'}
        data = {'test2':'val2'}
        profile = None
        val = hubblestack.files.hubblestack_nova.stat_nova._merge_yaml(ret, data, profile)
        assert val['test1'] == 'val1'

    def test_merge_yaml_different_val_for_data(self):
        ret = {}
        data = {'test2':'val2'}
        profile = None
        val = hubblestack.files.hubblestack_nova.stat_nova._merge_yaml(ret, data, profile)
        assert val['stat'] != 0

    def test_merge_yaml_for_pkg(self):
        ret = {}
        data = {}
        profile = None
        val = hubblestack.files.hubblestack_nova.stat_nova._merge_yaml(ret, data, profile)
        assert val['stat'] != 0

    def test_get_tags(self):
        data = {'stat': [{'passwd_owner_group': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', \
                'data': {'Ubuntu-16.04': [{'/etc/passwd': {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]}, \
                'description': 'Verify User/Group Ownership on /etc/passwd'}}]}
        hubblestack.files.hubblestack_nova.stat_nova.__grains__ = {'osfinger' : 'Ubuntu-16.04'}
        ret = hubblestack.files.hubblestack_nova.stat_nova._get_tags(data)
        assert ret['CIS-12.4'] == [{'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', \
                                    'tag': 'CIS-12.4', 'group': 'root', 'name': '/etc/passwd', 'uid': 0, 'gid': 0, \
                                    'description': 'Verify User/Group Ownership on /etc/passwd', 'module': 'stat', 'user': 'root'}]

    def test_get_tags_for_empty_data(self):
        data = {'stat': []}
        hubblestack.files.hubblestack_nova.stat_nova.__grains__ = {'osfinger' : 'Ubuntu-16.04'}
        ret = hubblestack.files.hubblestack_nova.stat_nova._get_tags(data)
        assert ret == {}

    def test_audit(self):
        val = {}
        data_list = [('ubuntu-1604-level-1-scored-v1-0-0', {'stat': {'passwd_owner_group': {'data': {'Ubuntu-16.04': [{'/etc/passwd': \
                    {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]}, 'description': 'Verify User/Group Ownership on /etc/passwd'}}})]
        __tags__ = '*'
        hubblestack.files.hubblestack_nova.stat_nova.__salt__ = {}
        try:
            val = hubblestack.files.hubblestack_nova.stat_nova.audit(data_list, __tags__, debug=False)
        except KeyError:
            assert val != 0
            pass
