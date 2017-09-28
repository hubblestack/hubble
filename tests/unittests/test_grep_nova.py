import hubblestack.files.hubblestack_nova.grep
import yaml
import pytest
import sys, os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../')

class TestGrep():

    def test_virtual(self):
        expected_val = True
        val = hubblestack.files.hubblestack_nova.grep.__virtual__()
        assert expected_val == val

    def test_merge_yaml(self):
        ret = {'test1':'val1'}
        data = {'test1':'val1'}
        profile = None
        val = hubblestack.files.hubblestack_nova.grep._merge_yaml(ret, data, profile)
        assert val['test1'] == 'val1'

    def test_merge_yaml_different_val(self):
        ret = {'test1':'val1'}
        data = {'test2':'val2'}
        profile = None
        val = hubblestack.files.hubblestack_nova.grep._merge_yaml(ret, data, profile)
        assert val['test1'] == 'val1'

    def test_merge_yaml_different_val_for_data(self):
        ret = {}
        data = {'test2':'val2'}
        profile = None
        val = hubblestack.files.hubblestack_nova.grep._merge_yaml(ret, data, profile)
        assert val['grep'] != 0

    def test_merge_yaml_for_pkg(self):
        ret = {}
        data = {}
        profile = None
        val = hubblestack.files.hubblestack_nova.grep._merge_yaml(ret, data, profile)
        assert val['grep'] != 0

    def test_audit_for_Success(self):
        val = {}
        data_list = [('ubuntu-1604-level-1-scored-v1-0-0', \
                     {'stat': {'passwd_owner_group': {'data': {'Ubuntu-16.04': [{'/etc/passwd': \
                    {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]}, \
                    'description': 'Verify User/Group Ownership on /etc/passwd'}}})]
        __tags__ = '*'
        hubblestack.files.hubblestack_nova.grep.__grains__ = {'osfinger' : 'Ubuntu-16.04'}
        val = hubblestack.files.hubblestack_nova.grep.audit(data_list, __tags__, debug=False)
        assert val['Success'] != 0


    def test_audit_for_Failure(self):
        val = {}
        data_list = [('ubuntu-1604-level-1-scored-v1-0-0', \
                     {'stat': {'passwd_owner_group': {'data': {'Ubuntu-16.04': [{'/etc/passwd': \
                    {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]}, \
                    'description': 'Verify User/Group Ownership on /etc/passwd'}}})]
        __tags__ = '*'
        hubblestack.files.hubblestack_nova.grep.__grains__ = {'osfinger' : 'Ubuntu-16.04'}
        val = hubblestack.files.hubblestack_nova.grep.audit(data_list, __tags__, debug=False)
        assert val['Failure'] != 0

    def test_audit_for_Controlled(self):
        val = {}
        data_list = [('ubuntu-1604-level-1-scored-v1-0-0', \
                     {'stat': {'passwd_owner_group': {'data': {'Ubuntu-16.04': [{'/etc/passwd': \
                    {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]}, \
                    'description': 'Verify User/Group Ownership on /etc/passwd'}}})]
        __tags__ = '*'
        hubblestack.files.hubblestack_nova.grep.__grains__ = {'osfinger' : 'Ubuntu-16.04'}
        val = hubblestack.files.hubblestack_nova.grep.audit(data_list, __tags__, debug=False)
        assert val['Controlled'] != 0

