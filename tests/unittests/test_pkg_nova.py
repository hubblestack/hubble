import hubblestack.files.hubblestack_nova.pkg
import yaml
import pytest

class TestPkg():

    def test_virtual(self):
        expected_val = True
        val = hubblestack.files.hubblestack_nova.pkg.__virtual__()
        assert expected_val == val

    def test_merge_yaml(self):
        ret = {'test1':'val1'}
        data = {'test1':'val1'}
        profile = None
        val = hubblestack.files.hubblestack_nova.pkg._merge_yaml(ret, data, profile)
        assert val['test1'] == 'val1'

    def test_merge_yaml_different_val(self):
        ret = {'test1':'val1'}
        data = {'test2':'val2'}
        profile = None
        val = hubblestack.files.hubblestack_nova.pkg._merge_yaml(ret, data, profile)
        assert val['test1'] == 'val1'

    def test_merge_yaml_different_val_for_data(self):
        ret = {}
        data = {'test2':'val2'}
        profile = None
        val = hubblestack.files.hubblestack_nova.pkg._merge_yaml(ret, data, profile)
        assert val['pkg'] != 0

    def test_merge_yaml_for_pkg(self):
        ret = {}
        data = {}
        profile = None
        val = hubblestack.files.hubblestack_nova.pkg._merge_yaml(ret, data, profile)
        assert val['pkg'] != 0

    def test_get_tags(self):
        data = {'pkg': {'blacklist': [{'prelink': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', \
                'data': {'Ubuntu-16.04': [{'prelink': 'CIS-4.4'}]}, 'description': 'Disable Prelink'}}, \
               {'nis': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': \
               [{'nis': 'CIS-5.1.1'}]}, 'description': 'Ensure NIS is not installed'}}, {'biosdevname': \
               {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'biosdevname': 'CIS-6.17'}]}, \
                'description': 'Ensure biosdevname is not enabled'}}, {'talk': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', \
                'data': {'Ubuntu-16.04': [{'talk': 'CIS-5.1.5'}]}, 'description': 'Ensure Talk Client is not installed'}}, \
               {'xserver': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'xserver-xorg-core\\*': 'CIS-6.1'}]}, \
               'description': 'Ensure the X Window system is not installed'}}], 'whitelist': [{'ntp': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', \
               'data': {'Ubuntu-16.04': [{'ntp': 'CIS-6.5'}]}, 'description': 'Configure Network Time Protocol (NTP)'}}, {'rsyslog': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', \
               'data': {'Ubuntu-16.04': [{'rsyslog': 'CIS-8.2.1'}]}, 'description': 'Install the rsyslog package'}}, {'tcpd': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', \
               'data': {'Ubuntu-16.04': [{'tcpd': 'CIS-7.4.1'}]}, 'description': 'Install TCP Wrappers'}}]}}
        hubblestack.files.hubblestack_nova.pkg.__grains__ = {'osfinger' : 'Ubuntu-16.04'}
        ret = hubblestack.files.hubblestack_nova.pkg._get_tags(data)
        assert ret['CIS-6.5'] == [{'tag': 'CIS-6.5', 'name': 'ntp', 'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'type': 'whitelist', \
                                   'module': 'pkg', 'description': 'Configure Network Time Protocol (NTP)'}]

    def test_get_tags_for_empty_data(self):
        data = {'pkg': {}}
        hubblestack.files.hubblestack_nova.pkg.__grains__ = {'osfinger' : 'Ubuntu-16.04'}
        ret = hubblestack.files.hubblestack_nova.pkg._get_tags(data)
        assert ret == {}

    def test_audit_for_Success(self):
       val = {}
       data_list = [('ubuntu-1604-level-1-scored-v1-0-0', {'stat': {'passwd_owner_group': {'data': {'Ubuntu-16.04': \
                   [{'/etc/passwd': {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]}, \
                     'description': 'Verify User/Group Ownership on /etc/passwd'}}})]
       __tags__ = {'CIS-6.5': [{'tag': 'CIS-6.5', 'name': 'ntp', 'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'type': 'whitelist', \
                   'module': 'pkg', 'description': 'Configure Network Time Protocol (NTP)'}]}
       val = hubblestack.files.hubblestack_nova.pkg.audit(data_list, __tags__, debug=False)
       assert val['Success'] != 0

    def test_audit_for_Failure(self):
        val = {}
        data_list = [('ubuntu-1604-level-1-scored-v1-0-0', {'stat': {'passwd_owner_group': {'data': {'Ubuntu-16.04': \
                    [{'/etc/passwd': {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]}, \
                      'description': 'Verify User/Group Ownership on /etc/passwd'}}})]
        __tags__ = {'CIS-6.5': [{'tag': 'CIS-6.5', 'name': 'ntp', 'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'type': 'whitelist', \
                   'module': 'pkg', 'description': 'Configure Network Time Protocol (NTP)'}]}
        val = hubblestack.files.hubblestack_nova.pkg.audit(data_list, __tags__, debug=False)
        assert val['Failure'] != 0

    def test_audit_for_Controlled(self):
        val = {}
        data_list = [('ubuntu-1604-level-1-scored-v1-0-0', {'stat': {'passwd_owner_group': {'data': {'Ubuntu-16.04': \
                    [{'/etc/passwd': {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]}, \
                      'description': 'Verify User/Group Ownership on /etc/passwd'}}})]
        __tags__ = {'CIS-6.5': [{'tag': 'CIS-6.5', 'name': 'ntp', 'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'type': 'whitelist', \
                   'module': 'pkg', 'description': 'Configure Network Time Protocol (NTP)'}]}
        val = hubblestack.files.hubblestack_nova.pkg.audit(data_list, __tags__, debug=False)
        assert val['Controlled'] != 0


