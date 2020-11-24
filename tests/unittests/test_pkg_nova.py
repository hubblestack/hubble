import os
import hubblestack.files.hubblestack_nova.pkg


class TestPkg():

    def test_virtual(self):
        expected_val = True
        val = hubblestack.files.hubblestack_nova.pkg.__virtual__()
        assert expected_val == val

    def test_merge_yaml(self):
        ret = {'pkg': {}}
        data = {'pkg':
                {'blacklist': {'talk': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}},
                 'whitelist': {'ssh_ignore_rhosts': {'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}}}
        profile = 'ubuntu-1604-level-1-scored-v1-0-0'
        val = hubblestack.files.hubblestack_nova.pkg._merge_yaml(ret, data, profile)
        assert val['pkg'] == {'blacklist': [{'talk': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}}],
                              'whitelist': [{'ssh_ignore_rhosts': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}]}

    def test_merge_yaml_recurssive(self):
        ret = {}
        profile = 'ubuntu-1604-level-1-scored-v1-0-0'
        data1 = {'pkg':
                 {'blacklist': {'talk1': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}},
                  'whitelist': {'ssh_ignore_rhosts': {'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}}}
        data2 = {'pkg':
                 {'blacklist': {'talk2': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}}}}
        data_list = [data1, data2]
        for data in data_list:
            val = hubblestack.files.hubblestack_nova.pkg._merge_yaml(ret, data, profile)
        assert (len(val['pkg']['blacklist'])) == 2

    def test_audit_for_success(self):
        val = {}
        data_list = [('ubuntu-1604-level-1-scored-v1-0-0',
                     {'pkg':
                      {'blacklist': {'prelink': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'prelink': 'CIS-4.4'}]}, 'description': 'Disable Prelink'}, 'nis': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'nis': 'CIS-5.1.1'}]}, 'description': 'Ensure NIS is not installed'}},
                       'whitelist': {'ntp': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'ntp': 'CIS-6.5'}]}, 'description': 'Configure Network Time Protocol (NTP)'}, 'rsyslog': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'rsyslog': 'CIS-8.2.1'}]}, 'description': 'Install the rsyslog package'}}}})]
        __tags__ = 'CIS-6.5'
        hubblestack.files.hubblestack_nova.pkg.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        __salt__ = {}

        def pkg_version(name):
            return name
        __salt__['pkg.version'] = pkg_version
        hubblestack.files.hubblestack_nova.pkg.__salt__ = __salt__
        val = hubblestack.files.hubblestack_nova.pkg.audit(data_list, __tags__, [], debug=False)
        assert len(val['Success']) != 0
        assert len(val['Failure']) == 0

    def test_audit_for_incorrect_input(self):
        val = {}
        data_list = []
        __tags__ = 'wrong_test_data'
        hubblestack.files.hubblestack_nova.pkg.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        __salt__ = {}
        expected_val = {'Failure': [], 'Controlled': [], 'Success': []}

        def pkg_version(name):
            return name
        __salt__['pkg.version'] = pkg_version
        hubblestack.files.hubblestack_nova.pkg.__salt__ = __salt__
        val = hubblestack.files.hubblestack_nova.pkg.audit(data_list, __tags__, [], debug=False)
        assert val == expected_val

    def test_audit_for_value_error(self):
        val = {}
        data_list = 'wrong_test_data'
        __tags__ = 'CIS-6.5'
        hubblestack.files.hubblestack_nova.pkg.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        __salt__ = {}

        def pkg_version(name):
            return name
        __salt__['pkg.version'] = pkg_version
        hubblestack.files.hubblestack_nova.pkg.__salt__ = __salt__
        try:
            val = hubblestack.files.hubblestack_nova.pkg.audit(data_list, __tags__, [], debug=False)
        except ValueError:
            pass

    def test_get_tags(self):
        hubblestack.files.hubblestack_nova.pkg.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        data = {'pkg':
                {'blacklist': [{'talk1': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}},
                               {'talk2': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}}],
                 'whitelist': [{'ssh_ignore_rhosts': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}]}}
        val = hubblestack.files.hubblestack_nova.pkg._get_tags(data)
        assert val['CIS-5.1.4'] != 0
        assert val['CIS-9.3.6'] != 0

    def test_get_tags_for_empty_data(self):
        data = {'pkg': {}}
        hubblestack.files.hubblestack_nova.pkg.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        ret = hubblestack.files.hubblestack_nova.pkg._get_tags(data)
        assert ret == {}
