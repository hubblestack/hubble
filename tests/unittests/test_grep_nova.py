import os
import hubblestack.files.hubblestack_nova.grep


class TestGrep():

    def test_virtual(self):
        expected_val = True
        val = hubblestack.files.hubblestack_nova.grep.__virtual__()
        assert expected_val == val

    def test_merge_yaml(self):
        ret = {'grep': {}}
        data = {'grep':
                {'blacklist': {'talk': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}},
                 'whitelist': {'ssh_ignore_rhosts': {'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}}}
        profile = 'ubuntu-1604-level-1-scored-v1-0-0'
        val = hubblestack.files.hubblestack_nova.grep._merge_yaml(ret, data, profile)
        assert val['grep'] == {'blacklist': [{'talk': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}}],
                               'whitelist': [{'ssh_ignore_rhosts': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}]}

    def test_merge_yaml_recurssive(self):
        ret = {}
        profile = 'ubuntu-1604-level-1-scored-v1-0-0'
        data1 = {'grep':
                 {'blacklist': {'talk1': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}},
                  'whitelist': {'ssh_ignore_rhosts': {'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}}}
        data2 = {'grep':
                 {'blacklist': {'talk2': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}}}}
        data_list = [data1, data2]
        for data in data_list:
            val = hubblestack.files.hubblestack_nova.grep._merge_yaml(ret, data, profile)
        assert (len(val['grep']['blacklist'])) == 2

    def test_audit_for_success(self):
        val = {}
        data_list = [('ubuntu-1604-level-1-scored-v1-0-0',
                     {'grep':
                      {'blacklist': {'talk': {'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}},
                       'whitelist': {'ssh_permit_user_env': {'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'PermitUserEnvironment', 'tag': 'CIS-9.3.10', 'match_output': 'no'}}]}, 'description': 'Do Not Allow Users to Set Environment Options'},
                                     'ssh_ignore_rhosts': {'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}}})]
        __tags__ = 'CIS-9.3.10'
        __salt__ = {}

        def cmd_run_all(cmd, python_shell=False, ignore_retcode=False):
            test_val = {'pid': 28191, 'retcode': 0, 'stderr': '', 'stdout': 'tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0'}
            return test_val
        __salt__['cmd.run_all'] = cmd_run_all
        hubblestack.files.hubblestack_nova.grep.__salt__ = __salt__
        hubblestack.files.hubblestack_nova.grep.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        val = hubblestack.files.hubblestack_nova.grep.audit(data_list, __tags__, [], debug=False)
        assert len(val['Success']) != 0
        assert len(val['Failure']) == 0

    def test_audit_for_value_error(self):
        val = {}
        data_list = 'wrong_test_data'
        __tags__ = 'CIS-9.3.10'
        __salt__ = {}

        def cmd_run_all(cmd, python_shell=False, ignore_retcode=False):
            test_val = {'pid': 28191, 'retcode': 0, 'stderr': '', 'stdout': 'tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0'}
            return test_val
        __salt__['cmd.run_all'] = cmd_run_all
        hubblestack.files.hubblestack_nova.grep.__salt__ = __salt__
        hubblestack.files.hubblestack_nova.grep.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        try:
            val = hubblestack.files.hubblestack_nova.grep.audit(data_list, __tags__, [], debug=False)
        except ValueError:
            pass
        hubblestack.files.hubblestack_nova.grep.__salt__ = {}

    def test_audit_for_incorrect_input(self):
        val = {}
        data_list = []
        __tags__ = 'wrong_test_data'
        __salt__ = {}
        expected_val = {'Failure': [], 'Controlled': [], 'Success': []}

        def cmd_run_all(cmd, python_shell=False, ignore_retcode=False):
            test_val = {'pid': 28191, 'retcode': 0, 'stderr': '', 'stdout': 'tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0'}
            return test_val
        __salt__['cmd.run_all'] = cmd_run_all
        hubblestack.files.hubblestack_nova.grep.__salt__ = __salt__
        hubblestack.files.hubblestack_nova.grep.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        val = hubblestack.files.hubblestack_nova.grep.audit(data_list, __tags__, [], debug=False)
        assert val == expected_val
        hubblestack.files.hubblestack_nova.grep.__salt__ = {}

    def test_get_tags(self):
        hubblestack.files.hubblestack_nova.grep.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        data = {'grep':
                {'blacklist': [{'talk1': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}},
                               {'talk2': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'/etc/inetd.conf': {'pattern': '^talk', 'tag': 'CIS-5.1.4'}}, {'/etc/inetd.conf': {'pattern': '^ntalk', 'tag': 'CIS-5.1.4'}}]}, 'description': 'Ensure talk server is not enabled'}}],
                 'whitelist': [{'ssh_ignore_rhosts': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0', 'data': {'Ubuntu-16.04': [{'/etc/ssh/sshd_config': {'pattern': 'IgnoreRhosts', 'tag': 'CIS-9.3.6', 'match_output': 'yes'}}]}, 'description': 'Set SSH IgnoreRhosts to Yes'}}]}}
        val = hubblestack.files.hubblestack_nova.grep._get_tags(data)
        assert val['CIS-5.1.4'] != 0
        assert val['CIS-9.3.6'] != 0

    def test_get_tags_with_empty_list(self):
        hubblestack.files.hubblestack_nova.grep.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        data = {'grep':
                {'blacklist': [],
                 'whitelist': []}}
        val = hubblestack.files.hubblestack_nova.grep._get_tags(data)
        assert val == {}

    def test_grep(self):
        path = '/proc/mount/'
        pattern = '/dev/shm'
        arg = ''
        __salt__ = {}

        def cmd_run_all(cmd, python_shell=False, ignore_retcode=False):
            test_val = {'pid': 28191, 'retcode': 0, 'stderr': '', 'stdout': 'tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0'}
            return test_val
        __salt__['cmd.run_all'] = cmd_run_all
        hubblestack.files.hubblestack_nova.grep.__salt__ = __salt__
        val = hubblestack.files.hubblestack_nova.grep._grep(path, pattern, arg)
        hubblestack.files.hubblestack_nova.grep.__salt__ = {}
        assert val['stdout'] == 'tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0'
