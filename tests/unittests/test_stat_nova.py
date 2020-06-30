import os
import hubblestack.files.hubblestack_nova.stat_nova


class TestStatNova():

    def test_virtual(self):
        expected_val = True
        val = hubblestack.files.hubblestack_nova.stat_nova.__virtual__()
        assert expected_val == val

    def test_merge_yaml(self):
        ret = {}
        data = {
            'stat': {'passwd_owner_group': {
                'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0',
                'data': {'Ubuntu-16.04': [{'/etc/passwd': {'gid': 0,
                                                           'tag': 'CIS-12.4',
                                                           'group': 'root',
                                                           'uid': 0,
                                                           'user': 'root'}}]},
                'description': 'Verify User/Group Ownership on /etc/passwd'}}}
        profile = 'ubuntu-1604-level-1-scored-v1-0-0'
        val = hubblestack.files.hubblestack_nova.stat_nova._merge_yaml(ret, data, profile)
        assert val['stat'] == [{'passwd_owner_group': {
            'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0',
            'data': {'Ubuntu-16.04': [{'/etc/passwd': {'group': 'root',
                                                       'gid': 0,
                                                       'tag': 'CIS-12.4',
                                                       'uid': 0,
                                                       'user': 'root'}}]},
            'description': 'Verify User/Group Ownership on /etc/passwd'}}]

    def test_merge_yaml_recurssive(self):
        ret = {}
        profile = 'ubuntu-1604-level-1-scored-v1-0-0'
        data1 = {'stat': {'passwd_owner_group1': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0',
                                                  'data': {'Ubuntu-16.04': [{'/etc/passwd': {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]},
                                                  'description': 'Verify User/Group Ownership on /etc/passwd'}}}

        data2 = {'stat': {'passwd_owner_group2': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0',
                                                  'data': {'Ubuntu-16.04': [{'/etc/passwd': {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]},
                                                  'description': 'Verify User/Group Ownership on /etc/passwd'}}}
        data_list = [data1, data2]
        for data in data_list:
            val = hubblestack.files.hubblestack_nova.stat_nova._merge_yaml(ret, data, profile)
        assert (len(val['stat'])) == 2

    def test_get_tags(self):
        data = {'stat': [{'passwd_owner_group': {'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0',
                                                 'data': {'Ubuntu-16.04': [{'/etc/passwd': {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]},
                                                 'description': 'Verify User/Group Ownership on /etc/passwd'}}]}
        hubblestack.files.hubblestack_nova.stat_nova.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        ret = hubblestack.files.hubblestack_nova.stat_nova._get_tags(data)
        assert ret['CIS-12.4'] == [{'nova_profile': 'ubuntu-1604-level-1-scored-v1-0-0',
                                    'tag': 'CIS-12.4', 'group': 'root', 'name': '/etc/passwd', 'uid': 0, 'gid': 0,
                                    'description': 'Verify User/Group Ownership on /etc/passwd', 'module': 'stat', 'user': 'root'}]

    def test_get_tags_for_empty_data(self):
        data = {'stat': []}
        hubblestack.files.hubblestack_nova.stat_nova.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        ret = hubblestack.files.hubblestack_nova.stat_nova._get_tags(data)
        assert ret == {}

    def test_audit_for_success(self):
        val = {}
        data_list = [('ubuntu-1604-level-1-scored-v1-0-0', {'stat':
                                                            {'passwd_owner_group': {'data': {'Ubuntu-16.04': [{'/etc/passwd': {'gid': 0, 'tag': 'CIS-12.4', 'group': 'root', 'uid': 0, 'user': 'root'}}]},
                                                                                    'description': 'Verify User/Group Ownership on /etc/passwd'}}})]
        __tags__ = 'CIS-12.4'
        __salt__ = {}

        def file_stats(name):
            return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/issue', 'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322, 'ctime': 1491870657.914388}
        __salt__['file.stats'] = file_stats
        hubblestack.files.hubblestack_nova.stat_nova.__salt__ = __salt__
        hubblestack.files.hubblestack_nova.stat_nova.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        val = hubblestack.files.hubblestack_nova.stat_nova.audit(data_list, __tags__, [], debug=False)
        assert len(val['Success']) != 0

    def test_audit_for_incorrect_input(self):
        val = {}
        data_list = []
        __tags__ = ''
        __salt__ = {}
        expected_val = {'Failure': [], 'Controlled': [], 'Success': []}

        def file_stats(name):
            return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/issue', 'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322, 'ctime': 1491870657.914388}
        __salt__['file.stats'] = file_stats
        hubblestack.files.hubblestack_nova.stat_nova.__salt__ = __salt__
        hubblestack.files.hubblestack_nova.stat_nova.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        val = hubblestack.files.hubblestack_nova.stat_nova.audit(data_list, __tags__, [], debug=False)
        assert val == expected_val

    def test_audit_for_value_error(self):
        val = {}
        data_list = 'wrong_test_data'
        __tags__ = 'CIS-12.4'
        __salt__ = {}

        def file_stats(name):
            return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/issue', 'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322, 'ctime': 1491870657.914388}
        __salt__['file.stats'] = file_stats
        hubblestack.files.hubblestack_nova.stat_nova.__salt__ = __salt__
        hubblestack.files.hubblestack_nova.stat_nova.__grains__ = {'osfinger': 'Ubuntu-16.04'}
        try:
            val = hubblestack.files.hubblestack_nova.stat_nova.audit(data_list, __tags__, [], debug=False)
        except ValueError:
            pass

    def test_check_mode_1(self):
        test_data_max_permission = '644'
        test_data_given_permission = '644'
        test_data_allow_more_strict = True
        expected_val = True
        result = hubblestack.files.hubblestack_nova.stat_nova._check_mode(test_data_max_permission, test_data_given_permission, test_data_allow_more_strict)
        assert expected_val == result

    def test_check_mode_2(self):
        test_data_max_permission = '644'
        test_data_given_permission = '644'
        test_data_allow_more_strict = False
        expected_val = True
        result = hubblestack.files.hubblestack_nova.stat_nova._check_mode(test_data_max_permission, test_data_given_permission, test_data_allow_more_strict)
        assert expected_val == result

    def test_check_mode_3(self):
        test_data_max_permission = '644'
        test_data_given_permission = '600'
        test_data_allow_more_strict = True
        expected_val = True
        result = hubblestack.files.hubblestack_nova.stat_nova._check_mode(test_data_max_permission, test_data_given_permission, test_data_allow_more_strict)
        assert expected_val == result

    def test_check_mode_4(self):
        test_data_max_permission = '644'
        test_data_given_permission = '600'
        test_data_allow_more_strict = False
        expected_val = False
        result = hubblestack.files.hubblestack_nova.stat_nova._check_mode(test_data_max_permission, test_data_given_permission, test_data_allow_more_strict)
        assert expected_val == result

    def test_check_mode_5(self):
        test_data_max_permission = '644'
        test_data_given_permission = '655'
        test_data_allow_more_strict = True
        expected_val = False
        result = hubblestack.files.hubblestack_nova.stat_nova._check_mode(test_data_max_permission, test_data_given_permission, test_data_allow_more_strict)
        assert expected_val == result
