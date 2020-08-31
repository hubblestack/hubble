# -*- coding: utf-8 -*-

# Import Python Libs
from __future__ import absolute_import, unicode_literals, print_function
import os

from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import TestCase, skipIf
from tests.support.mock import (
    Mock,
    MagicMock,
    patch,
    NO_MOCK,
    NO_MOCK_REASON
)

# Import Salt libs
from hubblestack.utils.exceptions import CommandExecutionError
import hubblestack.modules.rpm_lowpkg as rpm
import hubblestack.modules.yumpkg as yumpkg
import hubblestack.modules.pkg_resource as pkg_resource

try:
    import pytest
except ImportError:
    pytest = None

LIST_REPOS = {
    'base': {
        'file': '/etc/yum.repos.d/CentOS-Base.repo',
        'gpgcheck': '1',
        'gpgkey': 'file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7',
        'mirrorlist': 'http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=os&infra=$infra',
        'name': 'CentOS-$releasever - Base'
    },
    'base-source': {
        'baseurl': 'http://vault.centos.org/centos/$releasever/os/Source/',
        'enabled': '0',
        'file': '/etc/yum.repos.d/CentOS-Sources.repo',
        'gpgcheck': '1',
        'gpgkey': 'file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7',
        'name': 'CentOS-$releasever - Base Sources'
    },
    'updates': {
        'file': '/etc/yum.repos.d/CentOS-Base.repo',
        'gpgcheck': '1',
        'gpgkey': 'file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7',
        'mirrorlist': 'http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=updates&infra=$infra',
        'name': 'CentOS-$releasever - Updates'
    },
    'updates-source': {
        'baseurl': 'http://vault.centos.org/centos/$releasever/updates/Source/',
        'enabled': '0',
        'file': '/etc/yum.repos.d/CentOS-Sources.repo',
        'gpgcheck': '1',
        'gpgkey': 'file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7',
        'name': 'CentOS-$releasever - Updates Sources'
    }
}


@skipIf(NO_MOCK, NO_MOCK_REASON)
class YumTestCase(TestCase, LoaderModuleMockMixin):
    '''
    Test cases for hubblestack.modules.yumpkg
    '''
    def setup_loader_modules(self):
        return {
            yumpkg: {
                '__context__': {
                    'yum_bin': 'yum',
                },
                '__grains__': {
                    'osarch': 'x86_64',
                    'os_family': 'RedHat',
                    'osmajorrelease': 7,
                },
            }
        }

    def test_list_pkgs_with_attr(self):
        '''
        Test packages listing with the attr parameter

        :return:
        '''
        def _add_data(data, key, value):
            data.setdefault(key, []).append(value)

        rpm_out = [
            'python-urlgrabber_|-(none)_|-3.10_|-8.el7_|-noarch_|-(none)_|-1487838471',
            'alsa-lib_|-(none)_|-1.1.1_|-1.el7_|-x86_64_|-(none)_|-1487838475',
            'gnupg2_|-(none)_|-2.0.22_|-4.el7_|-x86_64_|-(none)_|-1487838477',
            'rpm-python_|-(none)_|-4.11.3_|-21.el7_|-x86_64_|-(none)_|-1487838477',
            'pygpgme_|-(none)_|-0.3_|-9.el7_|-x86_64_|-(none)_|-1487838478',
            'yum_|-(none)_|-3.4.3_|-150.el7.centos_|-noarch_|-(none)_|-1487838479',
            'lzo_|-(none)_|-2.06_|-8.el7_|-x86_64_|-(none)_|-1487838479',
            'qrencode-libs_|-(none)_|-3.4.1_|-3.el7_|-x86_64_|-(none)_|-1487838480',
            'ustr_|-(none)_|-1.0.4_|-16.el7_|-x86_64_|-(none)_|-1487838480',
            'shadow-utils_|-2_|-4.1.5.1_|-24.el7_|-x86_64_|-(none)_|-1487838481',
            'util-linux_|-(none)_|-2.23.2_|-33.el7_|-x86_64_|-(none)_|-1487838484',
            'openssh_|-(none)_|-6.6.1p1_|-33.el7_3_|-x86_64_|-(none)_|-1487838485',
            'virt-what_|-(none)_|-1.13_|-8.el7_|-x86_64_|-(none)_|-1487838486',
        ]
        with patch.dict(yumpkg.__grains__, {'osarch': 'x86_64'}), \
             patch.dict(yumpkg.__salt__, {'cmd.run': MagicMock(return_value=os.linesep.join(rpm_out))}), \
             patch.dict(yumpkg.__salt__, {'pkg_resource.add_pkg': _add_data}), \
             patch.dict(yumpkg.__salt__, {'pkg_resource.format_pkg_list': pkg_resource.format_pkg_list}), \
             patch.dict(yumpkg.__salt__, {'pkg_resource.stringify': MagicMock()}):
            pkgs = yumpkg.list_pkgs(attr=['epoch', 'release', 'arch', 'install_date_time_t'])
            for pkg_name, pkg_attr in {
                'python-urlgrabber': {
                    'version': '3.10',
                    'release': '8.el7',
                    'arch': 'noarch',
                    'install_date_time_t': 1487838471,
                },
                'alsa-lib': {
                    'version': '1.1.1',
                    'release': '1.el7',
                    'arch': 'x86_64',
                    'install_date_time_t': 1487838475,
                },
                'gnupg2': {
                    'version': '2.0.22',
                    'release': '4.el7',
                    'arch': 'x86_64',
                    'install_date_time_t': 1487838477,
                },
                'rpm-python': {
                    'version': '4.11.3',
                    'release': '21.el7',
                    'arch': 'x86_64',
                    'install_date_time_t': 1487838477,
                },
                'pygpgme': {
                    'version': '0.3',
                    'release': '9.el7',
                    'arch': 'x86_64',
                    'install_date_time_t': 1487838478,
                },
                'yum': {
                    'version': '3.4.3',
                    'release': '150.el7.centos',
                    'arch': 'noarch',
                    'install_date_time_t': 1487838479,
                },
                'lzo': {
                    'version': '2.06',
                    'release': '8.el7',
                    'arch': 'x86_64',
                    'install_date_time_t': 1487838479,
                },
                'qrencode-libs': {
                    'version': '3.4.1',
                    'release': '3.el7',
                    'arch': 'x86_64',
                    'install_date_time_t': 1487838480,
                },
                'ustr': {
                    'version': '1.0.4',
                    'release': '16.el7',
                    'arch': 'x86_64',
                    'install_date_time_t': 1487838480,
                },
                'shadow-utils': {
                    'epoch': '2',
                    'version': '4.1.5.1',
                    'release': '24.el7',
                    'arch': 'x86_64',
                    'install_date_time_t': 1487838481,
                },
                'util-linux': {
                    'version': '2.23.2',
                    'release': '33.el7',
                    'arch': 'x86_64',
                    'install_date_time_t': 1487838484,
                },
                'openssh': {
                    'version': '6.6.1p1',
                    'release': '33.el7_3',
                    'arch': 'x86_64',
                    'install_date_time_t': 1487838485,
                },
                'virt-what': {
                    'version': '1.13',
                    'release': '8.el7',
                    'install_date_time_t': 1487838486,
                    'arch': 'x86_64',
                }}.items():
                self.assertTrue(pkgs.get(pkg_name))
                self.assertEqual(pkgs[pkg_name], [pkg_attr])

    @skipIf(not yumpkg.HAS_YUM, 'Could not import yum')
    def test_yum_base_error(self):
        with patch('yum.YumBase') as mock_yum_yumbase:
            mock_yum_yumbase.side_effect = CommandExecutionError
            with pytest.raises(CommandExecutionError):
                yumpkg._get_yum_config()


@skipIf(pytest is None, 'PyTest is missing')
class YumUtilsTestCase(TestCase, LoaderModuleMockMixin):
    '''
    Yum/Dnf utils tests.
    '''
    def setup_loader_modules(self):
        return {
            yumpkg: {
                '__context__': {
                    'yum_bin': 'fake-yum',
                },
                '__grains__': {
                    'osarch': 'x86_64',
                    'os_family': 'RedHat',
                    'osmajorrelease': 7,
                },
            }
        }

    def test_call_yum_default(self):
        '''
        Call default Yum/Dnf.
        :return:
        '''
        with patch.dict(yumpkg.__salt__, {'cmd.run_all': MagicMock(), 'config.get': MagicMock(return_value=False)}):
            yumpkg._call_yum(['-y', '--do-something'])  # pylint: disable=W0106
            yumpkg.__salt__['cmd.run_all'].assert_called_once_with(
                ['fake-yum', '-y', '--do-something'], env={},
                output_loglevel='trace', python_shell=False)

    @patch('hubblestack.utils.systemd.has_scope', MagicMock(return_value=True))
    def test_call_yum_in_scope(self):
        '''
        Call Yum/Dnf within the scope.
        :return:
        '''
        with patch.dict(yumpkg.__salt__, {'cmd.run_all': MagicMock(), 'config.get': MagicMock(return_value=True)}):
            yumpkg._call_yum(['-y', '--do-something'])  # pylint: disable=W0106
            yumpkg.__salt__['cmd.run_all'].assert_called_once_with(
                ['systemd-run', '--scope', 'fake-yum', '-y', '--do-something'], env={},
                output_loglevel='trace', python_shell=False)

    def test_call_yum_with_kwargs(self):
        '''
        Call Yum/Dnf with the optinal keyword arguments.
        :return:
        '''
        with patch.dict(yumpkg.__salt__, {'cmd.run_all': MagicMock(), 'config.get': MagicMock(return_value=False)}):
            yumpkg._call_yum(['-y', '--do-something'],
                             python_shell=True, output_loglevel='quiet', ignore_retcode=False,
                             username='Darth Vader')  # pylint: disable=W0106
            yumpkg.__salt__['cmd.run_all'].assert_called_once_with(
                ['fake-yum', '-y', '--do-something'], env={}, ignore_retcode=False,
                output_loglevel='quiet', python_shell=True, username='Darth Vader')
