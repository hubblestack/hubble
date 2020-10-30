# -*- coding: utf-8 -*-

# Import Python libs
from __future__ import absolute_import, print_function, unicode_literals

# Import Salt Testing Libs
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import TestCase, skipIf
from tests.support.mock import (
    MagicMock,
    patch,
    NO_MOCK,
    NO_MOCK_REASON,
    call
)

# Import Salt Libs
import hubblestack.modules.gentoo_service as gentoo_service


@skipIf(NO_MOCK, NO_MOCK_REASON)
class GentooServicesTestCase(TestCase, LoaderModuleMockMixin):
    '''
    Test cases for hubblestack.modules.gentoo_service
    '''

    def setup_loader_modules(self):
        return {gentoo_service: {}}

    def test_service_list_parser(self):
        '''
        Test for parser of rc-status results
        '''
        # no services is enabled
        mock = MagicMock(return_value='')
        with patch.dict(gentoo_service.__mods__, {'cmd.run': mock}):
            self.assertFalse(gentoo_service.get_enabled())
        mock.assert_called_once_with('rc-update -v show')

    def test_get_enabled_single_runlevel(self):
        '''
        Test for Return a list of service that are enabled on boot
        '''
        service_name = 'name'
        runlevels = ['default']
        mock = MagicMock(return_value=self.__services({service_name: runlevels}))
        with patch.dict(gentoo_service.__mods__, {'cmd.run': mock}):
            enabled_services = gentoo_service.get_enabled()
            self.assertTrue(service_name in enabled_services)
            self.assertEqual(enabled_services[service_name], runlevels)

    def test_get_enabled_filters_out_disabled_services(self):
        '''
        Test for Return a list of service that are enabled on boot
        '''
        service_name = 'name'
        runlevels = ['default']
        disabled_service = 'disabled'
        service_list = self.__services({service_name: runlevels, disabled_service: []})

        mock = MagicMock(return_value=service_list)
        with patch.dict(gentoo_service.__mods__, {'cmd.run': mock}):
            enabled_services = gentoo_service.get_enabled()
            self.assertEqual(len(enabled_services), 1)
            self.assertTrue(service_name in enabled_services)
            self.assertEqual(enabled_services[service_name], runlevels)

    def test_get_enabled_with_multiple_runlevels(self):
        '''
        Test for Return a list of service that are enabled on boot at more than one runlevel
        '''
        service_name = 'name'
        runlevels = ['non-default', 'default']
        mock = MagicMock(return_value=self.__services({service_name: runlevels}))
        with patch.dict(gentoo_service.__mods__, {'cmd.run': mock}):
            enabled_services = gentoo_service.get_enabled()
            self.assertTrue(service_name in enabled_services)
            self.assertEqual(enabled_services[service_name][0], runlevels[1])
            self.assertEqual(enabled_services[service_name][1], runlevels[0])

    def test_available(self):
        '''
        Test for Returns ``True`` if the specified service is
        available, otherwise returns
        ``False``.
        '''
        disabled_service = 'disabled'
        enabled_service = 'enabled'
        multilevel_service = 'multilevel'
        missing_service = 'missing'
        shutdown_service = 'shutdown'
        service_list = self.__services({disabled_service: [],
                                        enabled_service: ['default'],
                                        multilevel_service: ['default', 'shutdown'],
                                        shutdown_service: ['shutdown']})
        mock = MagicMock(return_value=service_list)
        with patch.dict(gentoo_service.__mods__, {'cmd.run': mock}):
            self.assertTrue(gentoo_service.available(enabled_service))
            self.assertTrue(gentoo_service.available(multilevel_service))
            self.assertTrue(gentoo_service.available(disabled_service))
            self.assertTrue(gentoo_service.available(shutdown_service))
            self.assertFalse(gentoo_service.available(missing_service))

    def test_getall(self):
        '''
        Test for Return all available boot services
        '''
        disabled_service = 'disabled'
        enabled_service = 'enabled'
        service_list = self.__services({disabled_service: [],
                                        enabled_service: ['default']})
        mock = MagicMock(return_value=service_list)
        with patch.dict(gentoo_service.__mods__, {'cmd.run': mock}):
            all_services = gentoo_service.get_all()
            self.assertEqual(len(all_services), 2)
            self.assertTrue(disabled_service in all_services)
            self.assertTrue(enabled_service in all_services)

    def test_status(self):
        '''
        Test for Return the status for a service
        '''
        mock = MagicMock(return_value=True)
        with patch.dict(gentoo_service.__mods__, {'status.pid': mock}):
            self.assertTrue(gentoo_service.status('name', 1))

        # service is running
        mock = MagicMock(return_value=0)
        with patch.dict(gentoo_service.__mods__, {'cmd.retcode': mock}):
            self.assertTrue(gentoo_service.status('name'))
        mock.assert_called_once_with('/etc/init.d/name status',
                                     ignore_retcode=True,
                                     python_shell=False)

        # service is not running
        mock = MagicMock(return_value=1)
        with patch.dict(gentoo_service.__mods__, {'cmd.retcode': mock}):
            self.assertFalse(gentoo_service.status('name'))
        mock.assert_called_once_with('/etc/init.d/name status',
                                     ignore_retcode=True,
                                     python_shell=False)

        # service is stopped
        mock = MagicMock(return_value=3)
        with patch.dict(gentoo_service.__mods__, {'cmd.retcode': mock}):
            self.assertFalse(gentoo_service.status('name'))
        mock.assert_called_once_with('/etc/init.d/name status',
                                     ignore_retcode=True,
                                     python_shell=False)

        # service has crashed
        mock = MagicMock(return_value=32)
        with patch.dict(gentoo_service.__mods__, {'cmd.retcode': mock}):
            self.assertFalse(gentoo_service.status('name'))
        mock.assert_called_once_with('/etc/init.d/name status',
                                     ignore_retcode=True,
                                     python_shell=False)

    def test_enabled(self):
        '''
        Test for Return True if the named service is enabled, false otherwise
        '''
        mock = MagicMock(return_value={'name': ['default']})
        with patch.object(gentoo_service, 'get_enabled', mock):
            # service is enabled at any level
            self.assertTrue(gentoo_service.enabled('name'))
            # service is enabled at the requested runlevels
            self.assertTrue(gentoo_service.enabled('name', runlevels='default'))
            # service is enabled at a different runlevels
            self.assertFalse(gentoo_service.enabled('name', runlevels='boot'))

        mock = MagicMock(return_value={'name': ['boot', 'default']})
        with patch.object(gentoo_service, 'get_enabled', mock):
            # service is enabled at any level
            self.assertTrue(gentoo_service.enabled('name'))
            # service is enabled at the requested runlevels
            self.assertTrue(gentoo_service.enabled('name', runlevels='default'))
            # service is enabled at all levels
            self.assertTrue(gentoo_service.enabled('name', runlevels=['boot', 'default']))
            # service is enabled at a different runlevels
            self.assertFalse(gentoo_service.enabled('name', runlevels='some-other-level'))
            # service is enabled at a different runlevels
            self.assertFalse(gentoo_service.enabled('name', runlevels=['boot', 'some-other-level']))

    def __services(self, services):
        return '\n'.join([' | '.join([svc, ' '.join(services[svc])]) for svc in services])
