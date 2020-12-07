# -*- coding: utf-8 -*-
'''
Package support for openSUSE via the zypper package manager

:depends: - ``rpm`` Python module.  Install with ``zypper install rpm-python``

.. important::
    If you feel that Salt should be using this module to manage packages on a
    minion, and it is using a different module (or gives an error similar to
    *'pkg.install' is not available*), see :ref:`here
    <module-provider-override>`.

'''

# Import python libs
import fnmatch
import logging
import re
import os
import time
import datetime

from xml.dom import minidom as dom
from xml.parsers.expat import ExpatError

# Import salt libs
import hubblestack.utils.data
import hubblestack.utils.files
import hubblestack.utils.path
import hubblestack.utils.pkg
import hubblestack.utils.pkg.rpm
import hubblestack.utils.stringutils
import hubblestack.utils.environment
import hubblestack.utils.args
from hubblestack.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

HAS_ZYPP = False
ZYPP_HOME = '/etc/zypp'
LOCKS = '{0}/locks'.format(ZYPP_HOME)
REPOS = '{0}/repos.d'.format(ZYPP_HOME)
DEFAULT_PRIORITY = 99

# Define the module's virtual name
__virtualname__ = 'pkg'


def __virtual__():
    '''
    Set the virtual pkg module if the os is openSUSE
    '''
    if __grains__.get('os_family', '') != 'Suse':
        return (False, "Module zypper: non SUSE OS not suppored by zypper package manager")
    # Not all versions of SUSE use zypper, check that it is available
    if not hubblestack.utils.path.which('zypper'):
        return (False, "Module zypper: zypper package manager not found")
    return __virtualname__

class _Zypper(object):
    '''
    Zypper parallel caller.
    Validates the result and either raises an exception or reports an error.
    Allows serial zypper calls (first came, first won).
    '''

    SUCCESS_EXIT_CODES = {
        0: 'Successful run of zypper with no special info.',
        100: 'Patches are available for installation.',
        101: 'Security patches are available for installation.',
        102: 'Installation successful, reboot required.',
        103: 'Installation succesful, restart of the package manager itself required.',
    }

    WARNING_EXIT_CODES = {
        6: 'No repositories are defined.',
        7: 'The ZYPP library is locked.',
        106: 'Some repository had to be disabled temporarily because it failed to refresh. '
             'You should check your repository configuration (e.g. zypper ref -f).',
        107: 'Installation basically succeeded, but some of the packages %post install scripts returned an error. '
             'These packages were successfully unpacked to disk and are registered in the rpm database, '
             'but due to the failed install script they may not work as expected. The failed scripts output might '
             'reveal what actually went wrong. Any scripts output is also logged to /var/log/zypp/history.'
    }

    LOCK_EXIT_CODE = 7
    XML_DIRECTIVES = ['-x', '--xmlout']
    ZYPPER_LOCK = '/var/run/zypp.pid'
    TAG_RELEASED = 'zypper/released'
    TAG_BLOCKED = 'zypper/blocked'

    def __init__(self):
        '''
        Constructor
        '''
        self.__called = False
        self._reset()

    def _reset(self):
        '''
        Resets values of the call setup.

        :return:
        '''
        self.__cmd = ['zypper', '--non-interactive']
        self.__exit_code = 0
        self.__call_result = dict()
        self.__error_msg = ''
        self.__env = hubblestack.utils.environment.get_module_environment(globals())

        # Call config
        self.__xml = False
        self.__no_lock = False
        self.__no_raise = False
        self.__refresh = False
        self.__ignore_repo_failure = False
        self.__systemd_scope = False

    def __call__(self, *args, **kwargs):
        '''
        :param args:
        :param kwargs:
        :return:
        '''
        # Ignore exit code for 106 (repo is not available)
        if 'no_repo_failure' in kwargs:
            self.__ignore_repo_failure = kwargs['no_repo_failure']
        if 'systemd_scope' in kwargs:
            self.__systemd_scope = kwargs['systemd_scope']
        return self

    def __getattr__(self, item):
        '''
        Call configurator.

        :param item:
        :return:
        '''
        # Reset after the call
        if self.__called:
            self._reset()
            self.__called = False

        if item == 'xml':
            self.__xml = True
        elif item == 'nolock':
            self.__no_lock = True
        elif item == 'noraise':
            self.__no_raise = True
        elif item == 'refreshable':
            self.__refresh = True
        elif item == 'call':
            return self.__call
        else:
            return self.__dict__[item]

        # Prevent the use of "refreshable" together with "nolock".
        if self.__no_lock:
            self.__no_lock = not self.__refresh

        return self

    @property
    def exit_code(self):
        return self.__exit_code

    @exit_code.setter
    def exit_code(self, exit_code):
        self.__exit_code = int(exit_code or '0')

    @property
    def error_msg(self):
        return self.__error_msg

    @error_msg.setter
    def error_msg(self, msg):
        if self._is_error():
            self.__error_msg = msg and os.linesep.join(msg) or "Check Zypper's logs."

    @property
    def stdout(self):
        return self.__call_result.get('stdout', '')

    @property
    def stderr(self):
        return self.__call_result.get('stderr', '')

    @property
    def pid(self):
        return self.__call_result.get('pid', '')

    def _is_error(self):
        '''
        Is this is an error code?

        :return:
        '''
        if self.exit_code:
            msg = self.SUCCESS_EXIT_CODES.get(self.exit_code)
            if msg:
                log.info(msg)
            msg = self.WARNING_EXIT_CODES.get(self.exit_code)
            if msg:
                log.warning(msg)

        return self.exit_code not in self.SUCCESS_EXIT_CODES and self.exit_code not in self.WARNING_EXIT_CODES

    def _is_lock(self):
        '''
        Is this is a lock error code?

        :return:
        '''
        return self.exit_code == self.LOCK_EXIT_CODE

    def _is_xml_mode(self):
        '''
        Is Zypper's output is in XML format?

        :return:
        '''
        return [itm for itm in self.XML_DIRECTIVES if itm in self.__cmd] and True or False

    def _check_result(self):
        '''
        Check and set the result of a zypper command. In case of an error,
        either raise a CommandExecutionError or extract the error.

        result
            The result of a zypper command called with cmd.run_all
        '''
        if not self.__call_result:
            raise CommandExecutionError('No output result from Zypper?')

        self.exit_code = self.__call_result['retcode']
        if self._is_lock():
            return False

        if self._is_error():
            _error_msg = list()
            if not self._is_xml_mode():
                msg = self.__call_result['stderr'] and self.__call_result['stderr'].strip() or ""
                if msg:
                    _error_msg.append(msg)
            else:
                try:
                    doc = dom.parseString(self.__call_result['stdout'])
                except ExpatError as err:
                    log.error(err)
                    doc = None
                if doc:
                    msg_nodes = doc.getElementsByTagName('message')
                    for node in msg_nodes:
                        if node.getAttribute('type') == 'error':
                            _error_msg.append(node.childNodes[0].nodeValue)
                elif self.__call_result['stderr'].strip():
                    _error_msg.append(self.__call_result['stderr'].strip())
            self.error_msg = _error_msg
        return True

    def __call(self, *args, **kwargs):
        '''
        Call Zypper.

        :param state:
        :return:
        '''
        self.__called = True
        if self.__xml:
            self.__cmd.append('--xmlout')
        if not self.__refresh:
            self.__cmd.append('--no-refresh')

        self.__cmd.extend(args)
        kwargs['output_loglevel'] = 'trace'
        kwargs['python_shell'] = False
        kwargs['env'] = self.__env.copy()
        if self.__no_lock:
            kwargs['env']['ZYPP_READONLY_HACK'] = "1"  # Disables locking for read-only operations. Do not try that at home!

        # Zypper call will stuck here waiting, if another zypper hangs until forever.
        # However, Zypper lock needs to be always respected.
        was_blocked = False
        while True:
            cmd = []
            if self.__systemd_scope:
                cmd.extend(['systemd-run', '--scope'])
            cmd.extend(self.__cmd)
            log.debug("Calling Zypper: " + ' '.join(cmd))
            self.__call_result = __mods__['cmd.run_all'](cmd, **kwargs)
            if self._check_result():
                break

            if os.path.exists(self.ZYPPER_LOCK):
                try:
                    with hubblestack.utils.files.fopen(self.ZYPPER_LOCK) as rfh:
                        data = __mods__['ps.proc_info'](int(rfh.readline()),
                                                        attrs=['pid', 'name', 'cmdline', 'create_time'])
                        data['cmdline'] = ' '.join(data['cmdline'])
                        data['info'] = 'Blocking process created at {0}.'.format(
                            datetime.datetime.utcfromtimestamp(data['create_time']).isoformat())
                        data['success'] = True
                except Exception as err:
                    data = {'info': 'Unable to retrieve information about blocking process: {0}'.format(err.message),
                            'success': False}
            else:
                data = {'info': 'Zypper is locked, but no Zypper lock has been found.', 'success': False}

            if not data['success']:
                log.debug("Unable to collect data about blocking process.")
            else:
                log.debug("Collected data about blocking process.")

            log.debug("Waiting 5 seconds for Zypper gets released...")
            time.sleep(5)
            if not was_blocked:
                was_blocked = True

        if self.error_msg and not self.__no_raise and not self.__ignore_repo_failure:
            raise CommandExecutionError('Zypper command failure: {0}'.format(self.error_msg))

        return (
            self._is_xml_mode() and
            dom.parseString(hubblestack.utils.stringutils.to_str(self.__call_result['stdout'])) or
            self.__call_result['stdout']
        )


__zypper__ = _Zypper()

def list_pkgs(versions_as_list=False, **kwargs):
    '''
    List the packages currently installed as a dict. By default, the dict
    contains versions as a comma separated string::

        {'<package_name>': '<version>[,<version>...]'}

    versions_as_list:
        If set to true, the versions are provided as a list

        {'<package_name>': ['<version>', '<version>']}

    attr:
        If a list of package attributes is specified, returned value will
        contain them in addition to version, eg.::

        {'<package_name>': [{'version' : 'version', 'arch' : 'arch'}]}

        Valid attributes are: ``epoch``, ``version``, ``release``, ``arch``,
        ``install_date``, ``install_date_time_t``.

        If ``all`` is specified, all valid attributes will be returned.

            .. versionadded:: 2018.3.0

    removed:
        not supported

    purge_desired:
        not supported
    '''
    versions_as_list = hubblestack.utils.data.is_true(versions_as_list)
    # not yet implemented or not applicable
    if any([hubblestack.utils.data.is_true(kwargs.get(x))
            for x in ('removed', 'purge_desired')]):
        return {}

    attr = kwargs.get('attr')
    if attr is not None:
        attr = hubblestack.utils.args.split_input(attr)

    contextkey = 'pkg.list_pkgs'

    if contextkey not in __context__:
        ret = {}
        cmd = ['rpm', '-qa', '--queryformat',
               hubblestack.utils.pkg.rpm.QUERYFORMAT.replace('%{REPOID}', '(none)') + '\n']
        output = __mods__['cmd.run'](cmd,
                                     python_shell=False,
                                     output_loglevel='trace')
        for line in output.splitlines():
            pkginfo = hubblestack.utils.pkg.rpm.parse_pkginfo(
                line,
                osarch=__grains__['osarch']
            )
            if pkginfo:
                # see rpm version string rules available at https://goo.gl/UGKPNd
                pkgver = pkginfo.version
                epoch = ''
                release = ''
                if ':' in pkgver:
                    epoch, pkgver = pkgver.split(":", 1)
                if '-' in pkgver:
                    pkgver, release = pkgver.split("-", 1)
                all_attr = {
                    'epoch': epoch,
                    'version': pkgver,
                    'release': release,
                    'arch': pkginfo.arch,
                    'install_date': pkginfo.install_date,
                    'install_date_time_t': pkginfo.install_date_time_t
                }
                __mods__['pkg_resource.add_pkg'](ret, pkginfo.name, all_attr)

        _ret = {}
        for pkgname in ret:
            # Filter out GPG public keys packages
            if pkgname.startswith('gpg-pubkey'):
                continue
            _ret[pkgname] = sorted(ret[pkgname], key=lambda d: d['version'])

        __context__[contextkey] = _ret

    return __mods__['pkg_resource.format_pkg_list'](
        __context__[contextkey],
        versions_as_list,
        attr)

def version(*names, **kwargs):
    '''
    Returns a string representing the package version or an empty dict if not
    installed. If more than one package name is specified, a dict of
    name/version pairs is returned.
    '''
    return __mods__['pkg_resource.version'](*names, **kwargs) or {}

def version_cmp(ver1, ver2, ignore_epoch=False):
    '''
    .. versionadded:: 2015.5.4

    Do a cmp-style comparison on two packages. Return -1 if ver1 < ver2, 0 if
    ver1 == ver2, and 1 if ver1 > ver2. Return None if there was a problem
    making the comparison.

    ignore_epoch : False
        Set to ``True`` to ignore the epoch when comparing versions

        .. versionadded:: 2015.8.10,2016.3.2
    '''
    return __mods__['lowpkg.version_cmp'](ver1, ver2, ignore_epoch=ignore_epoch)

def refresh_db():
    '''
    Force a repository refresh by calling ``zypper refresh --force``, return a dict::

        {'<database name>': Bool}
    '''
    # Remove rtag file to keep multiple refreshes from happening in pkg states
    hubblestack.utils.pkg.clear_rtag(__opts__)
    ret = {}
    out = __zypper__.refreshable.call('refresh', '--force')

    for line in out.splitlines():
        if not line:
            continue
        if line.strip().startswith('Repository') and '\'' in line:
            try:
                key = line.split('\'')[1].strip()
                if 'is up to date' in line:
                    ret[key] = False
            except IndexError:
                continue
        elif line.strip().startswith('Building') and '\'' in line:
            key = line.split('\'')[1].strip()
            if 'done' in line:
                ret[key] = True
    return ret
