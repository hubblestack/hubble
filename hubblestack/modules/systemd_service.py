# -*- coding: utf-8 -*-
'''
Provides the service module for systemd

.. versionadded:: 0.10.0

.. important::
    If you feel that Salt should be using this module to manage services on a
    minion, and it is using a different module (or gives an error similar to
    *'service.start' is not available*), see :ref:`here
    <module-provider-override>`.
'''
# Import Python libs
import errno
import glob
import logging
import os
import fnmatch
import re
import shlex

# Import Salt libs
import hubblestack.utils.files
import hubblestack.utils.itertools
import hubblestack.utils.stringutils
import hubblestack.utils.systemd
from hubblestack.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

__func_alias__ = {
    'reload_': 'reload',
    'unmask_': 'unmask',
}

SYSTEM_CONFIG_PATHS = ('/lib/systemd/system', '/usr/lib/systemd/system')
LOCAL_CONFIG_PATH = '/etc/systemd/system'
INITSCRIPT_PATH = '/etc/init.d'
VALID_UNIT_TYPES = ('service', 'socket', 'device', 'mount', 'automount',
                    'swap', 'target', 'path', 'timer')

# Define the module's virtual name
__virtualname__ = 'service'

# Disable check for string substitution
# pylint: disable=E1321


def __virtual__():
    '''
    Only work on systems that have been booted with systemd
    '''
    if __grains__['kernel'] == 'Linux' \
            and hubblestack.utils.systemd.booted(__context__):
        return __virtualname__
    return (
        False,
        'The systemd execution module failed to load: only available on Linux '
        'systems which have been booted with systemd.'
    )

# The unused sig argument is required to maintain consistency with the API
# established by Salt's service management states.
def status(name, sig=None):  # pylint: disable=unused-argument
    '''
    Return the status for a service via systemd.
    If the name contains globbing, a dict mapping service name to True/False
    values is returned.

    .. versionchanged:: 2018.3.0
        The service name can now be a glob (e.g. ``salt*``)

    Args:
        name (str): The name of the service to check
        sig (str): Not implemented

    Returns:
        bool: True if running, False otherwise
        dict: Maps service name to True if running, False otherwise

    CLI Example:

    .. code-block:: bash

        salt '*' service.status <service name> [service signature]
    '''
    contains_globbing = bool(re.search(r'\*|\?|\[.+\]', name))
    if contains_globbing:
        services = fnmatch.filter(get_all(), name)
    else:
        services = [name]
    results = {}
    for service in services:
        _check_for_unit_changes(service)
        results[service] = __mods__['cmd.retcode'](_systemctl_cmd('is-active', service),
                                                   python_shell=False,
                                                   ignore_retcode=True) == 0
    if contains_globbing:
        return results
    return results[name]

def available(name):
    '''
    .. versionadded:: 0.10.4

    Check that the given service is available taking into account template
    units.

    CLI Example:

    .. code-block:: bash

        salt '*' service.available sshd
    '''
    _check_for_unit_changes(name)
    return _check_available(name)

# The unused kwargs argument is required to maintain consistency with the API
# established by Salt's service management states.
def enabled(name, **kwargs):  # pylint: disable=unused-argument
    '''
    Return if the named service is enabled to start on boot

    CLI Example:

    .. code-block:: bash

        salt '*' service.enabled <service name>
    '''
    # Try 'systemctl is-enabled' first, then look for a symlink created by
    # systemctl (older systemd releases did not support using is-enabled to
    # check templated services), and lastly check for a sysvinit service.
    if __mods__['cmd.retcode'](_systemctl_cmd('is-enabled', name),
                               python_shell=False,
                               ignore_retcode=True) == 0:
        return True
    elif '@' in name:
        # On older systemd releases, templated services could not be checked
        # with ``systemctl is-enabled``. As a fallback, look for the symlinks
        # created by systemctl when enabling templated services.
        cmd = ['find', LOCAL_CONFIG_PATH, '-name', name,
               '-type', 'l', '-print', '-quit']
        # If the find command returns any matches, there will be output and the
        # string will be non-empty.
        if bool(__mods__['cmd.run'](cmd, python_shell=False)):
            return True
    elif name in _get_sysv_services():
        return _sysv_enabled(name)

    return False


def get_all():
    '''
    Return a list of all available services

    CLI Example:

    .. code-block:: bash

        salt '*' service.get_all
    '''
    ret = _get_systemd_services()
    ret.update(set(_get_sysv_services(systemd_services=ret)))
    return sorted(ret)

def _get_systemd_services():
    '''
    Use os.listdir() to get all the unit files
    '''
    ret = set()
    for path in SYSTEM_CONFIG_PATHS + (LOCAL_CONFIG_PATH,):
        # Make sure user has access to the path, and if the path is a link
        # it's likely that another entry in SYSTEM_CONFIG_PATHS or LOCAL_CONFIG_PATH
        # points to it, so we can ignore it.
        if os.access(path, os.R_OK) and not os.path.islink(path):
            for fullname in os.listdir(path):
                try:
                    unit_name, unit_type = fullname.rsplit('.', 1)
                except ValueError:
                    continue
                if unit_type in VALID_UNIT_TYPES:
                    ret.add(unit_name if unit_type == 'service' else fullname)
    return ret

def _get_sysv_services(systemd_services=None):
    '''
    Use os.listdir() and os.access() to get all the initscripts
    '''
    try:
        sysv_services = os.listdir(INITSCRIPT_PATH)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            pass
        elif exc.errno == errno.EACCES:
            log.error(
                'Unable to check sysvinit scripts, permission denied to %s',
                INITSCRIPT_PATH
            )
        else:
            log.error(
                'Error %d encountered trying to check sysvinit scripts: %s',
                exc.errno,
                exc.strerror
            )
        return []

    if systemd_services is None:
        systemd_services = _get_systemd_services()

    ret = []
    for sysv_service in sysv_services:
        if os.access(os.path.join(INITSCRIPT_PATH, sysv_service), os.X_OK):
            if sysv_service in systemd_services:
                log.debug(
                    'sysvinit script \'%s\' found, but systemd unit '
                    '\'%s.service\' already exists',
                    sysv_service, sysv_service
                )
                continue
            ret.append(sysv_service)
    return ret

def _check_for_unit_changes(name):
    '''
    Check for modified/updated unit files, and run a daemon-reload if any are
    found.
    '''
    contextkey = 'systemd._check_for_unit_changes.{0}'.format(name)
    if contextkey not in __context__:
        if _untracked_custom_unit_found(name) or _unit_file_changed(name):
            systemctl_reload()
        # Set context key to avoid repeating this check
        __context__[contextkey] = True

def _untracked_custom_unit_found(name):
    '''
    If the passed service name is not available, but a unit file exist in
    /etc/systemd/system, return True. Otherwise, return False.
    '''
    unit_path = os.path.join('/etc/systemd/system',
                             _canonical_unit_name(name))
    return os.access(unit_path, os.R_OK) and not _check_available(name)

def _canonical_unit_name(name):
    '''
    Build a canonical unit name treating unit names without one
    of the valid suffixes as a service.
    '''
    if not isinstance(name, str):
        name = str(name)
    if any(name.endswith(suffix) for suffix in VALID_UNIT_TYPES):
        return name
    return '%s.service' % name

def _check_available(name):
    '''
    Returns boolean telling whether or not the named service is available
    '''
    _status = _systemctl_status(name)
    sd_version = hubblestack.utils.systemd.version(__context__)
    if sd_version is not None and sd_version >= 231:
        # systemd 231 changed the output of "systemctl status" for unknown
        # services, and also made it return an exit status of 4. If we are on
        # a new enough version, check the retcode, otherwise fall back to
        # parsing the "systemctl status" output.
        # See: https://github.com/systemd/systemd/pull/3385
        # Also: https://github.com/systemd/systemd/commit/3dced37
        return 0 <= _status['retcode'] < 4

    out = _status['stdout'].lower()
    if 'could not be found' in out:
        # Catch cases where the systemd version is < 231 but the return code
        # and output changes have been backported (e.g. RHEL 7.3).
        return False

    for line in hubblestack.utils.itertools.split(out, '\n'):
        match = re.match(r'\s+loaded:\s+(\S+)', line)
        if match:
            ret = match.group(1) != 'not-found'
            break
    else:
        raise CommandExecutionError(
            'Failed to get information on unit \'%s\'' % name
        )
    return ret

def _systemctl_status(name):
    '''
    Helper function which leverages __context__ to keep from running 'systemctl
    status' more than once.
    '''
    contextkey = 'systemd._systemctl_status.%s' % name
    if contextkey in __context__:
        return __context__[contextkey]
    __context__[contextkey] = __mods__['cmd.run_all'](
        _systemctl_cmd('status', name),
        python_shell=False,
        redirect_stderr=True,
        ignore_retcode=True
    )
    return __context__[contextkey]

def _systemctl_cmd(action, name=None, systemd_scope=False, no_block=False):
    '''
    Build a systemctl command line. Treat unit names without one
    of the valid suffixes as a service.
    '''
    ret = []
    if systemd_scope \
            and hubblestack.utils.systemd.has_scope(__context__) \
            and __mods__['config.get']('systemd.scope', True):
        ret.extend(['systemd-run', '--scope'])
    ret.append('systemctl')
    if no_block:
        ret.append('--no-block')
    if isinstance(action, str):
        action = shlex.split(action)
    ret.extend(action)
    if name is not None:
        ret.append(_canonical_unit_name(name))
    if 'status' in ret:
        ret.extend(['-n', '0'])
    return ret

def _unit_file_changed(name):
    '''
    Returns True if systemctl reports that the unit file has changed, otherwise
    returns False.
    '''
    return "'systemctl daemon-reload'" in _systemctl_status(name)['stdout'].lower()

def systemctl_reload():
    '''
    .. versionadded:: 0.15.0

    Reloads systemctl, an action needed whenever unit files are updated.

    CLI Example:

    .. code-block:: bash

        salt '*' service.systemctl_reload
    '''
    out = __mods__['cmd.run_all'](
        _systemctl_cmd('--system daemon-reload'),
        python_shell=False,
        redirect_stderr=True
    )
    if out['retcode'] != 0:
        raise CommandExecutionError(
            'Problem performing systemctl daemon-reload: %s' % out['stdout']
        )
    _clear_context()
    return True

def _clear_context():
    '''
    Remove context
    '''
    # Using list() here because modifying a dictionary during iteration will
    # raise a RuntimeError.
    for key in list(__context__):
        try:
            if key.startswith('systemd._systemctl_status.'):
                __context__.pop(key)
        except AttributeError:
            continue

def _sysv_enabled(name):
    '''
    A System-V style service is assumed disabled if the "startup" symlink
    (starts with "S") to its script is found in /etc/init.d in the current
    runlevel.
    '''
    # Find exact match (disambiguate matches like "S01anacron" for cron)
    for match in glob.glob('/etc/rc%s.d/S*%s' % (_runlevel(), name)):
        if re.match(r'S\d{,2}%s' % name, os.path.basename(match)):
            return True
    return False

def _runlevel():
    '''
    Return the current runlevel
    '''
    contextkey = 'systemd._runlevel'
    if contextkey in __context__:
        return __context__[contextkey]
    out = __mods__['cmd.run']('runlevel', python_shell=False, ignore_retcode=True)
    try:
        ret = out.split()[1]
    except IndexError:
        # The runlevel is unknown, return the default
        ret = _default_runlevel()
    __context__[contextkey] = ret
    return ret

def _default_runlevel():
    '''
    Try to figure out the default runlevel.  It is kept in
    /etc/init/rc-sysinit.conf, but can be overridden with entries
    in /etc/inittab, or via the kernel command-line at boot
    '''
    # Try to get the "main" default.  If this fails, throw up our
    # hands and just guess "2", because things are horribly broken
    try:
        with hubblestack.utils.files.fopen('/etc/init/rc-sysinit.conf') as fp_:
            for line in fp_:
                line = hubblestack.utils.stringutils.to_unicode(line)
                if line.startswith('env DEFAULT_RUNLEVEL'):
                    runlevel = line.split('=')[-1].strip()
    except Exception:
        return '2'

    # Look for an optional "legacy" override in /etc/inittab
    try:
        with hubblestack.utils.files.fopen('/etc/inittab') as fp_:
            for line in fp_:
                line = hubblestack.utils.stringutils.to_unicode(line)
                if not line.startswith('#') and 'initdefault' in line:
                    runlevel = line.split(':')[1]
    except Exception:
        pass

    # The default runlevel can also be set via the kernel command-line.
    # Kinky.
    try:
        valid_strings = set(
            ('0', '1', '2', '3', '4', '5', '6', 's', 'S', '-s', 'single'))
        with hubblestack.utils.files.fopen('/proc/cmdline') as fp_:
            for line in fp_:
                line = hubblestack.utils.stringutils.to_unicode(line)
                for arg in line.strip().split():
                    if arg in valid_strings:
                        runlevel = arg
                        break
    except Exception:
        pass

    return runlevel