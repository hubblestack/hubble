# -*- coding: utf-8 -*-
'''
Support for rpm
'''

# Import python libs
import logging
import os
import re
import datetime

import hubblestack.utils.path
import hubblestack.utils.pkg.rpm
import hubblestack.utils.versions

try:
    import rpm
    HAS_RPM = True
except ImportError:
    HAS_RPM = False

try:
    import rpmUtils.miscutils
    HAS_RPMUTILS = True
except ImportError:
    HAS_RPMUTILS = False

# pylint: enable=import-error,redefined-builtin
from hubblestack.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'lowpkg'


def __virtual__():
    '''
    Confine this module to rpm based systems
    '''
    if not hubblestack.utils.path.which('rpm'):
        return (False, 'The rpm execution module failed to load: rpm binary is not in the path.')
    try:
        os_grain = __grains__['os'].lower()
        os_family = __grains__['os_family'].lower()
    except Exception:
        return (False, 'The rpm execution module failed to load: failed to detect os or os_family grains.')

    enabled = ('amazon', 'xcp', 'xenserver', 'VirtuozzoLinux')

    if os_family in ['redhat', 'suse'] or os_grain in enabled:
        return __virtualname__
    return (False, 'The rpm execution module failed to load: only available on redhat/suse type systems '
        'or amazon, xcp or xenserver.')

def version_cmp(ver1, ver2, ignore_epoch=False):
    '''
    .. versionadded:: 2015.8.9

    Do a cmp-style comparison on two packages. Return -1 if ver1 < ver2, 0 if
    ver1 == ver2, and 1 if ver1 > ver2. Return None if there was a problem
    making the comparison.

    ignore_epoch : False
        Set to ``True`` to ignore the epoch when comparing versions

        .. versionadded:: 2015.8.10,2016.3.2
    '''
    normalize = lambda x: str(x).split(':', 1)[-1] \
        if ignore_epoch \
        else str(x)
    ver1 = normalize(ver1)
    ver2 = normalize(ver2)

    try:
        cmp_func = None
        if HAS_RPM:
            try:
                cmp_func = rpm.labelCompare
            except AttributeError:
                # Catches corner case where someone has a module named "rpm" in
                # their pythonpath.
                log.debug(
                    'rpm module imported, but it does not have the '
                    'labelCompare function. Not using rpm.labelCompare for '
                    'version comparison.'
                )
        if cmp_func is None and HAS_RPMUTILS:
            try:
                cmp_func = rpmUtils.miscutils.compareEVR
            except AttributeError:
                log.debug('rpmUtils.miscutils.compareEVR is not available')

        if cmp_func is None:
            if hubblestack.utils.path.which('rpmdev-vercmp'):
                # rpmdev-vercmp always uses epochs, even when zero
                def _ensure_epoch(ver):
                    def _prepend(ver):
                        return '0:{0}'.format(ver)

                    try:
                        if ':' not in ver:
                            return _prepend(ver)
                    except TypeError:
                        return _prepend(ver)
                    return ver

                ver1 = _ensure_epoch(ver1)
                ver2 = _ensure_epoch(ver2)
                result = __mods__['cmd.run_all'](
                    ['rpmdev-vercmp', ver1, ver2],
                    python_shell=False,
                    redirect_stderr=True,
                    ignore_retcode=True)
                # rpmdev-vercmp returns 0 on equal, 11 on greater-than, and
                # 12 on less-than.
                if result['retcode'] == 0:
                    return 0
                elif result['retcode'] == 11:
                    return 1
                elif result['retcode'] == 12:
                    return -1
                else:
                    # We'll need to fall back to hubblestack.utils.versions.version_cmp()
                    log.warning(
                        'Failed to interpret results of rpmdev-vercmp output. '
                        'This is probably a bug, and should be reported. '
                        'Return code was %s. Output: %s',
                        result['retcode'], result['stdout']
                    )
            else:
                # We'll need to fall back to hubblestack.utils.versions.version_cmp()
                log.warning(
                    'rpmdevtools is not installed, please install it for '
                    'more accurate version comparisons'
                )
        else:
            # If one EVR is missing a release but not the other and they
            # otherwise would be equal, ignore the release. This can happen if
            # e.g. you are checking if a package version 3.2 is satisfied by
            # 3.2-1.
            (ver1_e, ver1_v, ver1_r) = hubblestack.utils.pkg.rpm.version_to_evr(ver1)
            (ver2_e, ver2_v, ver2_r) = hubblestack.utils.pkg.rpm.version_to_evr(ver2)
            if not ver1_r or not ver2_r:
                ver1_r = ver2_r = ''

            cmp_result = cmp_func((ver1_e, ver1_v, ver1_r),
                                  (ver2_e, ver2_v, ver2_r))
            if cmp_result not in (-1, 0, 1):
                raise CommandExecutionError(
                    'Comparison result \'{0}\' is invalid'.format(cmp_result)
                )
            return cmp_result

    except Exception as exc:
        log.warning(
            'Failed to compare version \'%s\' to \'%s\' using RPM: %s',
            ver1, ver2, exc
        )

    # We would already have normalized the versions at the beginning of this
    # function if ignore_epoch=True, so avoid unnecessary work and just pass
    # False for this value.
    return hubblestack.utils.versions.version_cmp(ver1, ver2, ignore_epoch=False)

