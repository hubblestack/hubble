# -*- coding: utf-8 -*-
'''
    :copyright: Copyright 2017 by the SaltStack Team, see AUTHORS for more details.
    :license: Apache 2.0, see LICENSE for more details.


    hubblestack.utils.versions
    ~~~~~~~~~~~~~~~~~~~

    Version parsing based on distutils.version which works under python 3
    because on python 3 you can no longer compare strings against integers.
'''

# Import Python libs
from __future__ import absolute_import, print_function, unicode_literals
import logging
import numbers
import sys
import warnings
from distutils.version import LooseVersion as _LooseVersion

log = logging.getLogger(__name__)

class LooseVersion(_LooseVersion):

    def parse(self, vstring):
        _LooseVersion.parse(self, vstring)

        # Convert every part of the version to string in order to be able to compare
        self._str_version = [
            str(vp).zfill(8) if isinstance(vp, int) else vp for vp in self.version]

    def _cmp(self, other):
        if isinstance(other, str):
            other = LooseVersion(other)

        string_in_version = False
        for part in self.version + other.version:
            if not isinstance(part, int):
                string_in_version = True
                break

        if string_in_version is False:
            return _LooseVersion._cmp(self, other)

        # If we reached this far, it means at least a part of the version contains a string
        # In python 3, strings and integers are not comparable
        if self._str_version == other._str_version:
            return 0
        if self._str_version < other._str_version:
            return -1
        if self._str_version > other._str_version:
            return 1


def version_cmp(pkg1, pkg2, ignore_epoch=False):
    '''
    Compares two version strings using hubblestack.utils.versions.LooseVersion. This
    is a fallback for providers which don't have a version comparison utility
    built into them.  Return -1 if version1 < version2, 0 if version1 ==
    version2, and 1 if version1 > version2. Return None if there was a problem
    making the comparison.
    '''
    normalize = lambda x: str(x).split(':', 1)[-1] \
                if ignore_epoch else str(x)
    pkg1 = normalize(pkg1)
    pkg2 = normalize(pkg2)

    try:
        # pylint: disable=no-member
        if LooseVersion(pkg1) < LooseVersion(pkg2):
            return -1
        elif LooseVersion(pkg1) == LooseVersion(pkg2):
            return 0
        elif LooseVersion(pkg1) > LooseVersion(pkg2):
            return 1
    except Exception as exc:
        log.exception(exc)
    return None

