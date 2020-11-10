# -*- coding: utf-8 -*-
'''
    :codeauthor: Pedro Algarvio (pedro@algarvio.me)
    :copyright: Copyright 2017 by the SaltStack Team, see AUTHORS for more details.
    :license: Apache 2.0, see LICENSE for more details.


    tests.support.paths
    ~~~~~~~~~~~~~~~~~~~

    Tests related paths
'''

import os
import re
import sys
import stat
import logging
import tempfile
import textwrap

import hubblestack.utils.path

log = logging.getLogger(__name__)

TESTS_DIR = os.path.dirname(os.path.dirname(os.path.normpath(os.path.abspath(__file__))))
if TESTS_DIR.startswith('//'):
    # Have we been given an initial double forward slash? Ditch it!
    TESTS_DIR = TESTS_DIR[1:]
if sys.platform.startswith('win'):
    TESTS_DIR = os.path.normcase(TESTS_DIR)
CODE_DIR = os.path.dirname(TESTS_DIR)
if sys.platform.startswith('win'):
    CODE_DIR = CODE_DIR.replace('\\', '\\\\')
UNIT_TEST_FILES_DIR = os.path.join(TESTS_DIR, 'unittests')

# Let's inject CODE_DIR so salt is importable if not there already
if TESTS_DIR in sys.path:
    sys.path.remove(TESTS_DIR)
if CODE_DIR in sys.path and sys.path[0] != CODE_DIR:
    sys.path.remove(CODE_DIR)
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)
if TESTS_DIR not in sys.path:
    sys.path.insert(1, TESTS_DIR)

SYS_TMP_DIR = os.path.abspath(os.path.realpath(
    # Avoid ${TMPDIR} and gettempdir() on MacOS as they yield a base path too long
    # for unix sockets: ``error: AF_UNIX path too long``
    # Gentoo Portage prefers ebuild tests are rooted in ${TMPDIR}
    os.environ.get('TMPDIR', tempfile.gettempdir()) if not sys.platform.startswith('darwin') else '/tmp'
))
TMP = os.path.join(SYS_TMP_DIR, 'salt-tests-tmpdir')
FILES = os.path.join(UNIT_TEST_FILES_DIR, 'test_files')
PYEXEC = 'python{0}.{1}'.format(*sys.version_info)
TMP_CONF_DIR = os.path.join(TMP, 'config')
LOG_HANDLERS_DIR = os.path.join(FILES, 'log_handlers')

