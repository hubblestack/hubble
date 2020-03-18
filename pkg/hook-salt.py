# -*- coding: utf-8 -*-
"""
    :codeauthor: :email:`Pedro Algarvio (pedro@algarvio.me)`
    :copyright: © 2016 by the SaltStack Team, see AUTHORS for more details.
    :license: Apache 2.0, see LICENSE for more details.


    hook-salt.py
    ~~~~~~~~~~~~

    @todo: add description
"""
import os
from PyInstaller.utils.hooks import (collect_data_files,
                                     collect_submodules,
                                     collect_dynamic_libs,)

DATAS = []
BINARIES = []
HIDDEN_IMPORTS = []
# Let's handle salt.
# For salt we include the loader modules source files in DATAS and remove those from HIDDEN_IMPORTS
# This is the only way the salt loader seems to work
HIDDEN_IMPORTS.extend(collect_submodules('salt'))
DATAS.extend(collect_data_files('salt', include_py_files=True))

# Let's filter out salt loader modules which are included as data files
SALT_LOADERS = [
    'hubblestack',
    'salt.auth',
    'salt.beacons',
    'salt.cloud.clouds',
    'salt.engines',
    'salt.executors',
    'salt.grains',
    'salt.log.handlers',
    'salt.modules',
    'salt.netapi',
    'salt.output',
    'salt.output',
    'salt.pillars',
    'salt.proxy',
    'salt.queues',
    'salt.renderers',
    'salt.returners',
    'salt.roster',
    'salt.runners',
    'salt.sdb',
    'salt.search',
    'salt.serializers',
    'salt.spm.pkgdb',
    'salt.spm.pkgfiles',
    'salt.states',
    'salt.thorium',
    'salt.tops',
    'salt.utils',
    'salt.wheels',
]
LOADER_MODULES_SOURCES = []
for sloader in SALT_LOADERS:
    for mod in HIDDEN_IMPORTS[:]:
        if mod == sloader:
            continue
        if mod.startswith(mod):
            LOADER_MODULES_SOURCES.append(mod.replace('.', os.sep))

# Let's remove any python source files included that are in HIDDEN_IMPORTS but not on DATAS
for entry in DATAS[:]:
    path, mod = entry
    if not path.endswith(('.py', '.pyc')):
        # We are only after python files
        continue
    no_ext_path = os.path.splitext(path)[0]
    if not no_ext_path.endswith(tuple(LOADER_MODULES_SOURCES)):
        if entry in DATAS:
            DATAS.remove(entry)

# Some packages salt required, which we should include that are not discovered by PyInstaller
PACKAGES = []

for pkg in PACKAGES:
    DATAS.extend(collect_data_files(pkg, include_py_files=True))
    BINARIES.extend(collect_dynamic_libs(pkg))
    HIDDEN_IMPORTS.extend(collect_submodules(pkg))

DATAS.extend(collect_data_files('hubblestack', subdir=".", include_py_files=True))
# Finally, define the globals that PyInstaller expects
hiddenimports = HIDDEN_IMPORTS
datas = DATAS
binaries = BINARIES

def _patch_salt_grains_core_server_id():
    import salt.config # must import before salt.grains.core
    import salt.grains.core
    import sys
    import patch

    pset = patch.fromfile('pkg/salt.grains.core.patch')
    pset.items[0].target=salt.grains.core.__file__.encode()
    pset.apply()
    sys.stderr.write('patching complete\n')

_patch_salt_grains_core_server_id()