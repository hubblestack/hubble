# coding: utf-8

import os
import sys
import copy
import logging
import pytest
import collections
import hubblestack.config
import pstats
import subprocess
import yaml
import hubblestack.loader
import hubblestack.daemon
import hubblestack.syspaths

log = logging.getLogger(__name__)
Loaders = collections.namedtuple("Loaders", 'opts mods grains utils'.split())

tests_dir = os.path.dirname(os.path.realpath(__file__))
sources_dir = os.path.dirname(os.path.dirname(tests_dir))
hubble_dir = os.path.join(sources_dir, 'hubblestack')
output_dir = os.path.join(tests_dir, 'output')
ext_dir = os.path.join(hubble_dir, 'extmods')

if sources_dir not in sys.path:
    sys.path.insert(0, sources_dir)

# docker as root, developer homedir as 1000
# set HS_CHOWN_BACK=1000:1000 to chown -R $HS_CHOWN_BACK sources_dir
please_chown_my_files_back_to_me = 'HS_CHOWN_BACK'

# if true (in the string sense), attempt to profile hubble during testing
profile_enabling_env_var = 'HS_PROFILE'

@pytest.fixture(scope='session')
def osqueryd():
    tests_dir = os.path.dirname(os.path.realpath(__file__))
    sources_dir = os.path.dirname(os.path.dirname(tests_dir))
    config = os.path.join(sources_dir, 'conf', 'osqueryd.conf')
    cmd = ['osqueryd', '--disable-logging', '--config_path', config]
    with open(os.devnull, 'w') as fh:
        p = subprocess.Popen(cmd, stdout=fh, stderr=fh)
        yield p

def quiet_salt():
    class QuietSalt(logging.Filter):
        def filter(self, record):
            if record.name.startswith('salt.'):
                if 'Executing command' in record.msg:
                    record.levelno = logging.DEBUG
                    record.levelname = 'DEBUG'
                elif 'nebula' in record.msg:
                    pass
                else:
                    return 0
            return True

    qs = QuietSalt()
    for handler in logging.root.handlers:
        handler.addFilter(qs)

def update_config(config_file):
    with open(config_file) as ifh:
        dat = yaml.load(ifh, Loader=yaml.SafeLoader)

    dat['log_file'] = os.path.join(output_dir, 'hubble.log')
    dat['cachedir'] = os.path.join(output_dir, '.cache')
    dat['pidfile']  = os.path.join(output_dir, '.pidfile')

    with open(config_file, 'w') as ofh:
        yaml.dump(dat, ofh)


@pytest.fixture(scope='session')
def config_file():
    return os.path.join(tests_dir, 'hubble.config')

@pytest.fixture(scope='session')
def HSL(config_file):
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    quiet_salt()
    update_config(config_file)
    hubblestack.daemon.load_config(['-c', config_file])
    hsl = Loaders(hubblestack.daemon.__opts__, hubblestack.daemon.__mods__,
        hubblestack.daemon.__grains__, hubblestack.daemon.__utils__)
    yield hsl

@pytest.fixture(scope='function')
def __mods__(HSL):
    return HSL.mods

@pytest.fixture(scope='function')
def __salt__(__mods__): # XXX remove eventually
    return __mods__

@pytest.fixture(scope='function')
def __utils__(HSL):
    return HSL.utils

@pytest.fixture(scope='function')
def __grains__(HSL):
    return copy.deepcopy(HSL.grains)

@pytest.fixture(scope='function')
def __opts__(HSL):
    return copy.deepcopy(HSL.opts)

##### profiling
prof_filenames = set()

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    if os.environ.get(profile_enabling_env_var):
        import cProfile
        filename, lineno, funcname = item.location # item.name is just the function name
        profile_name = filename.split('/')[-1][:-3]
        profile_name += '-' + funcname + '.pstats'
        prof_filename = os.path.join(output_dir, profile_name)
        prof_filenames.add(prof_filename)
        try:
            os.makedirs(output_dir)
        except OSError:
            pass
        prof = cProfile.Profile()
        prof.enable()

    yield

    if os.environ.get(profile_enabling_env_var):
        prof.dump_stats(prof_filename)
        prof_filenames.add(prof_filename)

def pytest_sessionfinish(session, exitstatus):
    if os.environ.get(profile_enabling_env_var):
        # shamelessly ripped from pytest-profiling — then modified to taste
        if prof_filenames:
            combined = None
            for pfname in prof_filenames:
                if not os.path.isfile(pfname):
                    continue
                if combined is None:
                    combined = pstats.Stats(pfname)
                else:
                    combined.add(pfname)

            if combined:
                cfilename = os.path.join(output_dir, 'combined.pstats')
                csvg      = os.path.join(output_dir, 'combined.svg')
                combined.dump_stats(cfilename)

                gp_cmd = [ 'gprof2dot', '-f', 'pstats', cfilename ]

                gp = subprocess.Popen(gp_cmd, stdout=subprocess.PIPE)
                dp = subprocess.Popen(['dot', '-Tsvg', '-o', csvg], stdin=gp.stdout)
                dp.communicate()

    pcmf = os.environ.get(please_chown_my_files_back_to_me)
    if pcmf:
        p = subprocess.Popen(['chown', '-R', pcmf, sources_dir])
        p.communicate()
        print('\nchowned back files to {}'.format(pcmf))
