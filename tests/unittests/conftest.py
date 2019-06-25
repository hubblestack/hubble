
import os
import sys
import subprocess
import logging
import pytest
import collections
import salt.config
import salt.loader

log = logging.getLogger(__name__)
SaltLoaders = collections.namedtuple("SaltLoaders", 'opts salt grains utils'.split())

tests_dir = os.path.dirname(os.path.realpath(__file__))
sources_dir = os.path.dirname(os.path.dirname(tests_dir))
hubble_dir = os.path.join(sources_dir, 'hubblestack')
ext_dir = os.path.join(hubble_dir, 'extmods')

if sources_dir not in sys.path:
    sys.path.insert(0, sources_dir)

import hubblestack.daemon

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

@pytest.fixture(scope='session')
def salt_loaders():
    quiet_salt()

    sys.argv = ['hubble']
    log.debug('loading __opts__')

    config_file = os.path.join(tests_dir, 'hubble.config')
    __opts__ = salt.config.minion_config(config_file)
    __opts__['conf_file'] = config_file

    frb = __opts__['file_roots'].get('base', [])
    __opts__['file_roots']['base'] = [ os.path.realpath(x) for x in frb ]

    for i in 'module/modules grains returners fileserver utils fdg'.split():
        n = i
        if '/' in i:
            i,n = i.split('/')
        i = i + '_dirs'
        dirs = __opts__.get(i, list())
        dirs.append( os.path.join(ext_dir, n) )
        __opts__[i] = dirs

    disable_modules = __opts__.get('disable_modules', [])
    disable_modules.extend([
        'boto3_elasticache',
        'boto3_route53',
        'boto3_sns',
        'boto_apigateway',
        'boto_asg',
        'boto_cfn',
        'boto_cloudfront',
        'boto_cloudtrail',
        'boto_cloudwatch_event',
        'boto_cloudwatch',
        'boto_cognitoidentity',
        'boto_datapipeline',
        'boto_dynamodb',
        'boto_ec2',
        'boto_efs',
        'boto_elasticache',
        'boto_elasticsearch_domain',
        'boto_elb',
        'boto_elbv2',
        'boto_iam',
        'boto_iot',
        'boto_kinesis',
        'boto_kms',
        'boto_lambda',
        'boto_rds',
        'boto_route53',
        'boto_s3_bucket',
        'boto_s3',
        'boto_secgroup',
        'boto_sns',
        'boto_sqs',
        'boto_ssm',
        'boto_vpc',
    ])
    __opts__['disable_modules'] = disable_modules
    __opts__['cachedir'] = os.path.join(tests_dir, 'cache')
    __opts__['pidfile'] = os.path.join(tests_dir, 'hubble.pid')
    __opts__['log_file'] = os.path.join(tests_dir, 'hubble.log')
    __opts__['osquery_dbpath'] = os.path.join(__opts__['cachedir'], 'osquery')
    __opts__['osquerylogpath'] = os.path.join(tests_dir, 'hubble_osquery.log')
    __opts__['osquerylog_backupdir'] = os.path.join(tests_dir, 'hubble-osquery-bak')
    __opts__['log_level'] = 'error'
    __opts__['file_client'] = 'local'
    __opts__['fileserver_update_frequency'] = 40000 # 40ksec
    __opts__['grains_refresh_frequency'] = 4000 # 4ksec
    __opts__['scheduler_sleep_frequency'] = 0.5
    __opts__['logfile_maxbytes'] = 1*1024**2
    __opts__['logfile_backups'] = 1
    __opts__['delete_inaccessible_azure_containers'] = False
    __opts__['enable_globbing_in_nebula_masking'] = False
    __opts__['osquery_logfile_maxbytes'] = 5*1024**2
    __opts__['osquery_logfile_maxbytes_toparse'] = 10*1024**2
    __opts__['osquery_backuplogs_count'] = 2

    log.debug('loading __grains__')
    __opts__['grains'] = __grains__ = salt.loader.grains(__opts__)
    log.debug('loading __utils__')
    __utils__ = salt.loader.utils(__opts__)
    log.debug('loading __salt__ (aka minion mods)')
    __salt__ = salt.loader.minion_mods(__opts__, utils=__utils__)

    salt_loaders = SaltLoaders(__opts__, __salt__, __grains__, __utils__)

    log.debug('populating hubblestack.utils.stdrec with __grains__ and __opts__')
    hubblestack.utils.stdrec.__grains__ = salt_loaders.grains
    hubblestack.utils.stdrec.__opts__ = salt_loaders.opts

    log.debug('populating hubblestack.hec with __grains__, __salt__, and __opts__')
    hubblestack.hec.opt.__grains__ = salt_loaders.grains
    hubblestack.hec.opt.__salt__ = salt_loaders.salt
    hubblestack.hec.opt.__opts__ = salt_loaders.opts

    log.debug('populating hubblestack.splunklogging with __grains__, __salt__, and __opts__')
    hubblestack.splunklogging.__grains__ = salt_loaders.grains
    hubblestack.splunklogging.__salt__ = salt_loaders.salt
    hubblestack.splunklogging.__opts__ = salt_loaders.opts

    log.debug('populating hubblestack.status with __salt__ and __opts__')
    hubblestack.status.__opts__ = salt_loaders.opts
    hubblestack.status.__salt__ = salt_loaders.salt

    yield salt_loaders

@pytest.fixture(scope='session')
def __salt__(salt_loaders):
    return salt_loaders.salt

@pytest.fixture(scope='session')
def __grains__(salt_loaders):
    return salt_loaders.grains