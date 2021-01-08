from PyInstaller.utils.hooks import collect_submodules, collect_data_files

HIDDEN_IMPORTS = [
    'yaml',
    'ssl',
    'objgraph',
    'OpenSSL',
    'argparse',
    'base64',
    'json',
    'logging',
    'requests',
    'functools',
    'argparse',
    'logging',
    'time',
    'os',
    'random',
    'signal',
    'sys',
    'git',
    'daemon',
    'boto3',
    'botocore',
    'imp',
    'inspect',
    'yaml',
    'traceback',
    'pygit2',
    'Queue',
    'azure.storage.common',
    'azure.storage.blob',
    'croniter',
    'vulners',
    'sqlite3',

    'hubblestack',
    'hubblestack.daemon',
    'hubblestack.loader',
]

LOADERS = [
    'hubblestack',
    'hubblestack.audit',
    'hubblestack.comparators',
    'hubblestack.fdg',
    'hubblestack.files',
    'hubblestack.fileserver',
    'hubblestack.grains',
    'hubblestack.matchers',
    'hubblestack.modules',
    'hubblestack.platform',
    'hubblestack.returners',
    'hubblestack.serializers',
    'hubblestack.utils',
]


try:
    import hubblestack.pre_packaged_certificates
    HIDDEN_IMPORTS.append('hubblestack.pre_packaged_certificates')
except ImportError:
    pass

datas = list()
binaries = list()
hiddenimports = list(HIDDEN_IMPORTS)

for l in LOADERS:
    datas.extend(collect_data_files(l, subdir='.', include_py_files=True))

datas = list((path,mod) for path,mod in datas if path.endswith(('.py', '.pyc')))

for i in HIDDEN_IMPORTS:
    hiddenimports.extend( collect_submodules(i) )
