from PyInstaller.utils.hooks import collect_submodules

HIDDEN_IMPORTS = [
    'ssl',
    'objgraph',
    'Cryptodome',
    'OpenSSL',
    'argparse',
    'base64',
    'HTMLParser',
    'json',
    'logging',
    'requests',
    'functools',
    'BaseHTTPServer',
    'argparse',
    'logging',
    'time',
    'pprint',
    'os',
    'random',
    'signal',
    'sys',
    'git',
    'daemon',
    'boto3',
    'botocore',
    'imp',
    'six',
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

    # fdg readfile.json tries to absolute import a module during lazy load. Too
    # late for the packer to notice it should be packed in the binary.
    # marking it here for "hidden import"
    'hubblestack.utils.encoding',

    # signign uses pycryptodome and pyopenssl and various other things
    # make sure pyinstaller see this
    'hubblestack.utils.signing',
]

try:
    import hubblestack.pre_packaged_certificates
    HIDDEN_IMPORTS.append('hubblestack.pre_packaged_certificates')
except ImportError:
    pass

def _yield_all(HI):
    for i in HI:
        yield from collect_submodules(i)

hiddenimports = list(_yield_all(HIDDEN_IMPORTS))
