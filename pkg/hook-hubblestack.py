
from PyInstaller.utils.hooks import collect_submodules

HIDDEN_IMPORTS = [
    # random missing things after py3 upgrade
    'encodings',

    'ssl',
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

    # fdg readfile.json tries to absolute import a module during lazy load. Too
    # late for the packer to notice it should be packed in the binary.
    # marking it here for "hidden import"
    'hubblestack.utils.encoding',

    # signign uses pycryptodome and pyopenssl and various other things
    # make sure pyinstaller see this
    'hubblestack.utils.signing',
]
DATAS = []
binaries = []

def _yield_all(HI):
    for i in HI:
        yield from collect_submodules(i)

hiddenimports = list(_yield_all(HIDDEN_IMPORTS))
# datas = DATAS
# binaries = BINARIES
