from setuptools import setup, find_packages
import platform

try:
    import distro
    distro, version, _ = distro.linux_distribution(full_distribution_name=False)
except ImportError:
    distro = version = ''

platform_name=platform.system()

# Default to CentOS7
data_files = [('/usr/lib/systemd/system', ['pkg/source/hubble.service']),
              ('/etc/hubble', ['conf/hubble']), ]

build_dependencies = [
    'distro',
    'msgpack',
    'pyyaml',
    'objgraph',
    'pycryptodome',
    'cryptography',
    'pyopenssl',
    'requests>=2.13.0',
    'daemon',
    'pygit2',
    'gitpython',
    'pyinotify',
    'cffi',
    'croniter',
    'vulners',
    'ntplib',
    'patch==1.*',
    'packaging',
    'pyparsing'
]

if distro == 'redhat' or distro == 'centos':
    if version.startswith('6'):
        data_files = [('/etc/init.d', ['pkg/hubble']),
                      ('/etc/hubble', ['conf/hubble']), ]
    elif version.startswith('7'):
        data_files = [('/usr/lib/systemd/system', ['pkg/source/hubble.service']),
                      ('/etc/hubble', ['conf/hubble']), ]
elif distro == 'Amazon Linux AMI':
    data_files = [('/etc/init.d', ['pkg/hubble']),
                  ('/etc/hubble', ['conf/hubble']), ]

if platform_name == 'Windows':
    build_dependencies.remove('pyinotify')

def _hubble_version():
    try:
        from hubblestack.version import __version__
        return __version__
    except:
        pass
    return 'unknown'

setup(
    name='hubblestack',
    version=_hubble_version(),
    description='Modular, open-source security compliance framework',
    author='Colton Myers',
    author_email='colton.myers@gmail.com',
    maintainer='Colton Myers',
    maintainer_email='colton.myers@gmail.com',
    url='https://hubblestack.io',
    license='Apache 2.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'hubble = hubblestack.daemon:run',
        ],
    },
    install_requires=build_dependencies,
    data_files=data_files,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: System',
        'Topic :: System :: Logging',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Systems Administration',
    ],
)
