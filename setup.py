from setuptools import setup, find_packages
import re
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
    'objgraph',
    'pycryptodome',
    'cryptography',
    'pyopenssl>=16.2.0',
    'requests>=2.13.0',
    'daemon',
    'pygit2<0.27.0',
    'salt-ssh==2019.2.3',
    'gitpython',
    'pyinotify',
    'cffi',
    'croniter',
    'vulners',
    'ntplib',
    'patch==1.*',
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

with open('hubblestack/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name='hubblestack',
    version=version,
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
    options={
#        'build_scripts': {
#            'executable': '/usr/bin/env python',
#        },
        'bdist_rpm': {
            'requires': 'salt python-argparse python-inotify python-pygit2 python-setuptools',
        },
    },
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
