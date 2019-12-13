from setuptools import setup, find_packages
import platform
import re

distro, version, _ = platform.dist()
if not distro:
    distro, version, _ = platform.linux_distribution(supported_dists=['system'])

# Default to cent7
data_files = [('/usr/lib/systemd/system', ['pkg/source/hubble.service']),
              ('/etc/hubble', ['conf/hubble']), ]

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
    tests_require=[
        'mock',
    ],
    install_requires=[
        'salt-ssh >= 2019.2.0',
        'croniter',
        'pyinotify',
        'vulners == 1.3.0',
        'azure',
        'ntplib',
    ],
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
