from setuptools import setup, find_packages
import platform

distro, version, _ = platform.dist()

# Default to cent7
data_files = [('/usr/lib/systemd/system', ['pkg/hubble.service']),]

if distro == 'redhat' or distro == 'centos':
    if version.startswith('6'):
        data_files = [('/etc/init.d', ['pkg/hubble']),]
    elif version.startswith('7'):
        data_files = [('/usr/lib/systemd/system', ['pkg/hubble.service']),]

setup(
    name="hubblestack",
    version="2.0",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'hubble = hubble.daemon:run',
        ],
    },
    install_requires=[
        'salt >= 2016.3.4',
    ],
    data_files=data_files,
    options={
#        'build_scripts': {
#            'executable': '/usr/bin/env python',
#        },
        'bdist_rpm': {
            'requires': 'salt',
        },
    },

)
