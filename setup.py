from setuptools import setup, find_packages
import platform

distro, version, _ = platform.dist()
if not distro:
    distro, version, _ = platform.linux_distribution(supported_dists=['system'])

# Default to cent7
data_files = [('/usr/lib/systemd/system', ['pkg/hubble.service']),
              ('/etc/hubble', ['conf/hubble']),]

if distro == 'redhat' or distro == 'centos':
    if version.startswith('6'):
        data_files = [('/etc/init.d', ['pkg/hubble']),
                      ('/etc/hubble', ['conf/hubble']),]
    elif version.startswith('7'):
        data_files = [('/usr/lib/systemd/system', ['pkg/hubble.service']),
                      ('/etc/hubble', ['conf/hubble']),]
elif distro == 'Amazon Linux AMI':
    data_files = [('/etc/init.d', ['pkg/hubble']),
                  ('/etc/hubble', ['conf/hubble']),]


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
        'install': {
            'prefix': '/usr',
        },
    },

)
