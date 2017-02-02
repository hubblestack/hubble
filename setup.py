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
    version="2.0.1",
    description="Modular, open-source security compliance framework",
    author="Colton Myers",
    author_email="colton.myers@gmail.com",
    maintainer="Colton Myers",
    maintainer_email="colton.myers@gmail.com",
    url="https://hubblestack.io",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'hubble = hubblestack.daemon:run',
        ],
    },
    install_requires=[
        'salt >= 2015.5.0',
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
          'Topic :: Security',
          'Topic :: System',
          'Topic :: System :: Logging',
          'Topic :: System :: Monitoring',
          'Topic :: System :: Systems Administration',
          ],
)
