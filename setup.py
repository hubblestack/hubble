from setuptools import setup, find_packages
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
    data_files=[('/etc/init.d', ['pkg/hubble']),],
    options={
#        'build_scripts': {
#            'executable': '/usr/bin/env python',
#        },
        'bdist_rpm': {
            'requires': 'salt',
        },
    },

)
