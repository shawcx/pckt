#!/usr/bin/env python3

import sys
import platform

import setuptools

if 'Windows' == platform.system():
    defines = [('WIN32',None),('WPCAP',None)]
    include_dirs = ['npcap-sdk-1.13/Include']
    library_dirs = ['npcap-sdk-1.13/Lib/x64']
    libs = ['wpcap', 'ws2_32', 'advapi32']
elif 'Darwin' == platform.system():
    defines = [('MACOS',None)]
    include_dirs = []
    library_dirs = []
    libs = ['pcap']
else:
    defines = []
    include_dirs = []
    library_dirs = []
    libs = ['pcap']

setuptools.setup(
    name             = 'pckt',
    version          = '0.1',
    description      = 'PCAP bindings and packet (de)construction',
    long_description = open('README.rst').read(),
    license          = 'Proprietary',
    packages         = setuptools.find_packages(),
#    packages         = ['pckt'],
#    package_dir      = {'pckt': 'pckt'},
#    package_data     = {'pckt': ['manuf']},
    ext_modules = [
        setuptools.Extension(
            'pckt.pcap',
            ['src/pypcap.c'],
            define_macros = defines,
            include_dirs = include_dirs,
            library_dirs = library_dirs,
            libraries = libs
            )
        ],
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: Proprietary',
        'Programming Language :: Python :: 3',
        ],
    )
