#!/usr/bin/python

import sys
import platform

from distutils.core import setup
from distutils.extension import Extension

if 'Windows' == platform.system():
    defines = [('WIN32',None),('WPCAP',None)]
    include_dirs = ['winpcap/include']
    library_dirs = ['winpcap/lib']
    libs = ['wpcap', 'ws2_32', 'advapi32']
else:
    defines = []
    include_dirs = []
    library_dirs = []
    libs = ['pcap']

setup(
    name = 'pckt',
    version = '0.1',
    description = 'PCAP bindings and packet (de)construction',
    long_description = open('README.rst').read(),
    license = 'TBD',
    packages = ['pckt'],
    package_dir = {'pckt': 'pckt'},
    package_data = {'pckt': ['manuf']},
    scripts = [
        'bin/pketh',
        'bin/pkarp',
        'bin/pkip',
        'bin/pkip6',
        'bin/pktcp',
        'bin/pkudp',
        'bin/update-pck-manuf',
        ],
    ext_modules = [
        Extension(
            'pckt.pcap',
            ['src/pckt.c'],
            define_macros = defines,
            include_dirs = include_dirs,
            library_dirs = library_dirs,
            libraries = libs
            )
        ]
    )
