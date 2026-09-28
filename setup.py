#!/usr/bin/env python3

import platform

from setuptools import setup, find_namespace_packages, Extension

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
    python_requires = '>=3.6',
    packages = find_namespace_packages(include=['pckt', 'pckt.*']),
    package_data = {'pckt': ['manuf']},
    scripts = [
        'pckt/tools/pckt-eth',
        'pckt/tools/pckt-arp',
        'pckt/tools/pckt-ip',
        'pckt/tools/pckt-ip6',
        'pckt/tools/pckt-tcp',
        'pckt/tools/pckt-udp',
        'pckt/tools/update-pckt-manuf',
        ],
    ext_modules = [
        Extension(
            'pckt.pcap',
            ['src/pcapmodule.c'],
            define_macros = defines,
            include_dirs = include_dirs,
            library_dirs = library_dirs,
            libraries = libs
            ),
        ]
    )
