#!/usr/bin/env python3

# metadata is in pyproject.toml; the extension's build settings depend on the platform

import platform

from setuptools import setup, Extension

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
