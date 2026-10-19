#!/usr/bin/env python3

# metadata is in pyproject.toml; the extension's build settings depend on the platform,
# and the license's keyword on the setuptools version

import platform

import setuptools
from setuptools import setup, Extension

if int(setuptools.__version__.split('.')[0]) >= 77:
    license = {'license_expression': 'MIT'}
else:
    license = {'license': 'MIT'}

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
    **license,
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
