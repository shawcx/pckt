#!/usr/bin/env python3

# metadata is in pyproject.toml; the extension's build settings depend on the platform,
# and the license's keyword on the setuptools version

import os
import platform
import sysconfig

import setuptools
from setuptools import setup, Extension

if int(setuptools.__version__.split('.')[0]) >= 77:
    license = {'license_expression': 'MIT'}
else:
    license = {'license': 'MIT'}

if 'Windows' == platform.system():
    defines = [('WIN32',None),('WPCAP',None)]
    include_dirs = []
    library_dirs = []
    libs = ['wpcap', 'ws2_32', 'advapi32']
    # NPCAP_SDK points at an unpacked Npcap SDK (https://npcap.com/#download)
    sdk = os.environ.get('NPCAP_SDK')
    if sdk:
        arch = {'win-amd64': 'x64', 'win-arm64': 'ARM64'}.get(sysconfig.get_platform(), '')
        include_dirs = [os.path.join(sdk, 'Include')]
        library_dirs = [os.path.join(sdk, 'Lib', arch)]
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
            # win32.c is #included, so edits to it need a rebuild too
            depends = ['src/pcapmodule.h', 'src/win32.c'],
            define_macros = defines,
            include_dirs = include_dirs,
            library_dirs = library_dirs,
            libraries = libs
            ),
        ]
    )
