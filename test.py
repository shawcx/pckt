#!/usr/bin/env python3

import sys
sys.path.insert(0, './build/lib.linux-x86_64-3.8')


import pckt
import pckt.pcap

if 1 == len(sys.argv):
    interfaces = pckt.pcap.find()
    for interface,settings in interfaces.items():
        if 'ip' not in settings:
            continue
        print(interface, settings)
    sys.exit(0)

if sys.argv[1].startswith('@'):
    pd = pckt.pcap.open_file(sys.argv[1][1:])
else:
    pd = pckt.pcap.open_live(sys.argv[1])

print(pd)

print(pd.fileno())
pd.close()
try:
    pd.fileno()
except pckt.pcap.error as e:
    print(e)
