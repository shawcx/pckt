#!/usr/bin/env python3
'''
Print decoded packets.

    python3 scripts/sniff.py                          # list devices
    sudo python3 scripts/sniff.py eth0 [bpf filter]
'''

import sys

from pckt import pcap, Ethernet
from pckt.capture import packets


def main():
    devices = pcap.findalldevs()

    if 1 == len(sys.argv):
        for (name, info) in sorted(devices.items()):
            if 'ip' in info:
                print(name, info)
        return

    pd = pcap.open_live(sys.argv[1], 65535, True, 100)
    if 2 < len(sys.argv):
        pd.setfilter(' '.join(sys.argv[2:]))

    count = 0
    try:
        for result in packets(pd):
            if result is None:
                continue
            (data, ts, wirelen) = result
            count += 1
            print('%.6f %5d %r' % (ts, wirelen, Ethernet.decode(data)))
    except KeyboardInterrupt:
        pass
    finally:
        pd.close()

    print()
    print('Captured', count, 'packet%s' % ('s' if count != 1 else ''))


if '__main__' == __name__:
    main()
