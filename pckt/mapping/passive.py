#!/usr/bin/env python3
'''
Passively map hosts on the local network from ARP and DHCP traffic.

    sudo python3 -m pckt.mapping.passive eth0
    python3 -m pckt.mapping.passive --file capture.pcap

Plain IP traffic isn't used: routed packets carry the router's MAC with the
remote host's address.
'''

import argparse
import socket
import struct

from pckt import pcap, vendor, Ethernet, ARP, DHCP

UNSPECIFIED = '0.0.0.0'


class PassiveMapper:
    def __init__(self):
        # 'aa:bb:cc:dd:ee:ff' => {'mac', 'vendor', 'ip', 'name', 'os'}
        self.hosts = {}

    def process(self, data):
        '''update hosts from one ethernet frame; returns the host if it changed, else None'''
        try:
            pkt = Ethernet.decode(data)
        except struct.error:
            return None

        if ARP in pkt:
            (addr, fields) = self.from_arp(pkt[ARP])
        elif DHCP in pkt:
            (addr, fields) = self.from_dhcp(pkt[DHCP])
        else:
            return None

        if addr is None or not fields:
            return None

        key = ':'.join('%.2x' % o for o in addr)
        host = self.hosts.setdefault(key, {'mac': key, 'vendor': vendor(addr)})
        if all(host.get(name) == value for (name, value) in fields.items()):
            return None
        host.update(fields)
        return host

    def from_arp(self, arp):
        # probes use 0.0.0.0 while checking an address is free
        if UNSPECIFIED == arp.src_ip:
            return (None, None)
        return (arp.src_mac, {'ip': arp.src_ip})

    def from_dhcp(self, msg):
        if DHCP.BOOTREQUEST != msg.type:
            return (None, None)

        fields = {}

        requested = msg.option(DHCP.REQUESTED_IP)
        if requested and 4 == len(requested):
            fields['ip'] = socket.inet_ntoa(requested)
        elif UNSPECIFIED != msg.clientip:
            fields['ip'] = msg.clientip

        name = msg.option(DHCP.HOSTNAME)
        if name:
            fields['name'] = name.decode('ascii', 'replace')

        # TODO: stop assuming all microsoft dhcp clients send MSFT in option 60
        if (msg.option(DHCP.VENDOR_CLASS) or b'').startswith(b'MSFT'):
            fields['os'] = 'windows'

        return (msg.clientmac, fields)


def describe(host):
    return '%s  %-15s %-20s %-8s %s' % (
        host['mac'],
        host.get('ip', ''),
        host.get('name', ''),
        host.get('os', ''),
        host.get('vendor') or '',
        )


def main():
    parser = argparse.ArgumentParser(description='Passively map hosts from ARP and DHCP traffic.')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('device', nargs='?', help='capture device')
    source.add_argument('--file', help='read a pcap file instead')
    args = parser.parse_args()

    if args.file:
        pd = pcap.open_offline(args.file)
    else:
        # a short timeout so next() returns regularly and Ctrl-C works
        pd = pcap.open_live(args.device, 65535, True, 100)
    pd.setfilter('arp or (udp and (port 67 or port 68))')

    mapper = PassiveMapper()
    try:
        while True:
            result = pd.next()
            if result is None:
                if args.file:
                    break
                continue
            host = mapper.process(result[0])
            if host:
                print(describe(host))
    except KeyboardInterrupt:
        pass
    finally:
        pd.close()


if '__main__' == __name__:
    main()
