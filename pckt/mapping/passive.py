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

from pckt.capture import packets
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

        system = dhcp_os(msg)
        if system:
            fields['os'] = system

        return (msg.clientmac, fields)


# clients that name themselves in the vendor class (option 60)
VENDOR_CLASSES = (
    (b'MSFT', 'windows'),
    (b'android-dhcp-', 'android'),
    (b'udhcp ', 'linux'),  # busybox
    )


def dhcp_os(msg):
    '''guess a DHCP client's OS from its vendor class, else its parameter request list; None if unknown'''
    vendor_class = msg.option(DHCP.VENDOR_CLASS) or b''
    for (prefix, system) in VENDOR_CLASSES:
        if vendor_class.startswith(prefix):
            return system
    # dhcpcd-<version>:<uname -s>-<uname -r>:<uname -m>
    if vendor_class.startswith(b'dhcpcd-') and b':' in vendor_class:
        return vendor_class.split(b':')[1].partition(b'-')[0].decode('ascii', 'replace').lower() or None

    params = list(msg.option(DHCP.PARAMETER_LIST) or b'')
    # Apple's client, with classless routes (121) second in newer versions; only macOS asks for LDAP (95)
    if params[:5] in ([1, 121, 3, 6, 15], [1, 3, 6, 15, 119]) and {119, 252} <= set(params):
        return 'macos' if 95 in params else 'ios'
    # most Windows versions since 2000 ask for all of these, whether or not they send MSFT
    if {31, 33, 43, 44, 46, 47} <= set(params):
        return 'windows'
    return None


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
        pd = pcap.open_live(args.device, 65535, True, 100)
    pd.setfilter('arp or (udp and (port 67 or port 68))')

    mapper = PassiveMapper()
    try:
        for result in packets(pd):
            if result is None:
                continue
            host = mapper.process(result[0])
            if host:
                print(describe(host), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        pd.close()


if '__main__' == __name__:
    main()
