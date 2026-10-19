#!/usr/bin/env python3
'''
Passively map hosts on the local network from ARP, DHCP, IPv6 neighbor
discovery and mDNS traffic.

    sudo python3 -m pckt.mapping.passive eth0
    python3 -m pckt.mapping.passive --file capture.pcap

Plain IP traffic isn't used: routed packets carry the router's MAC with the
remote host's address. Neighbor discovery and mDNS stay on the local link.
'''

import argparse
import socket
import struct

from pckt.capture import packets
from pckt import pcap, vendor, Ethernet, ARP, IP, IPv6, ICMPv6, ICMPv6_NeighborAdvert, UDP, DHCP, DNS

UNSPECIFIED = '0.0.0.0'
UNSPECIFIED6 = '::'
MDNS_PORT = 5353

# router solicitation and advertisement, neighbor solicitation and advertisement
NEIGHBOR_DISCOVERY = range(133, 137)


class PassiveMapper:
    def __init__(self):
        # 'aa:bb:cc:dd:ee:ff' => {'mac', 'vendor', 'ip', 'ipv6', 'name', 'os'}; ipv6 is a list
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
        elif ICMPv6 in pkt and IPv6 in pkt:
            (addr, fields) = self.from_ndp(pkt[Ethernet].src, pkt[IPv6], pkt[ICMPv6])
        elif DNS in pkt and MDNS_PORT == pkt[UDP].src:
            (addr, fields) = self.from_mdns(pkt[Ethernet].src, pkt, pkt[DNS])
        else:
            return None

        if addr is None or not fields:
            return None

        key = ':'.join('%.2x' % o for o in addr)
        host = self.hosts.setdefault(key, {'mac': key, 'vendor': vendor(addr)})
        changed = False
        for (name, value) in fields.items():
            if 'ipv6' == name:
                # hosts have several, so they're added to the list
                new = [a for a in value if a not in host.get('ipv6', [])]
                if new:
                    host.setdefault('ipv6', []).extend(new)
                    changed = True
            elif host.get(name) != value:
                host[name] = value
                changed = True
        return host if changed else None

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

    def from_ndp(self, src, ip6, msg):
        if msg.type not in NEIGHBOR_DISCOVERY:
            return (None, None)
        addrs = []
        # duplicate address detection probes use :: while checking an address is free
        if UNSPECIFIED6 != ip6.src:
            addrs.append(ip6.src)
        # an advertisement's target is the sender's own address
        if isinstance(msg, ICMPv6_NeighborAdvert) and msg.target not in addrs:
            addrs.append(msg.target)
        return (src, {'ipv6': addrs} if addrs else None)

    def from_mdns(self, src, pkt, msg):
        '''a response's address records name the sender when one is for the address it was sent from'''
        if not msg.qr:
            return (None, None)
        sender = pkt[IP].src if IP in pkt else pkt[IPv6].src

        # 'name.local' (lowercased; names are case-insensitive) => (name as sent, [(type, address)])
        records = {}
        for rr in msg.answers + msg.additional:
            if rr.type in (DNS.A, DNS.AAAA) and isinstance(rr.data, str) and rr.name.lower().endswith('.local'):
                records.setdefault(rr.name.lower(), (rr.name, []))[1].append((rr.type, rr.data))

        # others' records (e.g. from a sleep proxy) don't include the sender's address
        for (name, addrs) in records.values():
            if sender in (data for (kind, data) in addrs):
                break
        else:
            return (None, None)

        # labels are decoded as latin-1, but mDNS names are UTF-8
        fields = {'name': name[:-len('.local')].encode('latin-1').decode('utf-8', 'replace')}
        ipv4 = [data for (kind, data) in addrs if DNS.A == kind]
        ipv6 = [data for (kind, data) in addrs if DNS.AAAA == kind]
        if ipv4:
            fields['ip'] = sender if sender in ipv4 else ipv4[0]
        if ipv6:
            fields['ipv6'] = ipv6
        return (src, fields)


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
    return ('%s  %-15s %-20s %-8s %-12s %s' % (
        host['mac'],
        host.get('ip', ''),
        host.get('name', ''),
        host.get('os', ''),
        host.get('vendor') or '',
        ' '.join(host.get('ipv6', [])),
        )).rstrip()


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
    pd.setfilter('arp or icmp6 or (udp and (port 67 or port 68 or port %d))' % MDNS_PORT)

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
