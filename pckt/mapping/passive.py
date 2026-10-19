#!/usr/bin/env python3
'''
Passively map hosts on the local network from ARP, DHCP, DHCPv6, IPv6
neighbor discovery, mDNS, LLMNR, NetBIOS name service and LLDP traffic.

    sudo python3 -m pckt.mapping.passive eth0
    python3 -m pckt.mapping.passive --file capture.pcap

Plain IP traffic isn't used: routed packets carry the router's MAC with the
remote host's address. The others stay on the local link, or are only used
when they're broadcast or multicast.
'''

import argparse
import socket
import struct

from pckt.capture import packets
from pckt import (
    pcap, vendor, Ethernet, ARP, IP, IPv6, ICMPv6, ICMPv6_NeighborAdvert, UDP, DHCP, DHCPv6, DNS, NBNS, LLDP,
    )

UNSPECIFIED = '0.0.0.0'
UNSPECIFIED6 = '::'
MDNS_PORT = 5353
LLMNR_PORT = 5355

# router solicitation and advertisement, neighbor solicitation and advertisement
NEIGHBOR_DISCOVERY = range(133, 137)


class PassiveMapper:
    def __init__(self):
        # 'aa:bb:cc:dd:ee:ff' => {'mac', 'vendor', 'ip', 'ipv6', 'name', 'os', 'description', 'capabilities'};
        # ipv6 and capabilities are lists
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
        elif DHCPv6 in pkt and IPv6 in pkt:
            (addr, fields) = self.from_dhcpv6(pkt[Ethernet], pkt[IPv6], pkt[DHCPv6])
        elif ICMPv6 in pkt and IPv6 in pkt:
            (addr, fields) = self.from_ndp(pkt[Ethernet].src, pkt[IPv6], pkt[ICMPv6])
        elif NBNS in pkt and IP in pkt:
            (addr, fields) = self.from_nbns(pkt[Ethernet], pkt[IP], pkt[NBNS])
        elif DNS in pkt and pkt[UDP].src in (MDNS_PORT, LLMNR_PORT):
            (addr, fields) = self.from_mdns(pkt[Ethernet].src, pkt, pkt[DNS])
        elif LLDP in pkt:
            (addr, fields) = self.from_lldp(pkt[Ethernet].src, pkt[LLDP])
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
            elif 'name' == name and value.lower() == host.get(name, '').lower():
                # the same name in another case, e.g. NetBIOS's upper case: keep the first
                pass
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

    def from_dhcpv6(self, eth, ip6, msg):
        # a server echoes the client's name back, and a message unicast to a server may have been routed
        if msg.type not in DHCPv6.CLIENT_TYPES or not multicast(eth.dst):
            return (None, None)

        fields = {'ipv6': [ip6.src]}

        name = msg.fqdn()
        if name:
            # the host name, as the other sources give it
            fields['name'] = name.partition('.')[0]

        for (enterprise, data) in msg.vendor_classes():
            for vendor_class in data:
                system = vendor_class_os(vendor_class)
                if system:
                    fields['os'] = system

        return (eth.src, fields)

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
        '''
        mDNS and LLMNR responses: their address records name the sender
        when one is for the address it was sent from
        '''
        if not msg.qr or msg.rcode:
            return (None, None)
        sender = pkt[IP].src if IP in pkt else pkt[IPv6].src
        # mDNS names are in .local; LLMNR's are usually just a host name
        suffix = '.local' if MDNS_PORT == pkt[UDP].src else ''

        # name (lowercased; names are case-insensitive) => (name as sent, [(type, address)])
        records = {}
        for rr in msg.answers + msg.additional:
            if rr.type in (DNS.A, DNS.AAAA) and isinstance(rr.data, str) and rr.name.lower().endswith(suffix):
                records.setdefault(rr.name.lower(), (rr.name, []))[1].append((rr.type, rr.data))

        # others' records (e.g. from a sleep proxy) don't include the sender's address
        for (name, addrs) in records.values():
            if sender in (data for (kind, data) in addrs):
                break
        else:
            return (None, None)

        # labels are decoded as latin-1, but mDNS and LLMNR names are UTF-8
        fields = {'name': name[:len(name) - len(suffix)].encode('latin-1').decode('utf-8', 'replace')}
        ipv4 = [data for (kind, data) in addrs if DNS.A == kind]
        ipv6 = [data for (kind, data) in addrs if DNS.AAAA == kind]
        if ipv4:
            fields['ip'] = sender if sender in ipv4 else ipv4[0]
        if ipv6:
            fields['ipv6'] = ipv6
        return (src, fields)

    def from_nbns(self, eth, ip, msg):
        '''
        hosts broadcast registrations of their names: a unique workstation or
        server name for the address it was sent from names the sender
        '''
        # only broadcasts: a registration unicast to a WINS server may have been routed
        if msg.rcode or not multicast(eth.dst):
            return (None, None)
        for rr in msg.answers + msg.additional:
            decoded = NBNS.decode_name(rr.name)
            if NBNS.NB != rr.type or not isinstance(rr.data, list) or decoded is None:
                continue
            (name, suffix, scope) = decoded
            if not name or suffix not in (NBNS.WORKSTATION, NBNS.SERVER):
                continue
            if any(ip.src == addr and not flags & NBNS.GROUP for (flags, addr) in rr.data):
                return (eth.src, {'name': name, 'ip': ip.src})
        return (None, None)

    def from_lldp(self, src, msg):
        # a MAC chassis ID identifies a switch across its ports, which each send from their own MAC
        chassis = msg.tlv(LLDP.CHASSIS_ID, b'')
        if 7 == len(chassis) and LLDP.CHASSIS_MAC == chassis[0]:
            src = chassis[1:]

        fields = {}
        for (kind, name) in ((LLDP.SYSTEM_NAME, 'name'), (LLDP.SYSTEM_DESCRIPTION, 'description')):
            value = msg.tlv(kind)
            if value:
                fields[name] = value.decode('utf-8', 'replace')
        capabilities = msg.capabilities()
        if capabilities:
            fields['capabilities'] = capabilities
        for addr in msg.management_addresses():
            if ':' in addr:
                fields.setdefault('ipv6', []).append(addr)
            else:
                fields.setdefault('ip', addr)
        return (src, fields)


# clients that name themselves in the vendor class (option 60)
VENDOR_CLASSES = (
    (b'MSFT', 'windows'),
    (b'android-dhcp-', 'android'),
    (b'udhcp ', 'linux'),  # busybox
    )


def vendor_class_os(vendor_class):
    '''the OS a DHCP or DHCPv6 vendor class names, else None'''
    for (prefix, system) in VENDOR_CLASSES:
        if vendor_class.startswith(prefix):
            return system
    # dhcpcd-<version>:<uname -s>-<uname -r>:<uname -m>, the same for DHCPv6
    if vendor_class.startswith(b'dhcpcd-') and b':' in vendor_class:
        return vendor_class.split(b':')[1].partition(b'-')[0].decode('ascii', 'replace').lower() or None
    return None


def dhcp_os(msg):
    '''guess a DHCP client's OS from its vendor class, else its parameter request list; None if unknown'''
    system = vendor_class_os(msg.option(DHCP.VENDOR_CLASS) or b'')
    if system:
        return system

    params = list(msg.option(DHCP.PARAMETER_LIST) or b'')
    # Apple's client, with classless routes (121) second in newer versions; only macOS asks for LDAP (95)
    if params[:5] in ([1, 121, 3, 6, 15], [1, 3, 6, 15, 119]) and {119, 252} <= set(params):
        return 'macos' if 95 in params else 'ios'
    # most Windows versions since 2000 ask for all of these, whether or not they send MSFT
    if {31, 33, 43, 44, 46, 47} <= set(params):
        return 'windows'
    return None


def multicast(addr):
    '''whether an ethernet address is broadcast or multicast, which stays on the local link'''
    return bool(addr[0] & 1)


def describe(host):
    extra = list(host.get('ipv6', []))
    if host.get('capabilities'):
        extra.append('[%s]' % ','.join(host['capabilities']))
    if host.get('description'):
        # some (e.g. Cisco's) span several lines
        extra.append('"%s"' % ' '.join(host['description'].split()))
    return ('%s  %-15s %-20s %-8s %-12s %s' % (
        host['mac'],
        host.get('ip', ''),
        host.get('name', ''),
        host.get('os', ''),
        host.get('vendor') or '',
        ' '.join(extra),
        )).rstrip()


def main():
    parser = argparse.ArgumentParser(description='Passively map hosts on the local network.')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('device', nargs='?', help='capture device')
    source.add_argument('--file', help='read a pcap file instead')
    args = parser.parse_args()

    if args.file:
        pd = pcap.open_offline(args.file)
    else:
        pd = pcap.open_live(args.device, 65535, True, 100)
    ports = (67, 68, 137, 546, 547, MDNS_PORT, LLMNR_PORT)
    pd.setfilter('arp or icmp6 or ether proto 0x%x or (udp and (%s))' % (
        LLDP.ETHERTYPE, ' or '.join('port %d' % port for port in ports)))

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
