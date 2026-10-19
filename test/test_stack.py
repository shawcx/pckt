#!/usr/bin/env python3

import os
import socket
import subprocess
import sys
import tempfile
import unittest

from pckt import (
    checksum, Ethernet, ARP, IP, IPv6, ICMP, ICMP_EchoRequest, ICMP_EchoReply, ICMPv6, ICMPv6_EchoRequest,
    ICMPv6_NeighborSolicit, ICMPv6_NeighborAdvert, UDP, DHCP, DNS, DNSRR, LLDP,
    )
from pckt.stack.ghost import Ghost, BROADCAST, DHCP_RETRY
from pckt.mapping.passive import PassiveMapper, describe

try:
    from pckt import pcap
except ImportError:
    pcap = None

from test_pcap import write_pcap
from test_layers import lldp_switch

GHOST_MAC = bytes.fromhex('020000000001')
PEER_MAC = bytes.fromhex('00505600aabb')  # VMware prefix, for the vendor lookup
SERVER_MAC = bytes.fromhex('00505600ccdd')


class FakePcap:
    def __init__(self):
        self.sent = []

    def sendpacket(self, data):
        self.sent.append(Ethernet.decode(data))


class TestGhost(unittest.TestCase):
    def ghost(self, ip='10.0.0.66'):
        self.pd = FakePcap()
        return Ghost(self.pd, GHOST_MAC, ip)

    def arp_request(self, ip, dst=BROADCAST):
        return (Ethernet(dst=dst, src=PEER_MAC) / ARP(op=ARP.REQUEST, src_mac=PEER_MAC, src_ip='10.0.0.1', dst_mac=b'\x00' * 6, dst_ip=ip)).pack()

    def test_arp(self):
        ghost = self.ghost()
        ghost.inbound(self.arp_request('10.0.0.66'))
        (reply,) = self.pd.sent
        self.assertEqual((PEER_MAC, GHOST_MAC), (reply.dst, reply.src))
        arp = reply[ARP]
        self.assertEqual((ARP.REPLY, GHOST_MAC, '10.0.0.66', PEER_MAC, '10.0.0.1'), (arp.op, arp.src_mac, arp.src_ip, arp.dst_mac, arp.dst_ip))

    def test_arp_other_ip(self):
        ghost = self.ghost()
        ghost.inbound(self.arp_request('10.0.0.67'))
        self.assertEqual([], self.pd.sent)

    def test_other_mac_ignored(self):
        ghost = self.ghost()
        ghost.inbound(self.arp_request('10.0.0.66', dst=bytes.fromhex('020000000099')))
        self.assertEqual([], self.pd.sent)

    def test_runt_ignored(self):
        self.ghost().inbound(b'\x00' * 10)
        self.assertEqual([], self.pd.sent)

    def test_ping(self):
        ghost = self.ghost()
        ghost.inbound((Ethernet(dst=GHOST_MAC, src=PEER_MAC) / IP(src='10.0.0.1', dst='10.0.0.66') / ICMP_EchoRequest(id=9, seq=3) / b'abcdefgh').pack())
        (reply,) = self.pd.sent
        self.assertEqual(('10.0.0.66', '10.0.0.1'), (reply[IP].src, reply[IP].dst))
        echo = reply[ICMP]
        self.assertIsInstance(echo, ICMP_EchoReply)
        self.assertNotIsInstance(echo, ICMP_EchoRequest)
        self.assertEqual((9, 3, b'abcdefgh'), (echo.id, echo.seq, echo.payload))
        self.assertEqual(0, checksum(reply[IP].pack()[20:]))

    def test_ping_other_ip(self):
        ghost = self.ghost()
        ghost.inbound((Ethernet(dst=GHOST_MAC, src=PEER_MAC) / IP(src='10.0.0.1', dst='10.0.0.5') / ICMP_EchoRequest()).pack())
        self.assertEqual([], self.pd.sent)

    def server(self, ghost, kind, transid=None, yourip='10.0.0.50'):
        return (
            Ethernet(dst=BROADCAST, src=SERVER_MAC) /
            IP(src='10.0.0.1', dst='255.255.255.255') /
            UDP() /
            DHCP(type=DHCP.BOOTREPLY, transid=ghost.xid if transid is None else transid, yourip=yourip, clientmac=GHOST_MAC, options=[
                (DHCP.MESSAGE_TYPE, bytes([kind])),
                (DHCP.SERVER_ID, socket.inet_aton('10.0.0.1')),
                ])
            ).pack()

    def test_dhcp(self):
        ghost = self.ghost(ip=None)
        ghost.dhcp(DHCP.DISCOVER)
        discover = self.pd.sent[-1]
        self.assertEqual((68, 67), (discover[UDP].src, discover[UDP].dst))
        self.assertEqual((bytes([DHCP.DISCOVER]), ghost.xid, GHOST_MAC), (discover[DHCP].option(DHCP.MESSAGE_TYPE), discover[DHCP].transid, discover[DHCP].clientmac))

        # no address yet, so ARP isn't answered
        ghost.inbound(self.arp_request('10.0.0.50'))
        self.assertEqual(1, len(self.pd.sent))

        ghost.inbound(self.server(ghost, DHCP.OFFER, transid=ghost.xid + 1))
        self.assertEqual(1, len(self.pd.sent))

        ghost.inbound(self.server(ghost, DHCP.OFFER))
        request = self.pd.sent[-1][DHCP]
        self.assertEqual(bytes([DHCP.REQUEST]), request.option(DHCP.MESSAGE_TYPE))
        self.assertEqual(socket.inet_aton('10.0.0.50'), request.option(DHCP.REQUESTED_IP))
        self.assertEqual(socket.inet_aton('10.0.0.1'), request.option(DHCP.SERVER_ID))

        # a second offer is ignored
        ghost.inbound(self.server(ghost, DHCP.OFFER, yourip='10.0.0.51'))
        self.assertEqual(2, len(self.pd.sent))

        ghost.inbound(self.server(ghost, DHCP.ACK))
        self.assertEqual('10.0.0.50', ghost.ip)

        ghost.inbound(self.arp_request('10.0.0.50'))
        self.assertEqual('10.0.0.50', self.pd.sent[-1][ARP].src_ip)

    def test_dhcp_retry(self):
        ghost = self.ghost(ip=None)
        ghost.dhcp(DHCP.DISCOVER)
        ghost.inbound(self.server(ghost, DHCP.OFFER))
        self.assertEqual(2, len(self.pd.sent))

        # the ACK never arrives
        ghost.tick(ghost.dhcp_sent + 1)
        self.assertEqual(2, len(self.pd.sent))
        # not exactly DHCP_RETRY: (t + 10) - t can round to just under 10
        ghost.tick(ghost.dhcp_sent + DHCP_RETRY + 0.5)
        self.assertEqual(3, len(self.pd.sent))
        self.assertEqual(bytes([DHCP.DISCOVER]), self.pd.sent[-1][DHCP].option(DHCP.MESSAGE_TYPE))

        # a fresh offer is accepted again
        ghost.inbound(self.server(ghost, DHCP.OFFER))
        self.assertEqual(bytes([DHCP.REQUEST]), self.pd.sent[-1][DHCP].option(DHCP.MESSAGE_TYPE))
        ghost.inbound(self.server(ghost, DHCP.ACK))
        self.assertEqual('10.0.0.50', ghost.ip)

        # bound: no more retries
        ghost.tick(ghost.dhcp_sent + 100)
        self.assertEqual(4, len(self.pd.sent))

    def test_static_ip_no_dhcp(self):
        ghost = self.ghost()
        ghost.tick(10**9)
        self.assertEqual([], self.pd.sent)

    def test_dhcp_nak(self):
        ghost = self.ghost(ip=None)
        ghost.dhcp(DHCP.DISCOVER)
        ghost.inbound(self.server(ghost, DHCP.OFFER))
        old = ghost.xid
        ghost.inbound(self.server(ghost, DHCP.NAK))
        self.assertIsNone(ghost.ip)
        self.assertNotEqual(old, ghost.xid)
        restart = self.pd.sent[-1][DHCP]
        self.assertEqual((bytes([DHCP.DISCOVER]), ghost.xid), (restart.option(DHCP.MESSAGE_TYPE), restart.transid))


def dhcp_request(mac, name=None, vendor_class=None, params=None, requested='10.0.0.50'):
    options = [(DHCP.MESSAGE_TYPE, bytes([DHCP.REQUEST])), (DHCP.REQUESTED_IP, socket.inet_aton(requested))]
    if name:
        options.append((DHCP.HOSTNAME, name))
    if vendor_class:
        options.append((DHCP.VENDOR_CLASS, vendor_class))
    if params:
        options.append((DHCP.PARAMETER_LIST, bytes(params)))
    return (Ethernet(src=mac) / IP(src='0.0.0.0') / UDP() / DHCP(clientmac=mac, options=options)).pack()


def arp_from(mac, ip):
    return (Ethernet(src=mac) / ARP(op=ARP.REQUEST, src_mac=mac, src_ip=ip, dst_ip='10.0.0.1')).pack()


def ndp_from(mac, src, msg):
    return (Ethernet(src=mac, dst='33:33:00:00:00:01') / IPv6(src=src, dst='ff02::1') / msg).pack()


# mDNS sets the cache-flush bit in the class of a host's unique records
CACHE_FLUSH = 0x8000


def mdns_from(mac, src, records, qr=1, port=5353):
    ip = IPv6(src=src, dst='ff02::fb') if ':' in src else IP(src=src, dst='224.0.0.251')
    return (Ethernet(src=mac) / ip / UDP(src=port, dst=5353) / DNS(qr=qr, aa=qr, rd=0, answers=records)).pack()


def address_records(name, *addrs):
    return [DNSRR(name, DNS.AAAA if ':' in a else DNS.A, DNS.IN | CACHE_FLUSH, 120, a) for a in addrs]


class TestPassive(unittest.TestCase):
    def test_arp(self):
        mapper = PassiveMapper()
        host = mapper.process(arp_from(PEER_MAC, '10.0.0.7'))
        self.assertEqual({'mac': '00:50:56:00:aa:bb', 'vendor': 'VMware', 'ip': '10.0.0.7'}, host)
        # unchanged
        self.assertIsNone(mapper.process(arp_from(PEER_MAC, '10.0.0.7')))
        self.assertEqual('10.0.0.8', mapper.process(arp_from(PEER_MAC, '10.0.0.8'))['ip'])

    def test_arp_probe_ignored(self):
        mapper = PassiveMapper()
        self.assertIsNone(mapper.process(arp_from(PEER_MAC, '0.0.0.0')))
        self.assertEqual({}, mapper.hosts)

    def test_dhcp(self):
        mapper = PassiveMapper()
        host = mapper.process(dhcp_request(PEER_MAC, name=b'desktop', vendor_class=b'MSFT 5.0'))
        self.assertEqual(('10.0.0.50', 'desktop', 'windows'), (host['ip'], host['name'], host['os']))

    def test_dhcp_os(self):
        cases = [
            (b'MSFT 5.0', None, 'windows'),
            (b'android-dhcp-14', [1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108], 'android'),
            (b'udhcp 1.36.1', None, 'linux'),
            (b'dhcpcd-10.0.6:Linux-6.6.31+rpt-rpi-v8:aarch64:BCM2835', None, 'linux'),
            (b'dhcpcd-9.4.1:NetBSD-10.0:amd64', None, 'netbsd'),
            # without uname
            (b'dhcpcd-9.4.1', None, None),
            # Apple's current lists, then an older one without 121
            (None, [1, 121, 3, 6, 15, 119, 108, 252, 114, 162, 95, 44, 46], 'macos'),
            (None, [1, 121, 3, 6, 15, 119, 108, 252, 114, 162], 'ios'),
            (None, [1, 3, 6, 15, 119, 95, 252, 44, 46], 'macos'),
            # Windows 10 without its vendor class
            (None, [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252], 'windows'),
            # NetworkManager and ISC dhclient also ask for some of those
            (None, [1, 2, 6, 12, 15, 26, 28, 121, 3, 33, 40, 41, 42, 119, 249, 252, 17], None),
            (None, [1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42], None),
            ]
        for (vendor_class, params, expected) in cases:
            with self.subTest(vendor_class=vendor_class, params=params):
                host = PassiveMapper().process(dhcp_request(PEER_MAC, vendor_class=vendor_class, params=params))
                self.assertEqual(expected, host.get('os'))

    def test_ndp(self):
        mapper = PassiveMapper()
        # a solicitation's source is the sender's; its target isn't
        host = mapper.process(ndp_from(PEER_MAC, 'fe80::1', ICMPv6_NeighborSolicit(target='fe80::2')))
        self.assertEqual(['fe80::1'], host['ipv6'])
        # an advertisement's target is the sender's too
        advert = ICMPv6_NeighborAdvert(target='2001:db8::5', flags=ICMPv6_NeighborAdvert.SOLICITED)
        self.assertEqual(['fe80::1', '2001:db8::5'], mapper.process(ndp_from(PEER_MAC, 'fe80::1', advert))['ipv6'])
        self.assertIsNone(mapper.process(ndp_from(PEER_MAC, 'fe80::1', advert)))
        # duplicate address detection: the target may not end up being the sender's
        self.assertIsNone(mapper.process(ndp_from(PEER_MAC, '::', ICMPv6_NeighborSolicit(target='2001:db8::9'))))
        # router solicitation
        host = mapper.process(ndp_from(SERVER_MAC, 'fe80::3', ICMPv6(type=133) / bytes(4)))
        self.assertEqual(['fe80::3'], host['ipv6'])
        # other ICMPv6 isn't neighbor discovery
        self.assertIsNone(mapper.process(ndp_from(GHOST_MAC, 'fe80::4', ICMPv6_EchoRequest())))
        self.assertEqual(2, len(mapper.hosts))

    def test_mdns(self):
        mapper = PassiveMapper()
        records = address_records('Laptop.local', '10.0.0.7', 'fe80::7', '2001:db8::7') + [
            DNSRR('_ssh._tcp.local', DNS.PTR, DNS.IN, 4500, 'Laptop._ssh._tcp.local')]
        host = mapper.process(mdns_from(PEER_MAC, '10.0.0.7', records))
        self.assertEqual(('Laptop', '10.0.0.7', ['fe80::7', '2001:db8::7']), (host['name'], host['ip'], host['ipv6']))
        # the same records sent over IPv6
        self.assertIsNone(mapper.process(mdns_from(PEER_MAC, 'fe80::7', records)))

    def test_mdns_ignored(self):
        mapper = PassiveMapper()
        records = address_records('laptop.local', '10.0.0.7')
        # a sleep proxy answering for another host
        self.assertIsNone(mapper.process(mdns_from(SERVER_MAC, '10.0.0.9', records)))
        # a query, and a unicast DNS response
        self.assertIsNone(mapper.process(mdns_from(PEER_MAC, '10.0.0.7', records, qr=0)))
        self.assertIsNone(mapper.process(mdns_from(PEER_MAC, '10.0.0.7', records, port=53)))
        # not .local
        self.assertIsNone(mapper.process(mdns_from(PEER_MAC, '10.0.0.7', address_records('laptop.lan', '10.0.0.7'))))
        self.assertEqual({}, mapper.hosts)

    def test_mdns_utf8_name(self):
        # DNS names are the raw label bytes as latin-1; mDNS sends UTF-8
        name = 'Mätt-Laptop.local'.encode('utf-8').decode('latin-1')
        host = PassiveMapper().process(mdns_from(PEER_MAC, '10.0.0.7', address_records(name, '10.0.0.7')))
        self.assertEqual('Mätt-Laptop', host['name'])

    def test_lldp(self):
        mapper = PassiveMapper()
        host = mapper.process((Ethernet(dst=LLDP.MULTICAST, src='00:11:22:33:44:02') / lldp_switch()).pack())
        # keyed by the chassis MAC, not the port's
        self.assertEqual('00:11:22:33:44:00', host['mac'])
        self.assertEqual(('core-sw', '10.0.0.2', ['2001:db8::2'], ['bridge', 'router']),
                         (host['name'], host['ip'], host['ipv6'], host['capabilities']))
        self.assertTrue(host['description'].startswith('Cisco IOS Software'))
        self.assertIn('[bridge,router] "Cisco IOS Software, C2960 Software Copyright (c) 1986-2016"', describe(host))
        # another port of the same switch
        self.assertIsNone(mapper.process((Ethernet(dst=LLDP.MULTICAST, src='00:11:22:33:44:03') / lldp_switch()).pack()))
        self.assertEqual(['00:11:22:33:44:00'], list(mapper.hosts))

    def test_lldp_local_chassis(self):
        # e.g. lldpd with a locally assigned chassis ID: keyed by the sender's MAC
        lldp = LLDP(tlvs=[(LLDP.CHASSIS_ID, bytes([LLDP.CHASSIS_LOCAL]) + b'server1'), (LLDP.SYSTEM_NAME, b'server1')])
        host = PassiveMapper().process((Ethernet(dst=LLDP.MULTICAST, src=PEER_MAC) / lldp).pack())
        self.assertEqual(('00:50:56:00:aa:bb', 'server1'), (host['mac'], host['name']))

    def test_describe(self):
        mapper = PassiveMapper()
        mapper.process(arp_from(PEER_MAC, '10.0.0.7'))
        self.assertEqual('00:50:56:00:aa:bb  10.0.0.7%sVMware' % (' ' * 38), describe(mapper.hosts['00:50:56:00:aa:bb']))
        host = mapper.process(ndp_from(PEER_MAC, 'fe80::1', ICMPv6_NeighborSolicit(target='fe80::2')))
        self.assertTrue(describe(host).endswith('VMware       fe80::1'), describe(host))

    def test_dhcp_reply_ignored(self):
        mapper = PassiveMapper()
        reply = (Ethernet() / IP() / UDP() / DHCP(type=DHCP.BOOTREPLY, clientmac=PEER_MAC, yourip='10.0.0.9')).pack()
        self.assertIsNone(mapper.process(reply))

    def test_other_traffic_ignored(self):
        mapper = PassiveMapper()
        self.assertIsNone(mapper.process((Ethernet(src=PEER_MAC) / IP(src='8.8.8.8') / UDP(src=53, dst=53)).pack()))
        self.assertIsNone(mapper.process(b'\x00' * 10))

    @unittest.skipIf(pcap is None, 'pckt.pcap not built')
    def test_main_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'capture.pcap')
            write_pcap(path, [
                arp_from(PEER_MAC, '10.0.0.7'),
                (Ethernet() / IP() / UDP(src=1, dst=2) / b'filtered out').pack(),
                dhcp_request(SERVER_MAC, name=b'laptop'),
                ndp_from(GHOST_MAC, 'fe80::1', ICMPv6_NeighborSolicit(target='fe80::2')),
                mdns_from(PEER_MAC, '10.0.0.7', address_records('printer.local', '10.0.0.7')),
                (Ethernet(dst=LLDP.MULTICAST, src='00:11:22:33:44:02') / lldp_switch()).pack(),
                ])
            root = os.path.dirname(os.path.dirname(pcap.__file__))
            result = subprocess.run(
                [sys.executable, '-m', 'pckt.mapping.passive', '--file', path],
                capture_output=True, text=True, timeout=30, cwd=root,
                )
        self.assertEqual(0, result.returncode, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(5, len(lines))
        self.assertIn('10.0.0.7', lines[0])
        self.assertIn('laptop', lines[1])
        self.assertIn('fe80::1', lines[2])
        self.assertIn('printer', lines[3])
        self.assertIn('core-sw', lines[4])


if '__main__' == __name__:
    unittest.main()
