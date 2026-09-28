#!/usr/bin/env python3

import os
import socket
import subprocess
import sys
import tempfile
import unittest

from pckt import checksum, Ethernet, ARP, IP, ICMP, ICMP_EchoRequest, ICMP_EchoReply, UDP, DHCP
from pckt.stack.ghost import Ghost, BROADCAST
from pckt.mapping.passive import PassiveMapper

try:
    from pckt import pcap
except ImportError:
    pcap = None

from test_pcap import write_pcap

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


def dhcp_request(mac, name=None, vendor_class=None, requested='10.0.0.50'):
    options = [(DHCP.MESSAGE_TYPE, bytes([DHCP.REQUEST])), (DHCP.REQUESTED_IP, socket.inet_aton(requested))]
    if name:
        options.append((DHCP.HOSTNAME, name))
    if vendor_class:
        options.append((DHCP.VENDOR_CLASS, vendor_class))
    return (Ethernet(src=mac) / IP(src='0.0.0.0') / UDP() / DHCP(clientmac=mac, options=options)).pack()


def arp_from(mac, ip):
    return (Ethernet(src=mac) / ARP(op=ARP.REQUEST, src_mac=mac, src_ip=ip, dst_ip='10.0.0.1')).pack()


class TestPassive(unittest.TestCase):
    def test_arp(self):
        mapper = PassiveMapper()
        host = mapper.process(arp_from(PEER_MAC, '10.0.0.7'))
        self.assertEqual({'mac': '00:50:56:00:aa:bb', 'vendor': 'Vmware', 'ip': '10.0.0.7'}, host)
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
                ])
            root = os.path.dirname(os.path.dirname(pcap.__file__))
            result = subprocess.run(
                [sys.executable, '-m', 'pckt.mapping.passive', '--file', path],
                capture_output=True, text=True, timeout=30, cwd=root,
                )
        self.assertEqual(0, result.returncode, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(2, len(lines))
        self.assertIn('10.0.0.7', lines[0])
        self.assertIn('laptop', lines[1])


if '__main__' == __name__:
    unittest.main()
