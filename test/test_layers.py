#!/usr/bin/env python3

import socket
import struct
import unittest

from pckt import (
    Layer, checksum, Ethernet, VLAN, ARP, IP, IPv6, ICMP, ICMP_EchoRequest, ICMP_EchoReply,
    ICMPv6, ICMPv6_EchoRequest, ICMPv6_EchoReply, ICMPv6_NeighborSolicit, ICMPv6_NeighborAdvert,
    TCP, UDP, DHCP, DHCP_Request, DHCPv6, DHCPv6Relay, LLDP,
    )


def verifies(data):
    '''receiver-side check: data including its checksum sums to 0xffff'''
    return 0 == checksum(data)


def pseudo(ip, proto, segment):
    return ip.pseudo_header(proto, len(segment)) + segment


class TestChecksum(unittest.TestCase):
    def test_ip_header_vector(self):
        # https://en.wikipedia.org/wiki/Internet_checksum
        ip = IP(len=0x73, frag=0x4000, ttl=64, proto=17, src='192.168.0.1', dst='192.168.0.199')
        self.assertEqual(bytes.fromhex('450000730000400040 11b861c0a80001c0a800c7'.replace(' ', '')), ip.pack())

    def test_odd_length(self):
        self.assertEqual(checksum(b'\x01'), checksum(b'\x01\x00'))


class TestBuild(unittest.TestCase):
    def test_udp_chain(self):
        pkt = Ethernet(src='00:11:22:33:44:55') / IP(src='10.0.0.1', dst='10.0.0.2') / UDP(src=68, dst=67) / b'hello'
        frame = pkt.pack()

        (dst, src, proto) = struct.unpack('!6s6sH', frame[:14])
        self.assertEqual((b'\xff' * 6, bytes.fromhex('001122334455'), 0x0800), (dst, src, proto))

        ip = frame[14:34]
        self.assertEqual(0x45, ip[0])
        self.assertEqual(20 + 8 + 5, struct.unpack('!H', ip[2:4])[0])
        self.assertEqual(17, ip[9])
        self.assertTrue(verifies(ip))

        udp = frame[34:]
        self.assertEqual((68, 67, 13), struct.unpack('!3H', udp[:6]))
        self.assertTrue(verifies(pseudo(pkt[IP], 17, udp)))
        self.assertEqual(b'hello', udp[8:])

    def test_tcp_chain_with_options(self):
        pkt = IP(src='10.0.0.1', dst='10.0.0.2') / TCP(src=1234, dst=80, syn=1000, flags=TCP.SYN, opts=b'\x02\x04\x05\xb4\x01') / b'x'
        data = pkt.pack()
        self.assertEqual(6, data[9])
        tcp = data[20:]
        # 5 bytes of options padded to 8 => 7 words
        self.assertEqual(7, tcp[12] >> 4)
        self.assertEqual(b'\x02\x04\x05\xb4\x01\x00\x00\x00', tcp[20:28])
        self.assertTrue(verifies(pseudo(pkt[IP], 6, tcp)))

    def test_icmp_echo(self):
        pkt = IP(src='10.0.0.1', dst='10.0.0.2') / ICMP_EchoRequest(id=7, seq=9) / b'ping'
        data = pkt.pack()
        self.assertEqual(1, data[9])
        self.assertEqual((8, 0), (data[20], data[21]))
        self.assertTrue(verifies(data[20:]))

    def test_arp(self):
        frame = (Ethernet() / ARP(op=1, src_mac='00:11:22:33:44:55', src_ip='10.0.0.1', dst_ip='10.0.0.2')).pack()
        self.assertEqual(0x0806, struct.unpack('!H', frame[12:14])[0])
        self.assertEqual(14 + 28, len(frame))

    def test_explicit_fields_win(self):
        data = (IP(proto=99, crc=0x1234, len=5) / UDP(len=3, crc=0) / b'abc').pack()
        self.assertEqual(5, struct.unpack('!H', data[2:4])[0])
        self.assertEqual(99, data[9])
        self.assertEqual(0x1234, struct.unpack('!H', data[10:12])[0])
        self.assertEqual((3, 0), struct.unpack('!HH', data[24:28]))

    def test_no_outer_ip(self):
        # nothing to build a pseudo header from
        self.assertEqual(0, struct.unpack('!H', UDP().pack(b'x')[6:8])[0])
        self.assertEqual(0, struct.unpack('!H', TCP().pack()[16:18])[0])

    def test_duck_typed_payload(self):
        dhcp = DHCP_Request()
        data = (IP() / UDP(src=68, dst=67) / dhcp).pack()
        self.assertEqual(dhcp.pack(), data[28:])

    def test_pack_data_override(self):
        # original style: pack each layer around the already packed payload;
        # UDP packed on its own has no IP layer to checksum against
        self.assertEqual(
            (IP() / UDP(crc=0) / b'abc').pack(),
            IP(proto=IP.UDP).pack(UDP().pack(b'abc')),
            )

    def test_bytes(self):
        pkt = IP() / b'x'
        self.assertEqual(pkt.pack(), bytes(pkt))


class TestChaining(unittest.TestCase):
    def test_operands_unchanged(self):
        base = Ethernet() / IP(dst='10.0.0.2')
        udp = base / UDP()
        tcp = base / TCP()
        self.assertIsNone(base[IP].payload)
        self.assertIsInstance(udp[IP].payload, UDP)
        self.assertIsInstance(tcp[IP].payload, TCP)

    def test_lookup(self):
        pkt = Ethernet() / IP() / UDP()
        self.assertEqual([Ethernet, IP, UDP], [type(l) for l in pkt])
        self.assertIn(UDP, pkt)
        self.assertNotIn(TCP, pkt)
        with self.assertRaises(KeyError):
            pkt[TCP]

    def test_no_append_after_bytes(self):
        with self.assertRaises(ValueError):
            IP() / b'x' / UDP()

    def test_unknown_field(self):
        with self.assertRaises(TypeError):
            IP(bogus=1)

    def test_repr(self):
        self.assertEqual("IP(dst='10.0.0.2') / UDP(dst=53) / b'q'", repr(IP(dst='10.0.0.2') / UDP(dst=53) / b'q'))


class TestDecode(unittest.TestCase):
    def roundtrip(self, pkt):
        data = pkt.pack()
        decoded = type(pkt).decode(data)
        self.assertEqual(data, decoded.pack())
        return decoded

    def test_udp(self):
        pkt = self.roundtrip(Ethernet() / IP(src='10.0.0.1', dst='10.0.0.2', opts=b'\x01\x01\x01\x01') / UDP(src=68, dst=67) / b'data')
        self.assertEqual([Ethernet, IP, UDP], [type(l) for l in pkt])
        self.assertEqual(('10.0.0.1', 6, b'\x01\x01\x01\x01'), (pkt[IP].src, pkt[IP].hlen, pkt[IP].opts))
        self.assertEqual(b'data', pkt[UDP].payload)

    def test_tcp(self):
        pkt = self.roundtrip(IP() / TCP(src=1, dst=2, syn=3, ack=4, flags=TCP.SYN | TCP.ACK, opts=b'\x01\x01\x01\x01'))
        self.assertEqual((3, 4, TCP.SYN | TCP.ACK, 6), (pkt[TCP].syn, pkt[TCP].ack, pkt[TCP].flags, pkt[TCP].hlen))

    def test_icmp_subclass(self):
        pkt = self.roundtrip(IP() / ICMP_EchoRequest(id=1, seq=2) / b'x')
        self.assertIsInstance(pkt[ICMP], ICMP_EchoRequest)
        self.assertEqual((1, 2), (pkt[ICMP].id, pkt[ICMP].seq))
        self.assertIsInstance(self.roundtrip(IP() / ICMP(type=3)).payload, ICMP)

    def test_arp(self):
        pkt = self.roundtrip(Ethernet() / ARP(op=2, src_ip='10.0.0.1'))
        self.assertEqual((2, '10.0.0.1'), (pkt[ARP].op, pkt[ARP].src_ip))

    def test_ethernet_padding_dropped(self):
        frame = (Ethernet() / IP() / UDP() / b'x').pack()
        pkt = Ethernet.decode(frame + b'\x00' * (60 - len(frame)))
        self.assertEqual(b'x', pkt[UDP].payload)

    def test_truncated_payload_kept(self):
        frame = (Ethernet() / IP() / UDP() / b'x').pack()[:20]
        pkt = Ethernet.decode(frame)
        self.assertEqual(frame[14:], pkt.payload)

    def test_unknown_proto_kept(self):
        pkt = IP.decode((IP(proto=200) / b'abc').pack())
        self.assertEqual(b'abc', pkt.payload)

    def test_recompute(self):
        pkt = IP.decode((IP(dst='10.0.0.2') / UDP() / b'x').pack())
        pkt.dst = '10.0.0.3'
        pkt.crc = None
        pkt[UDP].crc = None
        data = pkt.pack()
        self.assertTrue(verifies(data[:20]))
        self.assertTrue(verifies(pseudo(pkt, 17, data[20:])))


class TestEchoReply(unittest.TestCase):
    def test_from_request(self):
        req = IP.decode((IP() / ICMP_EchoRequest(id=5, seq=6) / b'x').pack())[ICMP]
        reply = ICMP_EchoReply(req, type=0)
        self.assertEqual((0, 5, 6, b'x', None), (reply.type, reply.id, reply.seq, reply.payload, reply.crc))

    def test_from_generic(self):
        reply = ICMP_EchoReply(ICMP(type=0, block=0x00050006))
        self.assertEqual((5, 6), (reply.id, reply.seq))



class TestVLAN(unittest.TestCase):
    def test_build(self):
        frame = (Ethernet() / VLAN(id=100, prio=5, dei=1) / IP()).pack()
        self.assertEqual((0x8100, (5 << 13) | (1 << 12) | 100, 0x0800), struct.unpack('!HHH', frame[12:18]))

    def test_stacked_decode(self):
        pkt = Ethernet.decode((Ethernet() / VLAN(id=7) / VLAN(id=200) / IP() / UDP() / b'x').pack())
        self.assertEqual([Ethernet, VLAN, VLAN, IP, UDP], [type(l) for l in pkt])
        self.assertEqual((7, 200), (pkt.payload.id, pkt.payload.payload.id))


class TestIPv6(unittest.TestCase):
    def test_udp(self):
        pkt = IPv6(src='fe80::1', dst='fe80::2') / UDP(src=1, dst=2) / b'abc'
        data = pkt.pack()
        self.assertEqual(0x60, data[0])
        self.assertEqual((11, 17, 255), struct.unpack('!HBB', data[4:8]))
        self.assertTrue(verifies(pseudo(pkt, 17, data[40:])))

    def test_tcp(self):
        pkt = IPv6(src='2001:db8::1', dst='2001:db8::2') / TCP(flags=TCP.SYN) / b'x'
        data = pkt.pack()
        self.assertEqual(6, data[6])
        self.assertTrue(verifies(pseudo(pkt, 6, data[40:])))

    def test_no_payload(self):
        self.assertEqual(IPv6.NO_NEXT_HEADER, IPv6().pack()[6])

    def test_traffic_class_flow(self):
        pkt = IPv6.decode(IPv6(tc=0xab, flow=0x12345).pack())
        self.assertEqual((6, 0xab, 0x12345), (pkt.ver, pkt.tc, pkt.flow))

    def test_decode(self):
        frame = (Ethernet() / IPv6(src='fe80::1', dst='fe80::2') / TCP(src=1, dst=2) / b'data').pack()
        pkt = Ethernet.decode(frame + b'\x00' * 8)
        self.assertEqual([Ethernet, IPv6, TCP], [type(l) for l in pkt])
        self.assertEqual(('fe80::1', b'data'), (pkt[IPv6].src, pkt[TCP].payload))
        self.assertEqual(frame, pkt.pack())


class TestICMPv6(unittest.TestCase):
    def test_echo(self):
        pkt = IPv6(src='fe80::1', dst='fe80::2') / ICMPv6_EchoRequest(id=7, seq=1) / b'ping'
        data = pkt.pack()
        self.assertEqual(58, data[6])
        self.assertEqual((128, 0), (data[40], data[41]))
        self.assertTrue(verifies(pseudo(pkt, 58, data[40:])))

    def test_no_outer_ipv6(self):
        self.assertEqual(0, struct.unpack('!H', ICMPv6_EchoReply().pack()[2:4])[0])

    def test_neighbor_discovery(self):
        opt = ICMPv6.lladdr_option(ICMPv6.SOURCE_LLADDR, '00:11:22:33:44:55')
        self.assertEqual(b'\x01\x01\x00\x11\x22\x33\x44\x55', opt)

        pkt = IPv6(src='fe80::1', dst='ff02::1:ff00:2') / ICMPv6_NeighborSolicit(target='fe80::2') / opt
        data = pkt.pack()
        self.assertTrue(verifies(pseudo(pkt, 58, data[40:])))
        decoded = IPv6.decode(data)
        self.assertIsInstance(decoded.payload, ICMPv6_NeighborSolicit)
        self.assertEqual(('fe80::2', opt), (decoded[ICMPv6].target, decoded[ICMPv6].payload))

        flags = ICMPv6_NeighborAdvert.SOLICITED | ICMPv6_NeighborAdvert.OVERRIDE
        decoded = IPv6.decode((IPv6() / ICMPv6_NeighborAdvert(target='fe80::2', flags=flags)).pack())
        self.assertIsInstance(decoded.payload, ICMPv6_NeighborAdvert)
        self.assertEqual(flags, decoded[ICMPv6].flags)

    def test_decode_subclasses(self):
        for cls in (ICMPv6_EchoRequest, ICMPv6_EchoReply):
            decoded = IPv6.decode((IPv6() / cls(id=3, seq=4)).pack())
            self.assertIsInstance(decoded.payload, cls)
            self.assertEqual((3, 4), (decoded[ICMPv6].id, decoded[ICMPv6].seq))
        self.assertEqual(ICMPv6, type(IPv6.decode((IPv6() / ICMPv6(type=1) / (b'\x00' * 4)).pack()).payload))


class TestDHCP(unittest.TestCase):
    def discover(self):
        return DHCP(transid=0x1234, clientmac='00:11:22:33:44:55', options=[
            (DHCP.MESSAGE_TYPE, bytes([DHCP.DISCOVER])),
            (DHCP.HOSTNAME, b'ghost'),
            ])

    def test_pack(self):
        data = self.discover().pack()
        self.assertEqual(300, len(data))
        self.assertEqual(bytes.fromhex('001122334455') + b'\x00' * 10, data[28:44])
        self.assertEqual(DHCP.MAGIC, struct.unpack('!I', data[236:240])[0])
        self.assertEqual(b'\x35\x01\x01\x0c\x05ghost\xff', data[240:251])

    def test_udp_ports(self):
        data = (IP() / UDP() / self.discover()).pack()
        self.assertEqual((68, 67), struct.unpack('!HH', data[20:24]))
        data = (IP() / UDP() / DHCP(type=DHCP.BOOTREPLY)).pack()
        self.assertEqual((67, 68), struct.unpack('!HH', data[20:24]))
        # explicit ports still win
        self.assertEqual((1, 2), struct.unpack('!HH', (UDP(src=1, dst=2) / self.discover()).pack()[:4]))

    def test_decode(self):
        frame = (Ethernet() / IP() / UDP() / self.discover()).pack()
        pkt = Ethernet.decode(frame)
        self.assertEqual([Ethernet, IP, UDP, DHCP], [type(l) for l in pkt])
        dhcp = pkt[DHCP]
        self.assertEqual((0x1234, bytes.fromhex('001122334455')), (dhcp.transid, dhcp.clientmac))
        self.assertEqual(bytes([DHCP.DISCOVER]), dhcp.option(DHCP.MESSAGE_TYPE))
        self.assertEqual(b'ghost', dhcp.option(DHCP.HOSTNAME))
        self.assertIsNone(dhcp.option(DHCP.LEASE_TIME))
        self.assertEqual(frame, pkt.pack())

    def test_decode_pad_options(self):
        data = self.discover().pack()
        # insert a pad option before the end option and drop the trailing padding
        raw = data[:251 - 1] + b'\x00\xff' + b'\x00' * 3
        dhcp = DHCP.decode(raw)
        self.assertEqual(b'\x00', dhcp.options[-1])
        self.assertEqual(raw, dhcp.pack())

    def test_raw_option_entries(self):
        self.assertEqual(
            DHCP(options=[b'\x35\x01\x03']).pack(),
            DHCP(options=[(DHCP.MESSAGE_TYPE, b'\x03')]).pack(),
            )

    def test_request_defaults(self):
        req = DHCP_Request(clientmac=b'\x00\x11\x22\x33\x44\x55')
        self.assertEqual(bytes([DHCP.REQUEST]), req.option(DHCP.MESSAGE_TYPE))
        self.assertNotEqual(req.transid, DHCP_Request().transid)
        self.assertEqual(1, DHCP.decode(req.pack()).type)

    def test_options_not_shared(self):
        a = DHCP()
        a.options.append((1, b'x'))
        self.assertEqual([], DHCP().options)


# from Wireshark's DHCPv6 sample: a solicit with a client ID, option request,
# elapsed time and a prefix delegation
DHCPV6_SOLICIT = bytes.fromhex(
    '011008740001000e000100011c39cf88080027fe8f9500060004001700180008000200000019000c27fe8f9500000e1000001518'
    )


def fqdn_option(*labels, partial=False):
    '''client FQDN option value: flags (S, the server updates AAAA records), then the name as DNS labels'''
    return b'\x01' + b''.join(bytes([len(label)]) + label for label in labels) + (b'' if partial else b'\x00')


class TestDHCPv6(unittest.TestCase):
    def test_decode(self):
        msg = DHCPv6.decode(DHCPV6_SOLICIT)
        self.assertEqual((DHCPv6.SOLICIT, 0x100874), (msg.type, msg.transid))
        self.assertEqual([DHCPv6.CLIENT_ID, DHCPv6.ORO, DHCPv6.ELAPSED_TIME, DHCPv6.IA_PD], [code for (code, value) in msg.options])
        self.assertEqual(b'\x00\x17\x00\x18', msg.option(DHCPv6.ORO))
        self.assertIsNone(msg.option(DHCPv6.CLIENT_FQDN))
        self.assertEqual(DHCPV6_SOLICIT, msg.pack())

    def test_udp_ports(self):
        for (kind, ports) in ((DHCPv6.SOLICIT, (546, 547)), (DHCPv6.INFORMATION_REQUEST, (546, 547)), (DHCPv6.REPLY, (547, 546))):
            data = (IPv6() / UDP() / DHCPv6(type=kind)).pack()
            self.assertEqual(ports, struct.unpack('!HH', data[40:44]), kind)
        pkt = Ethernet.decode((Ethernet() / IPv6() / UDP() / DHCPv6()).pack())
        self.assertEqual([Ethernet, IPv6, UDP, DHCPv6], [type(l) for l in pkt])

    def test_raw_option_entries(self):
        self.assertEqual(DHCPv6(options=[b'\x00\x08\x00\x02\x00\x00']).pack(), DHCPv6(options=[(DHCPv6.ELAPSED_TIME, b'\x00\x00')]).pack())

    def test_fqdn(self):
        cases = [
            (fqdn_option(b'DESKTOP-AB12', b'corp', b'example'), 'DESKTOP-AB12.corp.example'),
            # just the host name, which needn't be terminated
            (fqdn_option(b'laptop', partial=True), 'laptop'),
            (fqdn_option(b'laptop'), 'laptop'),
            # flags only, an overlong label, and a truncated one
            (b'\x01', None),
            (b'\x01\x40' + b'x' * 64, None),
            (b'\x01\x08laptop', None),
            ]
        for (value, name) in cases:
            with self.subTest(value=value):
                self.assertEqual(name, DHCPv6(options=[(DHCPv6.CLIENT_FQDN, value)]).fqdn())
        self.assertIsNone(DHCPv6().fqdn())

    def test_vendor_classes(self):
        msg = DHCPv6(options=[
            (DHCPv6.VENDOR_CLASS, struct.pack('!IH', 311, 8) + b'MSFT 5.0'),
            (DHCPv6.VENDOR_CLASS, struct.pack('!IH', 40712, 1) + b'a' + struct.pack('!H', 2) + b'bc'),
            # truncated data, and too short for an enterprise number
            (DHCPv6.VENDOR_CLASS, struct.pack('!IH', 9, 5) + b'abc'),
            (DHCPv6.VENDOR_CLASS, b'\x00\x00'),
            ])
        self.assertEqual([(311, [b'MSFT 5.0']), (40712, [b'a', b'bc']), (9, [])], msg.vendor_classes())

    def test_relay(self):
        inner = DHCPv6(transid=1).pack()
        relay = DHCPv6Relay(hops=1, link='2001:db8::1', peer='fe80::7', options=[(DHCPv6.RELAY_MSG, inner)])
        frame = (Ethernet() / IPv6() / UDP() / relay).pack()
        self.assertEqual((547, 547), struct.unpack('!HH', frame[54:58]))
        msg = Ethernet.decode(frame)[DHCPv6]
        self.assertIsInstance(msg, DHCPv6Relay)
        self.assertEqual((DHCPv6.RELAY_FORW, 1, '2001:db8::1', 'fe80::7'), (msg.type, msg.hops, msg.link, msg.peer))
        self.assertEqual(1, DHCPv6.decode(msg.option(DHCPv6.RELAY_MSG)).transid)
        self.assertEqual(frame, Ethernet.decode(frame).pack())

    def test_truncated(self):
        data = DHCPV6_SOLICIT[:-2]
        with self.assertRaises(struct.error):
            DHCPv6.decode(data)
        # inside a frame it's kept as bytes
        pkt = Ethernet.decode((Ethernet() / IPv6() / UDP(src=546, dst=547) / data).pack())
        self.assertNotIn(DHCPv6, pkt)
        self.assertEqual(data, pkt[UDP].payload)

    def test_options_not_shared(self):
        DHCPv6().options.append((1, b'x'))
        self.assertEqual([], DHCPv6().options)


def lldp_switch(port_mac=b'\x00\x11\x22\x33\x44\x02'):
    '''what a switch port sends: its chassis is identified by the switch's MAC'''
    return LLDP(tlvs=[
        (LLDP.CHASSIS_ID, bytes([LLDP.CHASSIS_MAC]) + b'\x00\x11\x22\x33\x44\x00'),
        (LLDP.PORT_ID, bytes([LLDP.PORT_INTERFACE]) + b'gi0/2'),
        (LLDP.TTL, struct.pack('!H', 120)),
        (LLDP.PORT_DESCRIPTION, b'uplink'),
        (LLDP.SYSTEM_NAME, b'core-sw'),
        (LLDP.SYSTEM_DESCRIPTION, b'Cisco IOS Software, C2960 Software\nCopyright (c) 1986-2016'),
        # supported: bridge and router; enabled: the same
        (LLDP.SYSTEM_CAPABILITIES, struct.pack('!HH', 0x14, 0x14)),
        # length (family + address), family, address, interface numbering, interface, OID length
        (LLDP.MANAGEMENT_ADDRESS, struct.pack('!BB4sBIB', 5, 1, socket.inet_aton('10.0.0.2'), 2, 1, 0)),
        (LLDP.MANAGEMENT_ADDRESS, struct.pack('!BB16sBIB', 17, 2, socket.inet_pton(socket.AF_INET6, '2001:db8::2'), 2, 1, 0)),
        ])


class TestLLDP(unittest.TestCase):
    def test_build(self):
        frame = (Ethernet(dst=LLDP.MULTICAST, src='00:11:22:33:44:02') / lldp_switch()).pack()
        self.assertEqual(LLDP.ETHERTYPE, struct.unpack('!H', frame[12:14])[0])
        # chassis ID TLV: type 1, length 7
        self.assertEqual(struct.pack('!H', (1 << 9) | 7), frame[14:16])
        # ends with the end TLV
        self.assertEqual(b'\x00\x00', frame[-2:])

    def test_decode(self):
        frame = (Ethernet(dst=LLDP.MULTICAST) / lldp_switch()).pack()
        pkt = Ethernet.decode(frame)
        lldp = pkt[LLDP]
        self.assertEqual(lldp_switch().tlvs, lldp.tlvs)
        self.assertEqual(b'core-sw', lldp.tlv(LLDP.SYSTEM_NAME))
        self.assertIsNone(lldp.tlv(LLDP.ORGANIZATION))
        self.assertEqual(['bridge', 'router'], lldp.capabilities())
        self.assertEqual(['10.0.0.2', '2001:db8::2'], lldp.management_addresses())
        self.assertEqual(frame, pkt.pack())

    def test_padding(self):
        # short frames are padded to 60 bytes after the end TLV
        frame = (Ethernet(dst=LLDP.MULTICAST) / LLDP(tlvs=[(LLDP.TTL, b'\x00\x78')])).pack()
        frame += bytes(60 - len(frame))
        pkt = Ethernet.decode(frame)
        self.assertEqual([(LLDP.TTL, b'\x00\x78')], pkt[LLDP].tlvs)
        self.assertEqual(frame, pkt.pack())

    def test_truncated(self):
        data = lldp_switch().pack()[:6]
        with self.assertRaises(struct.error):
            LLDP.decode(data)
        # inside a frame it's kept as bytes
        pkt = Ethernet.decode((Ethernet(proto=LLDP.ETHERTYPE) / data).pack())
        self.assertNotIn(LLDP, pkt)
        self.assertEqual(data, pkt.payload)

    def test_malformed_fields(self):
        lldp = LLDP(tlvs=[(LLDP.SYSTEM_CAPABILITIES, b'\x00'), (LLDP.MANAGEMENT_ADDRESS, b'\x05\x09abcd'), (LLDP.MANAGEMENT_ADDRESS, b'\x03\x01ab')])
        self.assertEqual([], lldp.capabilities())
        # an unknown family, then an IPv4 address that's too short
        self.assertEqual([], lldp.management_addresses())

    def test_default_not_shared(self):
        LLDP().tlvs.append((LLDP.TTL, b'\x00\x00'))
        self.assertEqual([], LLDP().tlvs)


if '__main__' == __name__:
    unittest.main()
