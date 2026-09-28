#!/usr/bin/env python3

import struct
import unittest

from pckt import Ethernet, IP, IPv6, UDP, DNS, DNSQuestion, DNSRR
from pckt.layer7.dns import MX, SOA, SRV

# dnsmasq's answer to "www.test.lan A" (a CNAME to web.test.lan): it doesn't
# compress the CNAME target, and then points the next owner name into it
DNSMASQ_CNAME = bytes.fromhex(
    '010285800001000200000000037777770474657374036c616e0000010001c00c0005000100000000000e'
    '037765620474657374036c616e00c02a000100010000000000040a000005'
    )

RECORDS = [
    DNSRR('www.example.com', DNS.CNAME, ttl=300, data='web.example.com'),
    DNSRR('web.example.com', DNS.A, ttl=60, data='93.184.216.34'),
    DNSRR('web.example.com', DNS.AAAA, ttl=60, data='2606:2800:220:1::248'),
    DNSRR('example.com', DNS.NS, ttl=60, data='ns1.example.com'),
    DNSRR('example.com', DNS.MX, ttl=3600, data=MX(10, 'mail.example.com')),
    DNSRR('example.com', DNS.TXT, ttl=3600, data=[b'v=spf1 -all', b'', b'x' * 255]),
    DNSRR('_sip._tcp.example.com', DNS.SRV, ttl=3600, data=SRV(10, 60, 5060, 'sip.example.com')),
    DNSRR('34.216.184.93.in-addr.arpa', DNS.PTR, ttl=3600, data='web.example.com'),
    DNSRR('example.com', 99, ttl=1, data=b'\x01\x02\x03'),
    ]
SOA_RR = DNSRR('example.com', DNS.SOA, ttl=3600, data=SOA('ns1.example.com', 'hostmaster.example.com', 2026092701, 7200, 3600, 1209600, 300))
OPT_RR = DNSRR('', DNS.OPT, cls=1232, ttl=0, data=b'')


def response(**fields):
    return DNS(id=0xbeef, qr=1, aa=1, ra=1, questions=[DNSQuestion('www.example.com')],
               answers=list(RECORDS), authority=[SOA_RR], additional=[OPT_RR], **fields)


class TestBuild(unittest.TestCase):
    def test_query_vector(self):
        # RFC 1035 wire format, worked by hand
        self.assertEqual(
            bytes.fromhex('1234 0100 0001 0000 0000 0000'.replace(' ', '')) +
            b'\x07example\x03com\x00' + b'\x00\x01\x00\x01',
            DNS.query('example.com', id=0x1234).pack(),
            )

    def test_trailing_dot_and_root(self):
        self.assertEqual(DNS.query('example.com.').pack(), DNS.query('example.com').pack())
        self.assertEqual(b'\x00\x00\x02\x00\x01', DNS.query('', DNS.NS).pack()[12:])

    def test_compression(self):
        data = DNS(qr=1, questions=[DNSQuestion('www.example.com')], answers=[DNSRR('www.example.com', data='10.0.0.1')]).pack()
        # the answer's owner points at the question name (offset 12)
        self.assertEqual(b'\xc0\x0c', data[33:35])

        # suffix compression inside rdata
        data = DNS(answers=[DNSRR('www.example.com', DNS.CNAME, data='web.example.com')]).pack()
        self.assertTrue(data.endswith(b'\x03web\xc0\x10'))

    def test_no_compression(self):
        compressed = response().pack()
        plain = response(compress=False).pack()
        self.assertLess(len(compressed), len(plain))
        self.assertNotIn(b'\xc0\x0c', plain)
        self.assertEqual(DNS.decode(compressed).answers, DNS.decode(plain).answers)

    def test_srv_target_not_compressed(self):
        data = DNS(answers=[DNSRR('example.com', DNS.A, data='10.0.0.1'), DNSRR('_x._tcp.example.com', DNS.SRV, data=SRV(1, 2, 3, 'example.com'))]).pack()
        self.assertTrue(data.endswith(b'\x07example\x03com\x00'))

    def test_counts(self):
        data = response().pack()
        self.assertEqual((1, len(RECORDS), 1, 1), struct.unpack('!4H', data[4:12]))
        self.assertEqual((5, 0, 0, 0), struct.unpack('!4H', DNS(qdcount=5, ancount=0).pack()[4:12]))

    def test_flags(self):
        for (name, bit) in (('qr', 15), ('aa', 10), ('tc', 9), ('rd', 8), ('ra', 7), ('z', 6), ('ad', 5), ('cd', 4)):
            fields = {'rd': 0, name: 1}
            self.assertEqual(1 << bit, struct.unpack('!H', DNS(**fields).pack()[2:4])[0], name)
            self.assertEqual(1, getattr(DNS.decode(DNS(**fields).pack()), name))
        dns = DNS.decode(DNS(opcode=DNS.UPDATE, rcode=DNS.NXDOMAIN).pack())
        self.assertEqual((DNS.UPDATE, DNS.NXDOMAIN), (dns.opcode, dns.rcode))

    def test_txt_str(self):
        rr = DNS.decode(DNS(answers=[DNSRR('t', DNS.TXT, data=['héllo'])]).pack()).answers[0]
        self.assertEqual(['héllo'.encode('utf-8')], rr.data)

    def test_invalid_names(self):
        for name in ('a..b', 'x' * 64 + '.com'):
            with self.assertRaises(ValueError):
                DNS.query(name).pack()

    def test_non_bytes_unknown_type(self):
        with self.assertRaises(TypeError):
            DNS(answers=[DNSRR('x', 99, data='text')]).pack()

    def test_sections_not_shared(self):
        a = DNS()
        a.questions.append(DNSQuestion('x'))
        self.assertEqual([], DNS().questions)


class TestDecode(unittest.TestCase):
    def test_typed_records(self):
        dns = DNS.decode(response().pack())
        self.assertEqual([DNSQuestion('www.example.com')], dns.questions)
        self.assertEqual(RECORDS, dns.answers)
        self.assertEqual([SOA_RR], dns.authority)
        self.assertEqual([OPT_RR], dns.additional)
        self.assertEqual((0xbeef, 1, 1, 1), (dns.id, dns.qr, dns.aa, dns.ra))

    def test_roundtrip(self):
        for pkt in (response(), response(compress=False), DNS.query('example.com')):
            data = pkt.pack()
            self.assertEqual(data, DNS.decode(data).pack())

    def test_other_encoders_roundtrip(self):
        dns = DNS.decode(DNSMASQ_CNAME)
        self.assertEqual(
            [DNSRR('www.test.lan', DNS.CNAME, data='web.test.lan'), DNSRR('web.test.lan', DNS.A, data='10.0.0.5')],
            dns.answers,
            )
        self.assertEqual(DNSMASQ_CNAME, dns.pack())

    def test_edits_reencode(self):
        dns = DNS.decode(DNSMASQ_CNAME)
        dns.answers[1].ttl = 42
        data = dns.pack()
        self.assertNotEqual(DNSMASQ_CNAME, data)
        self.assertEqual(42, DNS.decode(data).answers[1].ttl)
        self.assertEqual('web.test.lan', DNS.decode(data).answers[0].data)

        dns = DNS.decode(DNSMASQ_CNAME)
        dns.id = 7
        decoded = DNS.decode(dns.pack())
        self.assertEqual(7, decoded.id)
        self.assertEqual(dns.answers, decoded.answers)

    def test_trailing_bytes(self):
        pkt = UDP.decode((UDP() / DNS.query('example.com') / b'extra').pack())
        self.assertEqual(b'extra', pkt[DNS].payload)

    def test_malformed_rdata_kept(self):
        dns = DNS.decode(DNS(answers=[DNSRR('x', DNS.A, data=b'\x01\x02\x03\x04\x05')]).pack())
        self.assertEqual(b'\x01\x02\x03\x04\x05', dns.answers[0].data)

    def test_pointer_loop(self):
        # the question name points at itself
        data = bytes.fromhex('000001000001000000000000') + b'\xc0\x0c\x00\x01\x00\x01'
        with self.assertRaises(struct.error):
            DNS.decode(data)
        pkt = IP.decode((IP() / UDP(src=1, dst=53) / data).pack())
        self.assertEqual(data, pkt[UDP].payload)

    def test_truncated(self):
        data = response().pack()
        for size in (5, 20, len(data) - 1):
            pkt = UDP.decode((UDP(src=53, dst=1) / data[:size]).pack())
            self.assertEqual(data[:size], pkt.payload)

    def test_large_message(self):
        # names past offset 0x3fff can't be pointed at
        big = [DNSRR('filler.example.com', DNS.TXT, data=[b'x' * 255]) for x in range(70)]
        tail = [DNSRR('late.example.org', DNS.A, data='10.0.0.1'), DNSRR('late.example.org', DNS.A, data='10.0.0.2')]
        data = DNS(answers=big + tail).pack()
        self.assertGreater(len(data), 0x4000)
        self.assertEqual(big + tail, DNS.decode(data).answers)


class TestTransport(unittest.TestCase):
    def test_udp_ports(self):
        data = (IP() / UDP() / DNS.query('example.com')).pack()
        self.assertEqual((53, 53), struct.unpack('!HH', data[20:24]))

    def test_dispatch(self):
        for (src, dst) in ((40000, 53), (53, 40000), (5353, 5353)):
            pkt = Ethernet.decode((Ethernet() / IPv6() / UDP(src=src, dst=dst) / DNS.query('printer.local', DNS.PTR)).pack())
            self.assertIn(DNS, pkt)
            self.assertEqual('printer.local', pkt[DNS].questions[0].name)

    def test_repr(self):
        self.assertEqual(
            "DNS(id=0x0001, questions=[DNSQuestion(name='example.com', type=1, cls=1)])",
            repr(DNS.query('example.com', id=1)),
            )


if '__main__' == __name__:
    unittest.main()
