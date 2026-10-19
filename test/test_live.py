#!/usr/bin/env python3
'''
End-to-end tests over a real veth pair, run in an unprivileged user + network
namespace (unshare -rn), so they need no root:

    v0 10.0.0.1 (kernel, dnsmasq)  <==>  v1

A create() handle on v1 captures what's sent on v0, and pckt.DNS queries
dnsmasq over a plain UDP socket.

Skipped when namespaces or the tools aren't available.
'''

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


def namespaces_work():
    if not all(shutil.which(tool) for tool in ('unshare', 'ip')):
        return False
    try:
        return 0 == subprocess.run(
            ['unshare', '-rn', 'ip', 'link', 'add', 'v0', 'type', 'veth', 'peer', 'name', 'v1'],
            capture_output=True, timeout=10,
            ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return False


def pcap_built():
    try:
        from pckt import pcap
        return True
    except ImportError:
        return False


def setup_link():
    run = lambda *cmd: subprocess.run(cmd, check=True)
    # traffic to the namespace's own addresses goes over loopback
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'add', 'v0', 'type', 'veth', 'peer', 'name', 'v1')
    run('ip', 'link', 'set', 'v0', 'up')
    run('ip', 'link', 'set', 'v1', 'up')
    run('ip', 'addr', 'add', '10.0.0.1/24', 'dev', 'v0')


DNS_QUERIES = [
    ('web.test.lan', 'A'), ('web.test.lan', 'AAAA'), ('www.test.lan', 'A'), ('test.lan', 'MX'),
    ('test.lan', 'TXT'), ('_sip._tcp.test.lan', 'SRV'), ('5.0.0.10.in-addr.arpa', 'PTR'), ('missing.test.lan', 'A'),
    ]


def dns_scenario(tmp):
    import socket
    from pckt import DNS

    setup_link()
    server = subprocess.Popen([
        'dnsmasq', '--no-daemon', '--conf-file=/dev/null', '--no-resolv', '--no-hosts', '--interface=v0',
        '--bind-interfaces', '--pid-file=' + os.path.join(tmp, 'dnsmasq.pid'), '--user=root', '--group=root',
        '--host-record=web.test.lan,10.0.0.5,fd00::5', '--cname=www.test.lan,web.test.lan',
        '--mx-host=test.lan,mail.test.lan,10', '--txt-record=test.lan,v=spf1 -all,second string',
        '--srv-host=_sip._tcp.test.lan,sip.test.lan,5060,10,60', '--local=/test.lan/',
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    results = []
    try:
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.settimeout(1)
        for (idx, (name, kind)) in enumerate(DNS_QUERIES):
            query = DNS.query(name, getattr(DNS, kind), id=0x100 + idx)
            # retry while dnsmasq starts up
            for attempt in range(10):
                skt.sendto(query.pack(), ('10.0.0.1', 53))
                try:
                    raw = skt.recv(4096)
                    break
                except socket.timeout:
                    continue
            else:
                results.append({'name': name, 'error': 'no response'})
                continue
            dns = DNS.decode(raw)
            results.append({
                'name': name,
                'id': dns.id,
                'rcode': dns.rcode,
                'exact': dns.pack() == raw,
                'answers': [[rr.name, rr.type, repr(rr.data)] for rr in dns.answers],
                })
    finally:
        server.kill()
        server.wait()
    return results


def create_scenario(tmp):
    from pckt import Ethernet, IP, UDP, pcap
    from pckt.capture import packets

    setup_link()
    subprocess.run(['ip', 'addr', 'add', '10.0.0.3/24', 'dev', 'v0'], check=True)
    subprocess.run(['ip', '-6', 'addr', 'add', '2001:db8::1/64', 'dev', 'v0', 'nodad'], check=True)
    v0 = pcap.findalldevs()['v0']
    results = {name: v0.get(name) for name in ('ip', 'ipv4', 'ipv6')}

    rx = pcap.create('v1')
    rx.set_snaplen(64)
    rx.set_promisc(True)
    rx.set_timeout(100)
    rx.set_immediate_mode(True)
    results.update(warning=rx.activate(), snapshot=rx.snapshot())
    rx.setfilter('udp port 9999')

    frame = (Ethernet(src=pcap.mac('v0'), dst=pcap.mac('v1')) / IP(src='10.0.0.1', dst='10.0.0.2')
             / UDP(src=9999, dst=9999) / bytes(200)).pack()
    results['sent'] = frame.hex()
    pcap.open_live('v0').sendpacket(frame)

    deadline = time.monotonic() + 5
    for packet in packets(rx, 0.1):
        if packet:
            (data, ts, wirelen) = packet
            results['captured'] = data.hex()
            results['wirelen'] = wirelen
            break
        if time.monotonic() > deadline:
            break

    try:
        rx.set_snaplen(128)
    except pcap.error as e:
        results['set_after'] = str(e)

    # loop() writes straight into a Dumper; the frame is already waiting
    rx.setnonblock(False)
    pcap.open_live('v0').sendpacket(frame)
    dump = os.path.join(tmp, 'live.pcap')
    with rx.dump_open(dump) as dumper:
        rx.loop(dumper, 1)
    results['dumped'] = [(data.hex(), wirelen) for (data, ts, wirelen) in pcap.open_offline(dump)]

    # filters on a device get its netmask, for 'ip broadcast'
    results['lookupnet'] = pcap.lookupnet('v0')
    broadcast = pcap.open_live('v0').compile('ip broadcast')
    results['broadcast'] = [broadcast.match((Ethernet() / IP(dst=dst) / UDP()).pack())
                            for dst in ('10.0.0.255', '10.0.0.2', '255.255.255.255')]
    return results


def scenario(mode, tmp):
    '''runs inside the namespace; returns results for the test to check'''
    if 'dns' == mode:
        return dns_scenario(tmp)
    return create_scenario(tmp)


@unittest.skipUnless(pcap_built(), 'pckt.pcap not built')
@unittest.skipUnless(namespaces_work(), 'needs unshare -rn (unprivileged namespaces) and ip')
class TestLive(unittest.TestCase):
    def run_scenario(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                ['unshare', '-rn', sys.executable, os.path.abspath(__file__), mode, tmp],
                capture_output=True, text=True, timeout=90,
                )
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def test_create(self):
        # a handle from create(), configured before activate(), captures what's sent on the peer
        result = self.run_scenario('create')
        self.assertIsNone(result['warning'])
        self.assertEqual(64, result['snapshot'])
        sent = bytes.fromhex(result['sent'])
        self.assertIn('captured', result, 'nothing captured on v1')
        self.assertEqual(sent[:64], bytes.fromhex(result['captured']))
        self.assertEqual(len(sent), result['wirelen'])
        self.assertIn("can't be changed after", result['set_after'])
        self.assertEqual([[sent[:64].hex(), len(sent)]], result['dumped'])
        self.assertEqual(['10.0.0.0', '255.255.255.0'], result['lookupnet'])
        self.assertEqual([True, False, True], result['broadcast'])
        # findalldevs() lists every address, and ip is the first IPv4 one
        self.assertEqual(('10.0.0.1', ['10.0.0.1', '10.0.0.3']), (result['ip'], result['ipv4']))
        self.assertIn('2001:db8::1', result['ipv6'])

    @unittest.skipUnless(shutil.which('dnsmasq'), 'needs dnsmasq')
    def test_dns(self):
        from pckt import DNS
        results = {r['name'] + '/' + str(i): r for (i, r) in enumerate(self.run_scenario('dns'))}
        for (key, result) in results.items():
            self.assertNotIn('error', result, key)
            # dnsmasq's responses decode and re-pack byte for byte
            self.assertTrue(result['exact'], key)
        answers = [r['answers'] for r in results.values()]
        self.assertEqual([['web.test.lan', DNS.A, "'10.0.0.5'"]], answers[0])
        self.assertEqual([['web.test.lan', DNS.AAAA, "'fd00::5'"]], answers[1])
        self.assertEqual([['www.test.lan', DNS.CNAME, "'web.test.lan'"], ['web.test.lan', DNS.A, "'10.0.0.5'"]], answers[2])
        self.assertEqual([['test.lan', DNS.MX, "MX(preference=10, exchange='mail.test.lan')"]], answers[3])
        self.assertEqual([['test.lan', DNS.TXT, "[b'v=spf1 -all', b'second string']"]], answers[4])
        self.assertEqual([['_sip._tcp.test.lan', DNS.SRV, "SRV(priority=10, weight=60, port=5060, target='sip.test.lan')"]], answers[5])
        self.assertEqual([['5.0.0.10.in-addr.arpa', DNS.PTR, "'web.test.lan'"]], answers[6])
        self.assertEqual(([], DNS.NXDOMAIN), (answers[7], list(results.values())[7]['rcode']))


if '__main__' == __name__:
    if 3 == len(sys.argv) and sys.argv[1] in ('dns', 'create'):
        print(json.dumps(scenario(sys.argv[1], sys.argv[2])))
    else:
        unittest.main()
