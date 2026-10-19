#!/usr/bin/env python3

import ast
import ipaddress
import os
import pathlib
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest

from pckt import Ethernet, IP, UDP, TCP
from pckt.capture import packets

try:
    from pckt import pcap
except ImportError:
    pcap = None


FRAMES = [
    (Ethernet() / IP(src='10.0.0.1', dst='10.0.0.2') / UDP(src=1, dst=2) / b'one').pack(),
    (Ethernet() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP(src=3, dst=4) / b'two').pack(),
    (Ethernet() / IP(src='10.0.0.1', dst='10.0.0.2') / UDP(src=5, dst=6) / b'three').pack(),
]

# udp port 53, udp port 80, ARP, udp port 53 to another host, udp port 123
MIXED = [
    (Ethernet() / IP(src='10.0.0.1', dst='10.0.0.2') / UDP(src=40000, dst=53) / b'data').pack(),
    (Ethernet() / IP(src='10.0.0.1', dst='10.0.0.2') / UDP(src=40000, dst=80) / b'data').pack(),
    bytes(6) + b'\x02\x00\x00\x00\x00\x01\x08\x06' + bytes(28),
    (Ethernet() / IP(src='10.0.0.1', dst='10.0.0.3') / UDP(src=40000, dst=53) / b'data').pack(),
    (Ethernet() / IP(src='10.0.0.1', dst='10.0.0.2') / UDP(src=40000, dst=123) / b'data').pack(),
]

DLT_EN10MB = 1
DLT_RAW = 12

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def write_pcap(path, frames, wirelen_extra=0):
    with open(path, 'wb') as f:
        # pcap file header: magic, version 2.4, tz, sigfigs, snaplen, ethernet
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for idx, frame in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + idx, 250000, len(frame), len(frame) + wirelen_extra) + frame)


def pcap_bytes(frames, linktype=DLT_EN10MB, snaplen=65535, endian='<'):
    '''a pcap file of frames, each idx at 1700000000 + idx seconds and idx * 1000 + 7 microseconds'''
    out = [struct.pack(endian + 'IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype)]
    for idx, frame in enumerate(frames):
        out.append(struct.pack(endian + 'IIII', 1700000000 + idx, idx * 1000 + 7, len(frame), len(frame)))
        out.append(frame)
    return b''.join(out)


def read_pcap(path):
    '''
    (snaplen, linktype, [(ts_sec, ts_fraction, wirelen, data), ...]) from a pcap
    file; the fraction is in microseconds, or nanoseconds in a nanosecond file
    '''
    raw = pathlib.Path(path).read_bytes()
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    (snaplen, linktype) = struct.unpack(endian + 'II', raw[16:24])
    (records, offset) = ([], 24)
    while offset < len(raw):
        (sec, frac, caplen, wirelen) = struct.unpack(endian + 'IIII', raw[offset:offset + 16])
        offset += 16
        records.append((sec, frac, wirelen, raw[offset:offset + caplen]))
        offset += caplen
    return (snaplen, linktype, records)


def run_isolated(script, *args, timeout=10):
    '''
    runs script in a child Python that imports this pckt, so a deadlock fails the
    test instead of hanging it; returns its stdout, or None if it timed out
    '''
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [
        os.path.dirname(os.path.dirname(pcap.__file__)), os.environ.get('PYTHONPATH')])))
    try:
        result = subprocess.run([sys.executable, '-c', textwrap.dedent(script), *args],
                                capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


@unittest.skipIf(pcap is None, 'pckt.pcap not built (python3 setup.py build_ext --inplace)')
class PcapTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, 'test.pcap')
        write_pcap(self.path, FRAMES)

    def tearDown(self):
        self.tmp.cleanup()

    def make_pcap(self, frames, **kwargs):
        '''the path of a new pcap_bytes() file'''
        path = os.path.join(self.tmp.name, 'capture%d.pcap' % len(os.listdir(self.tmp.name)))
        pathlib.Path(path).write_bytes(pcap_bytes(frames, **kwargs))
        return path

    def open(self, frames, **kwargs):
        '''a handle reading frames, closed after the test'''
        pd = pcap.open_offline(self.make_pcap(frames, **kwargs))
        self.addCleanup(pd.close)
        return pd

    def tmp_path(self, name):
        return os.path.join(self.tmp.name, name)


class TestPcap(PcapTest):
    def test_findalldevs(self):
        devices = pcap.findalldevs()
        self.assertIsInstance(devices, dict)
        for name, info in devices.items():
            self.assertIsInstance(name, str)
            if 'mac' in info:
                self.assertIsInstance(info['mac'], bytes)
            if 'ip' in info:
                # the first IPv4 address
                self.assertEqual(info['ipv4'][0], info['ip'])
            for addr in info.get('ipv4', []):
                socket.inet_pton(socket.AF_INET, addr)
            for addr in info.get('ipv6', []):
                socket.inet_pton(socket.AF_INET6, addr)

    def test_findalldevs_details(self):
        for name, info in pcap.findalldevs().items():
            self.assertTrue(info['description'] is None or isinstance(info['description'], str), name)
            self.assertIsInstance(info['flags'], int)
            for address in info['addresses']:
                self.assertIn(address['family'], (socket.AF_INET, socket.AF_INET6))
                for key in ('addr', 'netmask', 'broadcast', 'dstaddr'):
                    if address[key] is not None:
                        ipaddress.ip_address(address[key])
            # ipv4 and ipv6 list the same addresses
            for (family, key) in ((socket.AF_INET, 'ipv4'), (socket.AF_INET6, 'ipv6')):
                listed = [a['addr'] for a in info['addresses'] if a['family'] == family]
                self.assertEqual(listed, info.get(key, []), name)

    @unittest.skipIf(sys.platform == 'win32', 'loopback interface name')
    def test_findalldevs_loopback(self):
        loopback = pcap.findalldevs()['lo0' if sys.platform == 'darwin' else 'lo']
        self.assertTrue(loopback['flags'] & pcap.IF_LOOPBACK)
        self.assertTrue(loopback['flags'] & pcap.IF_UP)
        self.assertIn({'family': socket.AF_INET, 'addr': '127.0.0.1', 'netmask': '255.0.0.0',
                       'broadcast': None, 'dstaddr': None}, loopback['addresses'])
        self.assertEqual(('127.0.0.1', '255.0.0.0'), (loopback['ip'], loopback['netmask']))
        for address in loopback['addresses']:
            if '::1' == address['addr']:
                self.assertEqual('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', address['netmask'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'needs a loopback named lo')
    def test_mac(self):
        self.assertEqual(bytes(6), pcap.mac('lo'))
        with self.assertRaisesRegex(pcap.error, 'nosuch0'):
            pcap.mac('nosuch0')
        with self.assertRaises(TypeError):
            pcap.mac(b'lo')
        # findalldevs() reports the same address
        for (name, info) in pcap.findalldevs().items():
            if 'mac' in info:
                self.assertEqual(pcap.mac(name), info['mac'], name)

    @unittest.skipIf(sys.platform == 'win32', 'loopback interface name')
    def test_lookupnet(self):
        self.assertEqual(('127.0.0.0', '255.0.0.0'), pcap.lookupnet('lo0' if sys.platform == 'darwin' else 'lo'))
        with self.assertRaises(pcap.error):
            pcap.lookupnet('nosuch0')
        with self.assertRaises(TypeError):
            pcap.lookupnet(b'lo')

    def test_module(self):
        self.assertIn('libpcap', pcap.lib_version())
        self.assertEqual('pckt.pcap', pcap.error.__module__)
        self.assertTrue(issubclass(pcap.error, Exception))

    def test_create(self):
        # pcap_create() doesn't check the device; activate() does, and needs privileges
        pd = pcap.create('nosuch0')
        for call in (pd.snapshot, pd.datalink, pd.bufsize, pd.major_version, pd.minor_version, pd.is_swapped):
            with self.assertRaisesRegex(pcap.error, 'not been activated'):
                call()
        self.assertIsNone(pd.set_snaplen(128))
        self.assertIsNone(pd.set_promisc(False))
        self.assertIsNone(pd.set_timeout(50))
        self.assertIsNone(pd.set_immediate_mode(True))
        self.assertIsNone(pd.set_buffer_size(1 << 20))
        self.assertIsNone(pd.set_rfmon(False))
        self.assertIsNone(pd.set_tstamp_type(pcap.TSTAMP_HOST))
        self.assertIsNone(pd.set_tstamp_precision(pcap.TSTAMP_PRECISION_MICRO))
        try:
            pd.set_tstamp_precision(pcap.TSTAMP_PRECISION_NANO)
        except pcap.error as e:
            # macOS BPF only has microsecond timestamps
            self.assertIn('precision', str(e))
            self.assertEqual(pcap.TSTAMP_PRECISION_MICRO, pd.get_tstamp_precision())
        else:
            self.assertEqual(pcap.TSTAMP_PRECISION_NANO, pd.get_tstamp_precision())
        for entry in pd.list_tstamp_types():
            self.assertEqual(3, len(entry))
            self.assertIsInstance(entry[0], int)
        self.assertEqual('', pd.geterr())
        with self.assertRaises(TypeError):
            pd.set_snaplen('128')
        with self.assertRaises(OverflowError):
            pd.set_timeout(1 << 40)
        for call in (pd.next, lambda: pd.loop(print), lambda: pd.dispatch(print), lambda: pd.compile('udp'),
                     lambda: pd.dump_open(self.tmp_path('unactivated.pcap'))):
            with self.assertRaises(pcap.error):
                call()
        if sys.platform != 'win32':
            with self.assertRaises(pcap.error):
                pd.setdirection(pcap.D_IN)
        with self.assertRaisesRegex(pcap.error, 'nosuch0'):
            pd.activate()
        pd.close()
        for call in (pd.activate, pd.geterr, lambda: pd.set_snaplen(128)):
            with self.assertRaises(pcap.error):
                call()

    def test_unsupported_tstamp_type_warns(self):
        pd = pcap.create('nosuch0')
        self.addCleanup(pd.close)
        self.assertIsInstance(pd.set_tstamp_type(pcap.TSTAMP_ADAPTER_UNSYNCED), str)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux only')
    def test_set_protocol_linux(self):
        pd = pcap.create('nosuch0')
        self.assertIsNone(pd.set_protocol_linux(0x0806))
        pd.close()
        with self.assertRaisesRegex(pcap.error, 'activated'):
            pcap.open_offline(self.path).set_protocol_linux(0x0806)

    def test_settings_after_activation(self):
        pd = pcap.open_offline(self.path)
        for setter in ('set_snaplen', 'set_promisc', 'set_timeout', 'set_immediate_mode', 'set_buffer_size',
                       'set_rfmon', 'set_tstamp_type', 'set_tstamp_precision'):
            with self.subTest(setter), self.assertRaisesRegex(pcap.error, 'activated'):
                getattr(pd, setter)(0)

    def test_only_devices_can_rfmon(self):
        # libpcap itself crashes if asked on a file or open_dead() handle
        self.assertIs(False, pcap.open_offline(self.path).can_set_rfmon())
        self.assertIs(False, pcap.open_dead().can_set_rfmon())

    def test_open_live_unknown_device(self):
        with self.assertRaises(pcap.error):
            pcap.open_live('nosuch0')

    def test_next(self):
        pd = pcap.open_offline(self.path)
        (data, ts, wirelen) = pd.next()
        self.assertEqual(FRAMES[0], data)
        self.assertEqual(1000.25, ts)
        self.assertEqual(len(FRAMES[0]), wirelen)
        pd.next()
        pd.next()
        with self.assertRaises(EOFError):
            pd.next()
        pd.close()

    def test_packets_file(self):
        pd = pcap.open_offline(self.path)
        self.assertEqual(FRAMES, [data for (data, ts, wirelen) in packets(pd)])

    def test_fileno(self):
        self.assertIsInstance(pcap.open_offline(self.path).fileno(), int)

    def test_wirelen(self):
        write_pcap(self.path, FRAMES[:1], wirelen_extra=100)
        pd = pcap.open_offline(self.path)
        self.assertEqual(len(FRAMES[0]) + 100, pd.next()[2])

    def test_loop(self):
        seen = []
        pcap.open_offline(self.path).loop(lambda *args: seen.append(args), -1, 'a', 'b')
        self.assertEqual([(f, 1000.25 + i, len(f), 'a', 'b') for i, f in enumerate(FRAMES)], seen)

    def test_loop_count(self):
        seen = []
        pd = pcap.open_offline(self.path)
        pd.loop(lambda data, ts, wirelen: seen.append(data), 2)
        self.assertEqual(FRAMES[:2], seen)
        # the rest are still there
        self.assertEqual(FRAMES[2], pd.next()[0])

    def test_loop_decode(self):
        ports = []
        pcap.open_offline(self.path).loop(lambda data, *_: ports.append(Ethernet.decode(data)[IP].payload.dst))
        self.assertEqual([2, 4, 6], ports)

    def test_callback_exception(self):
        seen = []
        def fail(data, *args):
            seen.append(data)
            if 2 == len(seen):
                raise ValueError('from callback')
        with self.assertRaisesRegex(ValueError, 'from callback'):
            pcap.open_offline(self.path).loop(fail)
        self.assertEqual(FRAMES[:2], seen)

    def test_breakloop(self):
        pd = pcap.open_offline(self.path)
        seen = []
        def stop(data, *args):
            seen.append(data)
            pd.breakloop()
        self.assertIsNone(pd.loop(stop))
        self.assertEqual(1, len(seen))

    def test_bad_callback(self):
        with self.assertRaises(pcap.error):
            pcap.open_offline(self.path).loop('not callable')
        with self.assertRaises(TypeError):
            pcap.open_offline(self.path).loop()

    def test_busy_inside_loop(self):
        # the pcap_t can't be closed, re-entered or refiltered from a callback
        for call in ('close', 'next', 'loop', 'dispatch', 'setfilter', 'iter'):
            pd = pcap.open_offline(self.path)
            calls = {
                'close': pd.close, 'next': pd.next, 'loop': lambda: pd.loop(print),
                'dispatch': lambda: pd.dispatch(print), 'setfilter': lambda: pd.setfilter('udp'),
                'iter': lambda: next(iter(pd)),
            }
            with self.subTest(call), self.assertRaisesRegex(pcap.error, 'busy'):
                pd.loop(lambda *args: calls[call]())
            # once the loop has ended the handle can be used again
            self.assertEqual(FRAMES[1], pd.next()[0])
            pd.close()

    def test_loops_run_concurrently_in_threads(self):
        # each callback waits until the other loop is running too
        barrier = threading.Barrier(2, timeout=5)
        results = {}

        def run(name):
            pd = pcap.open_offline(self.path)
            seen = []
            def callback(data, *args):
                if not seen:
                    barrier.wait()
                seen.append(data)
            try:
                pd.loop(callback)
                results[name] = seen
            except Exception as e:
                results[name] = e
            finally:
                pd.close()

        threads = [threading.Thread(target=run, args=(name,)) for name in 'ab']
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual({'a': FRAMES, 'b': FRAMES}, results)

    def test_filter(self):
        pd = pcap.open_offline(self.path)
        pd.setfilter('tcp')
        seen = []
        pd.loop(lambda data, *_: seen.append(data))
        self.assertEqual([FRAMES[1]], seen)
        with self.assertRaisesRegex(pcap.error, 'syntax error'):
            pd.setfilter('not a (valid filter')
        with self.assertRaises(TypeError):
            pd.setfilter(53)

    def test_closed(self):
        pd = pcap.open_offline(self.path)
        pd.close()
        calls = [
            pd.next, pd.datalink, lambda: pd.loop(print), lambda: pd.sendpacket(b'x'), lambda: pd.inject(b'x'),
            pd.breakloop, pd.geterr, pd.stats, pd.list_datalinks, pd.snapshot, pd.bufsize, pd.getnonblock,
            lambda: pd.setnonblock(False), lambda: pd.setfilter('udp'), lambda: pd.compile('udp'),
            lambda: pd.dump_open(self.tmp_path('unused.pcap')), lambda: pd.dispatch(print),
            lambda: pd.set_timeout(100), pd.can_set_rfmon, pd.list_tstamp_types, pd.get_tstamp_precision,
            lambda: pd.set_datalink(1), pd.major_version, pd.minor_version, pd.is_swapped, lambda: iter(pd),
            pd.__enter__,
        ]
        if sys.platform != 'win32':
            calls += [pd.fileno, pd.get_required_select_timeout]
        for call in calls:
            with self.assertRaisesRegex(pcap.error, 'invalid handle'):
                call()
        # closing again is fine
        pd.close()

    def test_open_errors(self):
        with self.assertRaises(pcap.error):
            pcap.open_offline(os.path.join(self.tmp.name, 'missing.pcap'))
        for target in (None, 1.5, ['capture.pcap']):
            with self.assertRaisesRegex(TypeError, 'path, a file object or a file descriptor'):
                pcap.open_offline(target)
        with self.assertRaises(pcap.error):
            pcap.open_offline(-1)

    def test_open_path_types(self):
        for convert in (str, os.fsencode, pathlib.Path):
            with self.subTest(convert):
                pd = pcap.open_offline(convert(self.path))
                self.assertEqual(FRAMES[0], pd.next()[0])
                pd.close()

    def test_datalink(self):
        pd = pcap.open_offline(self.path)
        self.assertEqual((1, 'EN10MB', 'Ethernet'), pd.datalink())
        self.assertEqual([(1, 'EN10MB', 'Ethernet')], pd.list_datalinks())
        unknown = self.open(FRAMES, linktype=999)
        self.assertEqual((999, None, None), unknown.datalink())
        self.assertEqual([(999, None, None)], unknown.list_datalinks())

    def test_snapshot(self):
        self.assertEqual(1500, self.open(FRAMES, snaplen=1500).snapshot())
        self.assertGreater(pcap.open_offline(self.path).bufsize(), 0)

    def test_file_rejects_live_calls(self):
        pd = pcap.open_offline(self.path)
        for call in (lambda: pd.inject(bytes(60)), lambda: pd.sendpacket(bytes(60)), pd.stats):
            with self.assertRaises(pcap.error):
                call()

    def test_file_details(self):
        for endian in '<>':
            with self.subTest(endian):
                pd = self.open(FRAMES, endian=endian)
                self.assertEqual((2, 4), (pd.major_version(), pd.minor_version()))
                self.assertIs(endian != ('<' if 'little' == sys.byteorder else '>'), pd.is_swapped())
                self.assertEqual(FRAMES, [data for (data, ts, wirelen) in pd])

    def test_handle(self):
        pd = pcap.open_offline(self.path)
        self.assertIsInstance(pd, pcap.Handle)
        self.assertIsInstance(iter(pd), pcap.PacketIterator)
        self.assertIsInstance(pd.compile('udp'), pcap.BPFProgram)
        with pd.dump_open(self.tmp_path('types.pcap')) as dumper:
            self.assertIsInstance(dumper, pcap.Dumper)
        self.assertTrue(repr(pd).startswith('<pckt.pcap.Handle object'))
        # a handle made directly has no device behind it, and can be subclassed
        with self.assertRaisesRegex(pcap.error, 'invalid handle'):
            pcap.Handle().next()
        with self.assertRaises(TypeError):
            pcap.Handle('eth0')
        class Sub(pcap.Handle):
            pass
        self.assertIsNone(Sub().close())
        for cls in (pcap.Dumper, pcap.PacketIterator):
            with self.assertRaises(TypeError):
                cls()

    def test_context_manager(self):
        with pcap.open_offline(self.path) as pd:
            self.assertEqual(FRAMES[0], pd.next()[0])
        with self.assertRaisesRegex(pcap.error, 'invalid handle'):
            pd.next()
        with self.assertRaises(ValueError):
            with pcap.open_offline(self.path) as pd:
                raise ValueError
        with self.assertRaisesRegex(pcap.error, 'invalid handle'):
            pd.next()

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'needs a FIFO')
    def test_loop_releases_gil(self):
        # loop() blocks in libpcap reading a FIFO until another Python thread
        # writes the next packet, which deadlocks if loop() holds the GIL
        script = '''
            import os, struct, sys, threading
            from pckt import pcap

            fifo = sys.argv[1]
            frame = b'\\xff' * 14
            record = struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame

            # a reader must exist before the writer can open without blocking
            dummy = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            w = os.open(fifo, os.O_WRONLY)
            os.write(w, struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + record)
            pd = pcap.open_offline(fifo)
            os.close(dummy)

            got_first = threading.Event()
            def writer():
                got_first.wait()
                os.write(w, record)
                os.close(w)
            threading.Thread(target=writer).start()

            seen = []
            pd.loop(lambda data, *args: (seen.append(data), got_first.set()))
            print(len(seen))
            '''
        fifo = self.tmp_path('fifo')
        os.mkfifo(fifo)
        result = run_isolated(script, fifo)
        self.assertIsNotNone(result, 'loop() held the GIL while blocked in libpcap')
        self.assertEqual('2', result)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'needs a FIFO')
    def test_open_releases_gil(self):
        # open_offline() blocks until another thread opens the FIFO and writes
        # the file header, which deadlocks if it holds the GIL
        script = '''
            import struct, sys, threading, time
            from pckt import pcap

            def writer():
                time.sleep(0.2)
                with open(sys.argv[1], 'wb') as f:
                    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                    f.write(struct.pack('<IIII', 0, 0, 14, 14) + bytes(14))
            threading.Thread(target=writer).start()

            print(len(list(pcap.open_offline(sys.argv[1]))))
            '''
        fifo = self.tmp_path('fifo')
        os.mkfifo(fifo)
        result = run_isolated(script, fifo)
        self.assertIsNotNone(result, 'open_offline() held the GIL while waiting for the header')
        self.assertEqual('1', result)


class TestFilter(PcapTest):
    def test_setfilter(self):
        pd = self.open(MIXED)
        self.assertIsNone(pd.setfilter('udp dst port 53'))
        self.assertEqual([MIXED[0], MIXED[3]], [data for (data, ts, wirelen) in pd])

    def test_program_on_two_handles(self):
        path = self.make_pcap(MIXED)
        (first, second) = (pcap.open_offline(path), pcap.open_offline(path))
        program = first.compile('arp or udp port 123')
        for pd in (first, second):
            pd.setfilter(program)
            seen = []
            pd.loop(lambda data, *_: seen.append(data))
            self.assertEqual([MIXED[2], MIXED[4]], seen)
            pd.close()

    def test_match(self):
        program = pcap.open_offline(self.path).compile('udp port 53', optimize=False)
        self.assertEqual([True, False, False, True, False], [program.match(frame) for frame in MIXED])
        self.assertIs(True, program.match(bytearray(MIXED[0])))
        self.assertIs(True, program.match(memoryview(MIXED[0])))
        self.assertIs(False, program.match(b''))
        with self.assertRaises(TypeError):
            program.match('text')

    def test_netmask(self):
        broadcast = (Ethernet() / IP(dst='10.0.0.255') / UDP()).pack()
        pd = pcap.open_offline(self.path)
        # a file has no device to take the netmask from
        with self.assertRaisesRegex(pcap.error, 'netmask'):
            pd.compile('ip broadcast')
        program = pd.compile('ip broadcast', netmask='255.255.255.0')
        self.assertIs(True, program.match(broadcast))
        self.assertIs(False, program.match(MIXED[0]))
        for netmask in ('255.255.255', 'nope', 0xffffff00):
            with self.subTest(netmask), self.assertRaisesRegex(pcap.error, 'dotted IPv4 string'):
                pd.compile('udp', netmask=netmask)
        pd.setfilter('ip broadcast', netmask='255.255.255.0')

    def test_open_dead(self):
        ethernet = pcap.open_dead()
        raw = pcap.open_dead(linktype=DLT_RAW, snaplen=1500)
        self.assertEqual((1, 'EN10MB', 'Ethernet'), ethernet.datalink())
        self.assertEqual((DLT_RAW, 'RAW'), raw.datalink()[:2])
        self.assertEqual(1500, raw.snapshot())
        packet = MIXED[0][14:]
        self.assertIs(True, ethernet.compile('udp port 53').match(MIXED[0]))
        self.assertIs(True, raw.compile('udp port 53').match(packet))
        self.assertIs(False, ethernet.compile('udp port 53').match(packet))
        with self.assertRaises(pcap.error):
            ethernet.next()

    def test_compile_without_handle(self):
        packet = MIXED[0][14:]
        self.assertIs(True, pcap.compile('udp port 53').match(MIXED[0]))
        self.assertIs(True, pcap.compile('udp port 53', DLT_RAW).match(packet))
        self.assertIs(False, pcap.compile('udp port 53', linktype=DLT_RAW).match(MIXED[0]))
        self.assertEqual(list(pcap.open_dead().compile('udp port 53')), list(pcap.compile('udp port 53')))
        self.assertEqual(['(000) ret      #1500'], pcap.compile('', snaplen=1500).instructions())
        broadcast = (Ethernet() / IP(dst='10.0.0.255') / UDP()).pack()
        self.assertIs(True, pcap.compile('ip broadcast', netmask='255.255.255.0').match(broadcast))
        # unlike pcap_compile_nopcap(), libpcap's error text comes through
        with self.assertRaisesRegex(pcap.error, 'syntax error'):
            pcap.compile('udp port')
        with self.assertRaisesRegex(pcap.error, 'netmask'):
            pcap.compile('ip broadcast')

    def test_instructions(self):
        program = pcap.open_dead().compile('udp port 53')
        lines = program.instructions()
        self.assertEqual(len(lines), len(program))
        self.assertGreater(len(lines), 2)
        self.assertEqual('(000) ldh      [12]', lines[0])
        self.assertTrue(lines[-1].startswith('(%03d) ret ' % (len(lines) - 1)))
        self.assertEqual(['(000) ret      #65535'], pcap.open_dead().compile('').instructions())

    def test_program_from_instructions(self):
        # as `tcpdump -ddd -y EN10MB arp` prints them, with its default snaplen
        tcpdump = '4\n40 0 0 12\n21 0 1 2054\n6 0 0 262144\n6 0 0 0\n'
        program = pcap.BPFProgram(tuple(map(int, line.split())) for line in tcpdump.splitlines()[1:])
        self.assertEqual(list(pcap.compile('arp', snaplen=262144)), list(program))
        self.assertEqual(4, len(program))
        self.assertEqual((0x28, 0, 0, 12), program[0])  # ldh [12]
        self.assertEqual((6, 0, 0, 0), program[-1])     # ret #0
        with self.assertRaises(IndexError):
            program[4]
        self.assertEqual([False, False, True, False, False], [program.match(frame) for frame in MIXED])

        pd = self.open(MIXED)
        pd.setfilter(program)
        self.assertEqual([MIXED[2]], [data for (data, ts, wirelen) in pd])

        copy = pcap.BPFProgram(program)
        self.assertEqual(list(program), list(copy))
        self.assertEqual(program.instructions(), copy.instructions())
        self.assertIs(True, pcap.BPFProgram([[6, 0, 0, 65535]]).match(b'x'))

    def test_invalid_program(self):
        for (instructions, message) in [
            ([(6, 0, 0)], 'instruction 0 must be'),
            ([(6, 0, 0, 0), (6, 0, 0, -1)], 'instruction 1 must be'),
            ([(6, 0, 0, 2**32)], 'instruction 0 must be'),
            ([(6, 256, 0, 0)], 'instruction 0 must be'),
            ([(0x10000, 0, 0, 0)], 'instruction 0 must be'),
            ([(6, 0, 0, '0')], 'instruction 0 must be'),
            (['6000'], 'instruction 0 must be'),
            ([], 'invalid BPF program'),
            ([(0x28, 0, 0, 12)], 'invalid BPF program'),               # no return at the end
            ([(0x15, 5, 0, 1), (6, 0, 0, 0)], 'invalid BPF program'),  # jumps past the end
        ]:
            with self.subTest(instructions), self.assertRaisesRegex(pcap.error, message):
                pcap.BPFProgram(instructions)
        with self.assertRaises(TypeError):
            pcap.BPFProgram()
        with self.assertRaisesRegex(TypeError, 'iterable'):
            pcap.BPFProgram(5)

    def test_lookups(self):
        self.assertEqual(1, pcap.datalink_name_to_val('EN10MB'))
        self.assertEqual(1, pcap.datalink_name_to_val('en10mb'))
        self.assertEqual(DLT_RAW, pcap.datalink_name_to_val('RAW'))
        self.assertEqual('EN10MB', pcap.datalink_val_to_name(1))
        self.assertEqual('Ethernet', pcap.datalink_val_to_description(1))
        self.assertIsNone(pcap.datalink_val_to_name(999))
        self.assertIsNone(pcap.datalink_val_to_description(999))
        with self.assertRaisesRegex(pcap.error, "unknown link type 'nonsense'"):
            pcap.datalink_name_to_val('nonsense')
        with self.assertRaises(TypeError):
            pcap.datalink_name_to_val(1)
        with self.assertRaises(TypeError):
            pcap.datalink_val_to_name('EN10MB')

        self.assertEqual(pcap.TSTAMP_HOST, pcap.tstamp_type_name_to_val('host'))
        self.assertEqual(pcap.TSTAMP_ADAPTER, pcap.tstamp_type_name_to_val('adapter'))
        self.assertEqual('adapter_unsynced', pcap.tstamp_type_val_to_name(pcap.TSTAMP_ADAPTER_UNSYNCED))
        self.assertIsNone(pcap.tstamp_type_val_to_name(99))
        with self.assertRaisesRegex(pcap.error, 'unknown timestamp type'):
            pcap.tstamp_type_name_to_val('sundial')

    def test_set_datalink(self):
        dead = pcap.open_dead()
        self.assertIsNone(dead.set_datalink(1))
        with self.assertRaisesRegex(pcap.error, 'not one of the DLTs'):
            dead.set_datalink(DLT_RAW)
        self.assertEqual(1, dead.datalink()[0])


class TestDumper(PcapTest):
    def test_roundtrip(self):
        path = self.tmp_path('out.pcap')
        dumper = pcap.open_offline(self.path).dump_open(path)
        for idx, frame in enumerate(FRAMES):
            dumper.write(frame, 1700000000 + idx + 0.25)
        dumper.close()

        copy = pcap.open_offline(path)
        self.assertEqual([(frame, 1700000000 + idx + 0.25, len(frame)) for idx, frame in enumerate(FRAMES)], list(copy))
        copy.close()
        (snaplen, linktype, records) = read_pcap(path)
        self.assertEqual((65535, DLT_EN10MB), (snaplen, linktype))
        self.assertEqual([(1700000000 + idx, 250000) for idx in range(len(FRAMES))], [r[:2] for r in records])

    def test_loop_into_dumper(self):
        # a Dumper is written to directly, keeping the capture timestamps
        source = self.make_pcap(MIXED)
        out = self.tmp_path('copy.pcap')
        pd = pcap.open_offline(source)
        with pd.dump_open(out) as dumper:
            self.assertIsNone(pd.loop(dumper))
        pd.close()
        self.assertEqual(read_pcap(source), read_pcap(out))

    def test_loop_into_dumper_write(self):
        # write() takes (data, ts, wirelen), so it can be the callback
        source = self.make_pcap(MIXED)
        out = self.tmp_path('copy.pcap')
        pd = pcap.open_offline(source)
        with pd.dump_open(out) as dumper:
            pd.loop(dumper.write)
        pd.close()
        self.assertEqual(read_pcap(source), read_pcap(out))

    def test_loop_into_dumper_with_filter_and_count(self):
        out = self.tmp_path('dns.pcap')
        pd = self.open(MIXED)
        pd.setfilter('udp port 53')
        with pd.dump_open(out) as dumper:
            pd.loop(dumper, 1)
            with self.assertRaises(TypeError):
                pd.loop(dumper, -1, 'extra')
        self.assertEqual([MIXED[0]], [record[3] for record in read_pcap(out)[2]])

    def test_timestamps(self):
        for (ts, expected) in [
            (1700000000.25, (1700000000, 250000)),
            (1700000000, (1700000000, 0)),
            (2.9999999, (3, 0)),
        ]:
            with self.subTest(ts):
                path = self.tmp_path('ts.pcap')
                with pcap.open_dead().dump_open(path) as dumper:
                    dumper.write(bytes(60), ts=ts)
                self.assertEqual(expected, read_pcap(path)[2][0][:2])

    def test_default_timestamp_is_now(self):
        for precision in (pcap.TSTAMP_PRECISION_MICRO, pcap.TSTAMP_PRECISION_NANO):
            with self.subTest(precision):
                path = self.tmp_path('now.pcap')
                before = time.time()
                with pcap.open_dead(precision=precision).dump_open(path) as dumper:
                    dumper.write(bytes(60))
                (sec, frac) = read_pcap(path)[2][0][:2]
                scale = 1e9 if pcap.TSTAMP_PRECISION_NANO == precision else 1e6
                self.assertLess(frac, scale)
                self.assertTrue(before - 1 <= sec + frac / scale <= time.time() + 1)

    def test_lengths(self):
        path = self.tmp_path('lengths.pcap')
        with pcap.open_dead(snaplen=64).dump_open(path) as dumper:
            dumper.write(b'\x01' * 100)
            dumper.write(b'\x02' * 40, wirelen=1500)
            dumper.write(bytearray(b'\x03' * 10), 1.0, None)
            dumper.write(memoryview(b'\x04' * 10))
            with self.assertRaisesRegex(pcap.error, 'wirelen'):
                dumper.write(b'\x05' * 40, wirelen=39)
            with self.assertRaises(TypeError):
                dumper.write('text')
        self.assertEqual([(100, b'\x01' * 64), (1500, b'\x02' * 40), (10, b'\x03' * 10), (10, b'\x04' * 10)],
                         [(wirelen, data) for (_, _, wirelen, data) in read_pcap(path)[2]])
        # reading it back reports the original length
        self.assertEqual((b'\x01' * 64, 100), pcap.open_offline(path).next()[::2])

    def test_append(self):
        path = self.tmp_path('append.pcap')
        dead = pcap.open_dead()
        with dead.dump_open(path) as dumper:
            dumper.write(b'\x01' * 60, ts=1)
        with dead.dump_open(path, append=True) as dumper:
            dumper.write(b'\x02' * 60, ts=2)
        self.assertEqual([1, 2], [record[0] for record in read_pcap(path)[2]])
        # the link types must match
        with self.assertRaises(pcap.error):
            pcap.open_dead(linktype=DLT_RAW).dump_open(path, append=True)
        with open(path, 'ab') as f, self.assertRaisesRegex(pcap.error, 'append needs a path'):
            dead.dump_open(f, append=True)

    def test_closed(self):
        pd = pcap.open_offline(self.path)
        with pd.dump_open(self.tmp_path('closed.pcap')) as dumper:
            dumper.flush()
        dumper.close()
        for call in (lambda: dumper.write(b'\x00'), dumper.flush, dumper.tell, dumper.__enter__, lambda: pd.loop(dumper)):
            with self.assertRaisesRegex(pcap.error, 'dumper is closed'):
                call()

    def test_open_errors(self):
        with self.assertRaises(pcap.error):
            pcap.open_dead().dump_open(self.tmp_path('missing/out.pcap'))
        with self.assertRaises(pcap.error):
            pcap.open_dead().dump_open(-1)

    def test_tell(self):
        path = self.tmp_path('tell.pcap')
        with pcap.open_dead().dump_open(path) as dumper:
            self.assertEqual(24, dumper.tell())  # the file header
            dumper.write(bytes(60), ts=1)
            self.assertEqual(24 + 16 + 60, dumper.tell())
            dumper.write(bytes(100), ts=2)
            self.assertEqual(24 + 2 * 16 + 60 + 100, dumper.tell())
        self.assertEqual(24 + 2 * 16 + 60 + 100, os.path.getsize(path))

    @unittest.skipIf(sys.platform == 'win32', 'ftell on a Windows pipe is undefined')
    def test_tell_on_pipe(self):
        (rfd, wfd) = os.pipe()
        try:
            with pcap.open_dead().dump_open(wfd) as dumper:
                with self.assertRaises(pcap.error):
                    dumper.tell()
        finally:
            os.close(rfd)
            os.close(wfd)

    def test_nanoseconds(self):
        path = self.tmp_path('nano.pcap')
        dead = pcap.open_dead(precision=pcap.TSTAMP_PRECISION_NANO)
        self.assertEqual(pcap.TSTAMP_PRECISION_NANO, dead.get_tstamp_precision())
        with dead.dump_open(path) as dumper:
            dumper.write(bytes(60), ts=1.000000123)
            dumper.write(bytes(60), ts=2.9999999999)
        self.assertEqual([(1, 123), (3, 0)], [record[:2] for record in read_pcap(path)[2]])

        nano = pcap.open_offline(path, precision=pcap.TSTAMP_PRECISION_NANO)
        self.assertEqual(pcap.TSTAMP_PRECISION_NANO, nano.get_tstamp_precision())
        self.assertAlmostEqual(1.000000123, nano.next()[1], delta=1e-12)
        # read at microsecond precision, libpcap drops the nanoseconds
        micro = pcap.open_offline(path)
        self.assertEqual(pcap.TSTAMP_PRECISION_MICRO, micro.get_tstamp_precision())
        self.assertEqual(1.0, micro.next()[1])

    @unittest.skipIf(sys.platform == 'win32', 'needs a pipe that select() works on')
    def test_busy_while_loop_writes(self):
        # loop(dumper) blocks on a pipe after the first packet; meanwhile another
        # thread (which only runs if loop() released the GIL) can't touch the dumper
        (rfd, wfd) = os.pipe()
        os.write(wfd, pcap_bytes(FRAMES[:1]))
        out = self.tmp_path('busy.pcap')
        pd = pcap.open_offline(rfd)
        dumper = pd.dump_open(out)
        errors = []

        def poke():
            time.sleep(0.2)
            for call in (lambda: dumper.write(bytes(60)), dumper.close):
                try:
                    call()
                except pcap.error as e:
                    errors.append(str(e))
            pd.breakloop()
            os.close(wfd)  # if breakloop() didn't land, EOF ends the loop instead of hanging

        thread = threading.Thread(target=poke)
        thread.start()
        try:
            pd.loop(dumper)
        finally:
            thread.join()
            os.close(rfd)
        self.assertEqual(['dumper is busy in loop()'] * 2, errors)
        dumper.close()
        pd.close()
        self.assertEqual(FRAMES[:1], [record[3] for record in read_pcap(out)[2]])


class TestFiles(PcapTest):
    def test_dump_to_file_object(self):
        path = self.tmp_path('object.pcap')
        pd = pcap.open_offline(self.path)
        with open(path, 'wb') as f:
            with pd.dump_open(f) as dumper:
                pd.loop(dumper)
            # the dumper wrote through its own copy of the descriptor, so f is still open
            self.assertFalse(f.closed)
            f.write(b'')
        self.assertEqual(FRAMES, [record[3] for record in read_pcap(path)[2]])

    def test_descriptors(self):
        path = self.tmp_path('fd.pcap')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        with pcap.open_dead().dump_open(fd) as dumper:
            for frame in FRAMES:
                dumper.write(frame, ts=1)
        os.fstat(fd)  # still open
        os.close(fd)

        fd = os.open(path, os.O_RDONLY)
        pd = pcap.open_offline(fd)
        self.assertEqual(FRAMES, [data for (data, ts, wirelen) in pd])
        pd.close()
        os.fstat(fd)
        os.close(fd)

    def test_read_file_object(self):
        with open(self.path, 'rb') as f:
            pd = pcap.open_offline(f, precision=pcap.TSTAMP_PRECISION_NANO)
            self.assertEqual(pcap.TSTAMP_PRECISION_NANO, pd.get_tstamp_precision())
            self.assertEqual([(frame, 1000.25 + idx, len(frame)) for idx, frame in enumerate(FRAMES)], list(pd))
            pd.close()
            self.assertFalse(f.closed)

    def test_pipe(self):
        (rfd, wfd) = os.pipe()
        with pcap.open_dead().dump_open(wfd) as dumper:
            for frame in FRAMES:
                dumper.write(frame)
        os.close(wfd)
        pd = pcap.open_offline(rfd)
        self.assertEqual(FRAMES, [data for (data, ts, wirelen) in pd])
        pd.close()
        os.close(rfd)

    def test_subprocess(self):
        # the way to read `tcpdump -w -`
        child = subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.stdout.buffer.write(open(sys.argv[1], "rb").read())', self.path],
            stdout=subprocess.PIPE)
        pd = pcap.open_offline(child.stdout)
        seen = []
        pd.loop(lambda data, *_: seen.append(data))
        pd.close()
        child.stdout.close()
        self.assertEqual(0, child.wait())
        self.assertEqual(FRAMES, seen)


class TestReading(PcapTest):
    def test_iterate(self):
        pd = pcap.open_offline(self.path)
        self.assertEqual([(frame, 1000.25 + idx, len(frame)) for idx, frame in enumerate(FRAMES)], list(pd))
        # at the end of the file
        self.assertEqual([], list(pd))

    def test_iteration_interleaves_with_next(self):
        pd = pcap.open_offline(self.path)
        packet_iter = iter(pd)
        self.assertEqual(FRAMES[0], next(packet_iter)[0])
        self.assertEqual(FRAMES[1], pd.next()[0])
        self.assertEqual(FRAMES[2], next(packet_iter)[0])

    def test_iteration_respects_filter_and_close(self):
        pd = self.open(MIXED)
        pd.setfilter('udp port 53')
        packet_iter = iter(pd)
        self.assertEqual(MIXED[0], next(packet_iter)[0])
        pd.close()
        with self.assertRaisesRegex(pcap.error, 'invalid handle'):
            next(packet_iter)

    def test_dispatch(self):
        pd = pcap.open_offline(self.path)
        seen = []
        self.assertEqual(2, pd.dispatch(lambda *args: seen.append(args), 2, 'extra'))
        self.assertEqual(1, pd.dispatch(lambda *args: seen.append(args)))
        self.assertEqual(0, pd.dispatch(lambda *args: seen.append(args)))
        self.assertEqual([(f, 1000.25 + i, len(f)) + (('extra',) if i < 2 else ()) for i, f in enumerate(FRAMES)], seen)

    def test_dispatch_into_dumper(self):
        out = self.tmp_path('copy.pcap')
        pd = pcap.open_offline(self.path)
        with pd.dump_open(out) as dumper:
            self.assertEqual(len(FRAMES), pd.dispatch(dumper))
        self.assertEqual(read_pcap(self.path), read_pcap(out))

    def test_dispatch_stops(self):
        def fail(*args):
            raise ValueError('stop')
        with self.assertRaisesRegex(ValueError, 'stop'):
            pcap.open_offline(self.path).dispatch(fail)

        pd = pcap.open_offline(self.path)
        seen = []
        def stop(data, *args):
            seen.append(data)
            if 2 == len(seen):
                pd.breakloop()
        self.assertEqual(2, pd.dispatch(stop))

    @unittest.skipIf(sys.platform == 'win32', 'no selectable descriptors on Windows')
    def test_select_then_dispatch(self):
        # a capture from a pipe: select() reports it readable only once a packet is written
        (rfd, wfd) = os.pipe()
        os.write(wfd, pcap_bytes([]))
        try:
            pd = pcap.open_offline(rfd)
            fd = pd.fileno()
            self.assertIsNone(pd.get_required_select_timeout())
            self.assertEqual([], select.select([fd], [], [], 0)[0])
            os.write(wfd, pcap_bytes(FRAMES[:1])[24:])
            self.assertEqual([fd], select.select([fd], [], [], 5)[0])
            seen = []
            self.assertEqual(1, pd.dispatch(lambda data, *_: seen.append(data), 1))
            self.assertEqual(FRAMES[:1], seen)
            pd.close()
        finally:
            os.close(rfd)
            os.close(wfd)

    @unittest.skipIf(sys.platform == 'win32', 'POSIX signals')
    def test_sigint_in_callback(self):
        seen = []
        def callback(data, *args):
            seen.append(data)
            signal.raise_signal(signal.SIGINT)
        with self.assertRaises(KeyboardInterrupt):
            pcap.open_offline(self.path).loop(callback)
        self.assertEqual(FRAMES[:1], seen)
        # Python's own SIGINT handling is back once the loop has returned
        with self.assertRaises(KeyboardInterrupt):
            signal.raise_signal(signal.SIGINT)

    def interrupt_blocked(self, read, frames):
        '''
        reads from a pipe that stalls after frames, so read(pd) blocks until
        another thread sends SIGINT; that thread only runs if read() released
        the GIL. Returns what was read before the interrupt.
        '''
        (rfd, wfd) = os.pipe()
        os.write(wfd, pcap_bytes(frames))
        main = threading.get_ident()
        done = threading.Event()

        def interrupt():
            time.sleep(0.3)
            signal.pthread_kill(main, signal.SIGINT)
            # if the read is still blocked, end the capture so the test fails instead of hanging
            if not done.wait(5):
                os.close(wfd)

        thread = threading.Thread(target=interrupt)
        seen = []
        try:
            pd = pcap.open_offline(rfd)
            thread.start()
            with self.assertRaises(KeyboardInterrupt):
                read(pd, seen)
            pd.close()
        finally:
            done.set()
            thread.join()
            os.close(rfd)
            try:
                os.close(wfd)
            except OSError:
                pass
        return seen

    @unittest.skipIf(sys.platform == 'win32', 'needs pthread_kill')
    def test_sigint_interrupts_blocked_loop(self):
        seen = self.interrupt_blocked(lambda pd, seen: pd.loop(lambda data, *_: seen.append(data)), FRAMES[:1])
        self.assertEqual(FRAMES[:1], seen)

    @unittest.skipIf(sys.platform == 'win32', 'needs pthread_kill')
    def test_sigint_interrupts_blocked_read(self):
        for (name, read) in [('next', lambda pd, seen: pd.next()), ('iteration', lambda pd, seen: list(pd))]:
            with self.subTest(name):
                self.interrupt_blocked(read, [])

    @unittest.skipIf(sys.platform == 'win32', 'POSIX signals')
    def test_sigint_ignored(self):
        # nothing is hooked while SIGINT is ignored, so a capture runs on regardless
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            seen = []
            def callback(data, *args):
                seen.append(data)
                signal.raise_signal(signal.SIGINT)
            pcap.open_offline(self.path).loop(callback)
            self.assertEqual(FRAMES, seen)
        finally:
            signal.signal(signal.SIGINT, previous)


@unittest.skipUnless(pcap is not None and sys.platform == 'win32', 'Npcap only')
class TestNpcap(PcapTest):
    # Npcap's rpcap active mode; never run, since CI can't install Npcap

    def test_remoteact_without_connections(self):
        self.assertEqual([], pcap.remoteact_list())
        with self.assertRaises(pcap.error):
            pcap.remoteact_close('192.0.2.1')
        self.assertIsNone(pcap.remoteact_cleanup())  # nothing is waiting

    def test_remoteact_cleanup_stops_accept(self):
        errors = []

        def accept():
            try:
                pcap.remoteact_accept('127.0.0.1', '0')
            except pcap.error as e:
                errors.append(str(e))

        thread = threading.Thread(target=accept)
        thread.start()
        # cleanup only stops an accept that is already listening, so repeat it
        deadline = time.monotonic() + 10
        while thread.is_alive() and time.monotonic() < deadline:
            pcap.remoteact_cleanup()
            thread.join(0.1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(['remoteact_accept() was stopped by remoteact_cleanup()'], errors)


STUB = os.path.join(ROOT, 'pckt', 'pcap.pyi')
# dunders compared between the stub and the module; others such as __init__ aren't
DUNDERS = {'__enter__', '__exit__', '__iter__', '__next__', '__len__', '__getitem__'}


def stub_platform(test):
    # the stub branches only on `sys.platform == "..."` and `!=`
    assert 'sys.platform' == ast.unparse(test.left), ast.unparse(test)
    value = test.comparators[0].value
    return sys.platform == value if isinstance(test.ops[0], ast.Eq) else sys.platform != value


def stub_names(body):
    names = {}
    for node in body:
        if isinstance(node, ast.If):
            names.update(stub_names(node.body if stub_platform(node.test) else node.orelse))
        elif isinstance(node, ast.AnnAssign):
            names[node.target.id] = node
        elif isinstance(node, ast.Assign):
            names.update((target.id, node) for target in node.targets)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names[node.name] = node
    return names


def compared(names):
    return {name for name in names if not name.startswith('_') or name in DUNDERS}


@unittest.skipIf(pcap is None, 'pckt.pcap not built (python3 setup.py build_ext --inplace)')
class TestStub(unittest.TestCase):
    def test_stub_matches_module(self):
        with open(STUB) as f:
            stub = stub_names(ast.parse(f.read()).body)
        self.assertEqual(compared(dir(pcap)), compared(stub))
        for name, node in stub.items():
            if isinstance(node, ast.ClassDef) and not name.startswith('_') and 'error' != name:
                self.assertEqual(compared(vars(getattr(pcap, name))), compared(stub_names(node.body)), name)


if '__main__' == __name__:
    unittest.main()
