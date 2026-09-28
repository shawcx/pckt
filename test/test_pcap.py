#!/usr/bin/env python3

import os
import struct
import subprocess
import sys
import tempfile
import textwrap
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


def write_pcap(path, frames, wirelen_extra=0):
    with open(path, 'wb') as f:
        # pcap file header: magic, version 2.4, tz, sigfigs, snaplen, ethernet
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for idx, frame in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + idx, 250000, len(frame), len(frame) + wirelen_extra) + frame)


@unittest.skipIf(pcap is None, 'pckt.pcap not built (python3 setup.py build_ext --inplace)')
class TestPcap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, 'test.pcap')
        write_pcap(self.path, FRAMES)

    def tearDown(self):
        self.tmp.cleanup()

    def test_findalldevs(self):
        devices = pcap.findalldevs()
        self.assertIsInstance(devices, dict)
        for name, info in devices.items():
            self.assertIsInstance(name, str)
            if 'mac' in info:
                self.assertIsInstance(info['mac'], bytes)
            if 'ip' in info:
                self.assertIsInstance(info['ip'], str)

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
        pcap.open_offline(self.path).loop(lambda data, ts, wirelen: seen.append(data), 2)
        self.assertEqual(FRAMES[:2], seen)

    def test_loop_decode(self):
        ports = []
        pcap.open_offline(self.path).loop(lambda data, *_: ports.append(Ethernet.decode(data)[IP].payload.dst))
        self.assertEqual([2, 4, 6], ports)

    def test_callback_exception(self):
        def fail(*args):
            raise ValueError('from callback')
        with self.assertRaisesRegex(ValueError, 'from callback'):
            pcap.open_offline(self.path).loop(fail)

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

    def test_filter(self):
        pd = pcap.open_offline(self.path)
        pd.setfilter('tcp')
        seen = []
        pd.loop(lambda data, *_: seen.append(data))
        self.assertEqual([FRAMES[1]], seen)
        with self.assertRaises(pcap.error):
            pd.setfilter('not a (valid filter')

    def test_closed(self):
        pd = pcap.open_offline(self.path)
        pd.close()
        for call in (pd.next, pd.datalink, lambda: pd.loop(print), lambda: pd.sendpacket(b'x')):
            with self.assertRaises(pcap.error):
                call()

    def test_open_errors(self):
        with self.assertRaises(pcap.error):
            pcap.open_offline(os.path.join(self.tmp.name, 'missing.pcap'))
        with self.assertRaises(TypeError):
            pcap.open_offline(b'bytes path')

    def test_datalink(self):
        self.assertEqual((1, 'EN10MB', 'Ethernet'), pcap.open_offline(self.path).datalink())

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'needs a FIFO')
    def test_loop_releases_gil(self):
        # loop() blocks in libpcap reading a FIFO until another Python thread
        # writes the next packet, which deadlocks if loop() holds the GIL; run
        # it in a subprocess so a deadlock fails the test instead of hanging it
        script = textwrap.dedent('''
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
            ''')
        fifo = os.path.join(self.tmp.name, 'fifo')
        os.mkfifo(fifo)
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [os.path.dirname(os.path.dirname(pcap.__file__)), os.environ.get('PYTHONPATH')])))
        try:
            result = subprocess.run([sys.executable, '-c', script, fifo], capture_output=True, text=True, timeout=10, env=env)
        except subprocess.TimeoutExpired:
            self.fail('loop() held the GIL while blocked in libpcap')
        self.assertEqual('2', result.stdout.strip(), result.stderr)

if '__main__' == __name__:
    unittest.main()
