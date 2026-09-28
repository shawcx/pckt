#!/usr/bin/env python3
'''
End-to-end tests over a real veth pair, run in an unprivileged user + network
namespace (unshare -rn), so they need no root. The kernel's own ARP and ping
(and dnsmasq, if installed) are the peers:

    v0 10.0.0.1 (kernel, dnsmasq, passive mapper)  <==>  v1 (ghost)

Skipped when namespaces or the tools aren't available.
'''

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GHOST_MAC = '00:50:56:00:00:99'


def namespaces_work():
    if not all(shutil.which(tool) for tool in ('unshare', 'ip', 'ping')):
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


def wait_for(predicate, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return ''


def scenario(dhcp, tmp):
    '''runs inside the namespace; returns results for the test to check'''
    run = lambda *cmd: subprocess.run(cmd, check=True)
    run('ip', 'link', 'add', 'v0', 'type', 'veth', 'peer', 'name', 'v1')
    run('ip', 'link', 'set', 'v0', 'up')
    run('ip', 'link', 'set', 'v1', 'up')
    run('ip', 'addr', 'add', '10.0.0.1/24', 'dev', 'v0')

    env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [ROOT, os.environ.get('PYTHONPATH')])))
    procs = []
    def start(name, *cmd):
        out = open(os.path.join(tmp, name), 'w')
        proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, env=env)
        procs.append(proc)
        return proc

    results = {}
    try:
        if dhcp:
            start('dnsmasq', 'dnsmasq', '--no-daemon', '--conf-file=/dev/null', '--interface=v0', '--bind-interfaces',
                  '--port=0', '--dhcp-range=10.0.0.100,10.0.0.150,255.255.255.0,1h',
                  '--dhcp-leasefile=' + os.path.join(tmp, 'leases'), '--pid-file=' + os.path.join(tmp, 'dnsmasq.pid'),
                  '--user=root', '--group=root')
            passive = start('passive', sys.executable, '-m', 'pckt.mapping.passive', 'v0')
            ghost_args = []
        else:
            ghost_args = ['--ip', '10.0.0.66']

        ghost = start('ghost', sys.executable, '-m', 'pckt.stack.ghost', 'v1', '-q', '--mac', GHOST_MAC, *ghost_args)

        if dhcp:
            wait_for(lambda: 'bound to' in read(os.path.join(tmp, 'ghost')), 30)
            for line in read(os.path.join(tmp, 'ghost')).splitlines():
                if line.startswith('bound to '):
                    results['ip'] = line.split()[-1]
        else:
            # give it a moment to open the capture
            time.sleep(1)
            results['ip'] = '10.0.0.66'

        if 'ip' in results:
            ping = subprocess.run(['ping', '-c', '3', '-i', '0.3', '-W', '3', results['ip']], capture_output=True, text=True)
            results['ping'] = ping.returncode
            results['neighbor'] = subprocess.run(['ip', 'neigh', 'show', results['ip']], capture_output=True, text=True).stdout

        ghost.send_signal(signal.SIGINT)
        results['ghost_exit'] = ghost.wait(10)
        results['ghost_log'] = read(os.path.join(tmp, 'ghost'))

        if dhcp:
            wait_for(lambda: GHOST_MAC in read(os.path.join(tmp, 'passive')), 5)
            passive.send_signal(signal.SIGINT)
            passive.wait(10)
            results['passive'] = read(os.path.join(tmp, 'passive'))
            results['dnsmasq'] = read(os.path.join(tmp, 'dnsmasq'))
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    return results


@unittest.skipUnless(pcap_built(), 'pckt.pcap not built')
@unittest.skipUnless(namespaces_work(), 'needs unshare -rn (unprivileged namespaces), ip and ping')
class TestLive(unittest.TestCase):
    def run_scenario(self, dhcp):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                ['unshare', '-rn', sys.executable, os.path.abspath(__file__), 'dhcp' if dhcp else 'static', tmp],
                capture_output=True, text=True, timeout=90,
                )
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def test_static(self):
        result = self.run_scenario(dhcp=False)
        self.assertEqual(0, result['ping'], result['ghost_log'])
        self.assertIn(GHOST_MAC, result['neighbor'])
        self.assertEqual(0, result['ghost_exit'], result['ghost_log'])

    @unittest.skipUnless(shutil.which('dnsmasq'), 'needs dnsmasq')
    def test_dhcp(self):
        result = self.run_scenario(dhcp=True)
        self.assertIn('ip', result, result.get('dnsmasq'))
        self.assertTrue(result['ip'].startswith('10.0.0.'))
        self.assertEqual(0, result['ping'], result['ghost_log'])
        self.assertEqual(0, result['ghost_exit'], result['ghost_log'])

        # the mapper on the server side saw the kernel (ARP) and ghost (DHCP)
        lines = result['passive'].splitlines()
        self.assertTrue(any(GHOST_MAC in l and result['ip'] in l and 'Vmware' in l for l in lines), lines)
        self.assertTrue(any('10.0.0.1 ' in l for l in lines), lines)


if '__main__' == __name__:
    if 3 == len(sys.argv) and sys.argv[1] in ('static', 'dhcp'):
        print(json.dumps(scenario('dhcp' == sys.argv[1], sys.argv[2])))
    else:
        unittest.main()
