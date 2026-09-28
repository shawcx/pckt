#!/usr/bin/env python3
'''
Pretend to be a host on the local network: answer ARP and ping for an IPv4
address that is either given or leased from a DHCP server.

    sudo python3 -m pckt.stack.ghost               # list devices
    sudo python3 -m pckt.stack.ghost eth0 [--mac 02:00:00:00:00:01] [--ip 10.0.0.66]
'''

import argparse
import logging
import random
import socket
import struct

from pckt import pcap, mac, Ethernet, ARP, IP, ICMP, ICMP_EchoRequest, ICMP_EchoReply, UDP, DHCP

BROADCAST = b'\xff' * 6

log = logging.getLogger(__name__)


def random_mac():
    # locally administered unicast
    return bytes([0x02] + [random.randrange(256) for x in range(5)])


class Ghost:
    def __init__(self, pd, mac, ip=None):
        '''pd is an open pcap handle (anything with next/sendpacket/close)'''
        self.pd = pd
        self.mac = mac
        self.ip = ip
        self.xid = random.randrange(2**32)
        self.requested = False

    def run(self):
        if self.ip is None:
            self.dhcp(DHCP.DISCOVER)

        # next() returns on the capture timeout, so Ctrl-C is handled promptly
        try:
            while True:
                result = self.pd.next()
                if result:
                    self.inbound(result[0])
        except KeyboardInterrupt:
            pass
        finally:
            self.pd.close()

    def send(self, pkt):
        log.info('> %r', pkt)
        self.pd.sendpacket(pkt.pack())

    def inbound(self, data):
        try:
            pkt = Ethernet.decode(data)
        except struct.error:
            return

        if pkt.dst not in (self.mac, BROADCAST):
            return

        if ARP in pkt:
            self.on_arp(pkt[ARP])
        elif DHCP in pkt:
            self.on_dhcp(pkt[DHCP])
        elif ICMP_EchoRequest in pkt:
            self.on_ping(pkt)

    def on_arp(self, arp):
        if ARP.REQUEST == arp.op and self.ip is not None and arp.dst_ip == self.ip:
            log.info('< %r', arp)
            self.send(
                Ethernet(dst=arp.src_mac, src=self.mac) /
                ARP(op=ARP.REPLY, src_mac=self.mac, src_ip=self.ip, dst_mac=arp.src_mac, dst_ip=arp.src_ip)
                )

    def on_ping(self, pkt):
        (ip, echo) = (pkt[IP], pkt[ICMP])
        if ip.dst != self.ip:
            return
        log.info('< %r', ip)
        reply = Ethernet(dst=pkt.src, src=self.mac) / IP(src=self.ip, dst=ip.src) / ICMP_EchoReply(id=echo.id, seq=echo.seq)
        if echo.payload is not None:
            reply = reply / echo.payload
        self.send(reply)

    def dhcp(self, message_type, offer=None):
        options = [(DHCP.MESSAGE_TYPE, bytes([message_type]))]
        if offer is not None:
            options.append((DHCP.REQUESTED_IP, socket.inet_aton(offer.yourip)))
            server = offer.option(DHCP.SERVER_ID)
            if server:
                options.append((DHCP.SERVER_ID, server))
        options.append((DHCP.PARAMETER_LIST, bytes([DHCP.SUBNET_MASK, DHCP.ROUTER, DHCP.DNS])))

        # ask for broadcast replies since this address isn't known to anyone yet
        self.send(
            Ethernet(dst=BROADCAST, src=self.mac) /
            IP(src='0.0.0.0', dst='255.255.255.255') /
            UDP() /
            DHCP(transid=self.xid, clientmac=self.mac, bootpflags=0x8000, options=options)
            )

    def on_dhcp(self, msg):
        if DHCP.BOOTREPLY != msg.type or self.xid != msg.transid:
            return

        log.info('< %r', msg)
        kind = msg.option(DHCP.MESSAGE_TYPE, b'\x00')[0]

        if DHCP.OFFER == kind and not self.requested:
            self.requested = True
            self.dhcp(DHCP.REQUEST, msg)
        elif DHCP.ACK == kind and self.requested:
            self.ip = msg.yourip
            log.warning('bound to %s', self.ip)
        elif DHCP.NAK == kind:
            log.warning('DHCP NAK, starting over')
            self.requested = False
            self.xid = random.randrange(2**32)
            self.dhcp(DHCP.DISCOVER)


def main():
    parser = argparse.ArgumentParser(description='Answer ARP and ping as a fake host.')
    parser.add_argument('device', nargs='?', help='capture device; lists devices when omitted')
    parser.add_argument('--mac', help='default: random locally administered address')
    parser.add_argument('--ip', help='default: lease one with DHCP')
    parser.add_argument('-q', '--quiet', action='store_true', help='only log address changes')
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING if args.quiet else logging.INFO, format='%(message)s')

    devices = pcap.findalldevs()

    if args.device is None:
        for (name, info) in sorted(devices.items()):
            addr = ':'.join('%.2x' % o for o in info.get('mac', b''))
            print(' %-16s %-17s %s' % (name, addr, info.get('ip', '')))
        return

    if args.device not in devices:
        parser.error('unknown device: %s' % args.device)

    # a short timeout so next() returns regularly
    pd = pcap.open_live(args.device, 65535, True, 100)
    # only capture inbound packets; does nothing on windows
    pd.setdirection(pcap.D_IN)

    Ghost(pd, mac(args.mac) if args.mac else random_mac(), args.ip).run()


if '__main__' == __name__:
    main()
