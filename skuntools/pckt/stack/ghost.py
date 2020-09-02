#!/usr/bin/env python3

import sys
import time
import random
import socket

try:
    import pypcap
except:
    print('Missing module: pypcap')
    sys.exit(-1)

import pckt


class GhostAdapter:
    @staticmethod
    def GetDevices():
        return pypcap.find()

    def __init__(self, dev, settings=None):
        self.device = dev

        if settings:
            # split on ':', convert string to integer to byte and join
            self.mac  = ''.join(chr(int(o,16)) for o in settings['mac'].split(':', 6))
            #self.ip   = socket.inet_aton(settings['ip'])
            #self.mask = socket.inet_aton(settings['netmask'])
            self.ip   = settings['ip']
            self.mask = settings['netmask']
            print(settings)
            action = self.Loop
        else:
            self.mac  = b'\x22\x33\x44\x55\x66\x77'
            self.ip   = '0.0.0.0'
            self.mask = '255.255.255.255'
            action = self.DHCP

        self.pd = pypcap.open_live(self.device, 2048, False, 100)

        # only capture in bound packets; does nothing on windows
        self.pd.setdirection(pypcap.D_IN)

        # for windows, ignore when our mac addr is the src
        #self.pd.setfilter('ether src not ' + settings['mac'])

        # pre-allocate some classes
        self.ethout = pckt.ethernet()
        self.arpin  = pckt.arp()
        self.arpout = pckt.arp()
        self.ipin   = pckt.ip()
        self.ipout  = pckt.ip()
        self.icmpin = pckt.icmp()

        self.udpin  = pckt.udp()
        self.udpout = pckt.udp()

        # call DHCP or Loop
        action()

    def DHCP(self):
        self.ethout.dst = b'\xff\xff\xff\xff\xff\xff'
        self.ethout.src = self.mac
        self.ethout.proto = pckt.ETHERNET_IP

        self.ipout.src = '0.0.0.0'
        self.ipout.dst = '255.255.255.255'
        self.ipout.proto = pckt.IP_UDP

        self.udpout.src = 68
        self.udpout.dst = 67

        dhcp = pckt.layer7.DHCP_Request()
        dhcp.clientmac = self.mac

        dhcp.pack()

        pkt = dhcp.pack()

        print(repr(pkt))

        pkt = self.udpout.pack(pkt)
        pkt = self.ipout.pack(pkt)
        pkt = self.ethout.pack(pkt)

        self.Outbound(pkt)

        self.Loop()

    def Loop(self):
        self.pd.loop(self.Inbound)
        self.pd.close()

    def Outbound(self, pkt):
        print('Sending')
        self.pd.inject(pkt)

    def Inbound(self, pkt):
        pkt = pckt.ethernet(pkt)

        # make assumptions about return packets
        self.ethout.dst  = pkt.src
        self.ethout.src  = self.mac
        self.ethout.type = pkt.type

        if 0x0800 == pkt.type:
            self.HandleIP(pkt.ip)
        elif 0x0806 == pkt.type:
            self.HandleARP(pkt)

    def HandleIP(self, pkt):
        self.ipout.dst   = pkt.src
        self.ipout.src   = self.ip
        self.ipout.proto = pkt.proto

        if 1 == pkt.proto:
            self.HandleICMP(pkt.layer4)
        elif 6 == pkt.proto:
            self.HandleTCP(pkt.layer4)
        elif 17 == pkt.proto:
            self.HandleUDP(pkt.layer4)
        else:
            print('Unknown proto:', pkt.proto)

    def HandleTCP(self, pkt):
        #print 'TCP'
        pass

    def HandleUDP(self, pkt):
        #print 'UDP'
        pass

    def HandleICMP(self, pkt):
        if 0 == pkt.type:
            icmp = pckt.ICMP_EchoReply(self.icmpin)
        elif 8 == pkt.type:
            icmp = pckt.ICMP_EchoRequest(self.icmpin)
            resp = pckt.ICMP_EchoReply(icmp)
            resp.type = 0
            #print icmp, resp

            self.Outbound(self.ethout.pack(self.ipout.pack(resp.pack(pkt))))
        else:
            print('Unknown ICMP:', self.icmpin)

    def HandleARP(self, pkt):
        pkt = self.arpin.unpack(pkt)

        # ARP REQUEST
        if 0x0001 == self.arpin.op:
            if self.arpin.dst_ip == self.ip:
                # constrcut REPLY
                self.arpout = pckt.arp()
                self.arpout.op = 0x0002
                self.arpout.dst_mac = self.arpin.src_mac
                self.arpout.dst_ip  = self.arpin.src_ip
                self.arpout.src_mac = self.mac
                self.arpout.src_ip  = self.ip

                print(self.ethout)
                print(self.arpout)

                self.Outbound(self.ethout.pack(self.arpout.pack()))


if '__main__' == __name__:
    devices = GhostAdapter.GetDevices()

    if 1 == len(sys.argv):
        print(' Usage:', sys.argv[0], '<adapter>')
        print()
        print(' Devices ')
        print('=' * 40)
        for device in devices:
            mac = pypcap.mac(device)
            mac = ':'.join('%.2x' % o for o in mac)
            print(' %-8s|' % (device), mac, devices[device].get('ip', ''))
        print()
        sys.exit(0)

    device = sys.argv[1]

    if device not in devices:
        print('Error: invalid device: %s' % device)
        sys.exit(-1)

    if True:
        settings = {
            'mac'     : '00:22:44:66:88:aa',
            'ip'      : '10.25.0.66',
            'netmask' : '255.255.255.0',
            }
    else:
        settings = None

    ghost = GhostAdapter(device, settings)
