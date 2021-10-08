
import os
import subprocess as subp

import pypcap
import packetio

#interfaces = pypcap.find()
#list(interfaces.keys())

if False:
    def next_win32(self):
        if subp.WAIT_OBJECT_0 != subp.WaitForSingleObject(self.pd.getevent(), 1000):
            return None
        return self.pd.next()

    def next_linux(self):
        if beaker.skt.timeout(self.pd, 1.0):
            return None
        return self.pd.next()

    def next_file(self):
        return self.pd.next()

    def run(self):
        if pypcap.version().startswith('WinPcap'):
            self.next = self.next_win32
        else:
            self.next = self.next_linux

        if self.interface.startswith('file:'):
            self.next = self.next_file
            try:
                self.pd = pypcap.open_file(self.interface[5:])
            except:
                logging.warn('Could not open file %s', repr(self.interface))
                return False
        else:
            try:
                self.pd = pypcap.open_live(self.interface)
            except:
                logging.warn('Could not open interface %s', repr(self.interface))
                return False

        while not self.should_stop():
            try:
                packet = self.next()
            except:
                loggin.error('Error reading from PCAP')
                self.stop()
                continue

            if None == packet:
                continue

            ethernet = packetio.Ethernet()
            length = ethernet.unpack(packet)

            packet = packet[length:]

            fields = {}

            fields['mac'] = ':'.join('%.2X' % d for d in ethernet.src)

            #print('-----------------------------')
            #print(fields)
            #print('%.4X' % ethernet.proto)

            if ethernet.ETHERNET_IP == ethernet.proto:
                self.ParseIP(packet, fields)
            elif ethernet.ETHERNET_ARP == ethernet.proto:
                #print('ARP ---------------------')
                #hexdump(packet)
                self.ParseARP(packet, fields)

            if 'ip' not in fields:
                continue

            if '0' == fields['ip'][0]:
                continue

            self.queue.put('HOST:' + ' '.join('%s="%s"' % p for p in fields.items()))

    def ParseARP(self, packet, fields):
        arp = packetio.ARP()
        length = arp.unpack(packet)
        fields['mac'] = ':'.join('%.2X' % d for d in arp.src_mac)
        fields['ip']  = '.'.join('%d'   % d for d in arp.src_ip)

    def ParseIP(self, packet, fields):
        ip = packetio.IP()
        length = ip.unpack(packet)
        packet = packet[length:]

        fields['ip'] = '.'.join('%d' % d for d in ip.src)

        if ip.IP_UDP == ip.proto:
            self.ParseUDP(packet, fields)

    def ParseUDP(self, packet, fields):
        udp = packetio.UDP()
        length = udp.unpack(packet)
        packet = packet[length:]

        if udp.src == 68 and udp.dst == 67:
            self.ParseDHCP(packet, fields)

    def ParseDHCP(self, packet, fields):
        fields['mac'] = ':'.join('%.2X' % d for d in packet[28:34])

        packet = packet[240:]

        # TODO: stop assuming all microsoft dhcp clients send MSFT in option 60
        #fields['os'] = 'linux'

        while True:
            if not packet or packet[0] == 0xff:
                break
            option = packet[0]
            length = packet[1]
            value = packet[2:2+length]

            if 50 == option:
                fields['ip'] = '.'.join('%d' % d for d in value)
            elif 12 == option:
                fields['name'] = value
            elif 60 == option:
                if value.startswith('MSFT'):
                    fields['os'] = 'windows'

            #print(option, repr(value))
            packet = packet[2+length:]
