
import struct
from random import randrange

from .layer import Layer, mac

class Ethernet(Layer):
    PROTOS = {
        0x0800 : 'IP',
        0x0806 : 'ARP',
        0x8035 : 'RARP',
        0x8100 : 'VLAN',
        0x86dd : 'IPv6',
        0x88cc : 'LLDP',
    }

    IP   = 0x0800
    ARP  = 0x0806
    RARP = 0x8035
    VLAN = 0x8100
    IPv6 = 0x86dd
    LLDP = 0x88cc

    FIELDS = (
        ('dst',   b'\xff\xff\xff\xff\xff\xff'),
        ('src',   b'\x00\x00\x00\x00\x00\x00'),
        ('proto', None), # payload's ETHERTYPE
    )
    MAC_FIELDS = ('dst', 'src')

    def randomize(self):
        self.dst = b'\xff' * 6
        self.src = bytes(randrange(256) for x in range(6))
        self.proto = list(Ethernet.PROTOS)[randrange(len(Ethernet.PROTOS))]

    def unpack(self, pkt):
        (self.dst,self.src,self.proto) = struct.unpack('!6s6sH', pkt[:14])
        return pkt[14:]

    def next_layer(self):
        return Layer.lookup('ETHERTYPE', self.proto)

    def build(self, data, outer):
        proto = self.proto
        if proto is None:
            proto = getattr(self.payload, 'ETHERTYPE', 0)
        return struct.pack('!6s6sH', mac(self.dst), mac(self.src), proto) + data

    def _fmt(self, name, value):
        if 'proto' == name and value is not None:
            return '0x%.4x (%s)' % (value, Ethernet.PROTOS.get(value, 'unknown'))
        return Layer._fmt(self, name, value)
