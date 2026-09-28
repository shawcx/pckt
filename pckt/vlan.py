
import struct

from .layer import Layer

class VLAN(Layer):
    '''802.1Q tag; sits between Ethernet and the tagged payload'''

    ETHERTYPE = 0x8100

    FIELDS = (
        ('prio',  0),
        ('dei',   0),
        ('id',    1),
        ('proto', None), # payload's ETHERTYPE
    )

    def unpack(self, pkt):
        (tci, self.proto) = struct.unpack('!HH', pkt[:4])
        self.prio = tci >> 13
        self.dei = (tci >> 12) & 0x1
        self.id = tci & 0xfff
        return pkt[4:]

    def next_layer(self):
        return Layer.lookup('ETHERTYPE', self.proto)

    def build(self, data, outer):
        proto = self.proto
        if proto is None:
            proto = getattr(self.payload, 'ETHERTYPE', 0)
        tci = (self.prio << 13) | (self.dei << 12) | self.id
        return struct.pack('!HH', tci, proto) + data

    def _fmt(self, name, value):
        if 'proto' == name and value is not None:
            return '0x%.4x' % value
        return Layer._fmt(self, name, value)
