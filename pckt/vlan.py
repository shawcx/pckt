
import struct

from .layer import Layer
from .llc import LLC

class VLAN(Layer):
    '''802.1Q tag; sits between Ethernet and the tagged payload'''

    ETHERTYPE = 0x8100

    FIELDS = (
        ('prio',  0),
        ('dei',   0),
        ('id',    1),
        ('proto', None), # payload's ETHERTYPE, or its length if it's LLC
    )

    def unpack(self, pkt):
        (tci, self.proto) = struct.unpack('!HH', pkt[:4])
        self.prio = tci >> 13
        self.dei = (tci >> 12) & 0x1
        self.id = tci & 0xfff
        if self.proto <= LLC.MAX_LENGTH:
            # drop any padding past the length
            return pkt[4:4 + self.proto]
        return pkt[4:]

    def next_layer(self):
        if self.proto <= LLC.MAX_LENGTH:
            return LLC
        return Layer.lookup('ETHERTYPE', self.proto)

    def build(self, data, outer):
        proto = self.proto
        if proto is None:
            proto = len(data) if isinstance(self.payload, LLC) else getattr(self.payload, 'ETHERTYPE', 0)
        tci = (self.prio << 13) | (self.dei << 12) | self.id
        return struct.pack('!HH', tci, proto) + data

    def _fmt(self, name, value):
        if 'proto' == name and value is not None:
            return '0x%.4x' % value
        return Layer._fmt(self, name, value)
