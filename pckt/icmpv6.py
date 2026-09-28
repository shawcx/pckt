
import socket
import struct

from .layer import Layer, checksum, mac

class ICMPv6(Layer):
    '''
    Generic ICMPv6 message; the body after the checksum is the payload.
    The checksum covers a pseudo header, so it needs an enclosing IPv6
    layer, otherwise it is 0.
    '''

    IP_PROTO = 0x3a

    # neighbor discovery option types
    SOURCE_LLADDR = 1
    TARGET_LLADDR = 2

    FIELDS = (
        ('type', 0),
        ('code', 0),
        ('crc',  None),
    )

    @staticmethod
    def lladdr_option(kind, addr):
        '''neighbor discovery source/target link-layer address option'''
        return struct.pack('!BB6s', kind, 1, mac(addr))

    @classmethod
    def subclass_for(cls, data):
        if cls is ICMPv6 and data:
            return {
                128 : ICMPv6_EchoRequest,
                129 : ICMPv6_EchoReply,
                135 : ICMPv6_NeighborSolicit,
                136 : ICMPv6_NeighborAdvert,
                }.get(data[0], ICMPv6)
        return cls

    def unpack(self, pkt):
        (self.type, self.code, self.crc) = struct.unpack('!BBH', pkt[:4])
        return pkt[4:]

    def header(self, crc):
        return struct.pack('!BBH', self.type, self.code, crc)

    def build(self, data, outer):
        crc = self.crc
        if crc is None:
            crc = 0
            if hasattr(outer, 'pseudo_header'):
                message = self.header(0) + data
                crc = checksum(outer.pseudo_header(ICMPv6.IP_PROTO, len(message)) + message)
        return self.header(crc) + data

class ICMPv6_EchoReply(ICMPv6):
    FIELDS = (
        ('type', 129),
        ('code', 0),
        ('crc',  None),
        ('id',   0),
        ('seq',  0),
    )

    def unpack(self, pkt):
        (self.type, self.code, self.crc, self.id, self.seq) = struct.unpack('!BBHHH', pkt[:8])
        return pkt[8:]

    def header(self, crc):
        return struct.pack('!BBHHH', self.type, self.code, crc, self.id, self.seq)

class ICMPv6_EchoRequest(ICMPv6_EchoReply):
    FIELDS = (
        ('type', 128),
        ('code', 0),
        ('crc',  None),
        ('id',   0),
        ('seq',  0),
    )

class ICMPv6_NeighborSolicit(ICMPv6):
    '''options (e.g. ICMPv6.lladdr_option(...)) go in the payload'''

    FIELDS = (
        ('type',     135),
        ('code',     0),
        ('crc',      None),
        ('reserved', 0),
        ('target',   '::'),
    )

    def unpack(self, pkt):
        (self.type, self.code, self.crc, self.reserved, target) = struct.unpack('!BBHI16s', pkt[:24])
        self.target = socket.inet_ntop(socket.AF_INET6, target)
        return pkt[24:]

    def header(self, crc):
        return struct.pack('!BBHI16s', self.type, self.code, crc, self.reserved, socket.inet_pton(socket.AF_INET6, self.target))

class ICMPv6_NeighborAdvert(ICMPv6):
    '''options (e.g. ICMPv6.lladdr_option(...)) go in the payload'''

    # bits of the flags field
    ROUTER    = 0x80000000
    SOLICITED = 0x40000000
    OVERRIDE  = 0x20000000

    FIELDS = (
        ('type',   136),
        ('code',   0),
        ('crc',    None),
        ('flags',  0),
        ('target', '::'),
    )

    def unpack(self, pkt):
        (self.type, self.code, self.crc, self.flags, target) = struct.unpack('!BBHI16s', pkt[:24])
        self.target = socket.inet_ntop(socket.AF_INET6, target)
        return pkt[24:]

    def header(self, crc):
        return struct.pack('!BBHI16s', self.type, self.code, crc, self.flags, socket.inet_pton(socket.AF_INET6, self.target))
