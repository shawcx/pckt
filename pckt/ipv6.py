
import socket
import struct

from .layer import Layer

class IPv6(Layer):
    '''IPv6 fixed header; extension headers are not decoded (left as payload bytes)'''

    ETHERTYPE = 0x86dd

    # next header value when there is no (known) payload
    NO_NEXT_HEADER = 59

    FIELDS = (
        ('ver',  6),
        ('tc',   0),
        ('flow', 0),
        ('plen', None), # payload length
        ('nh',   None), # payload's IP_PROTO
        ('hlim', 255),  # neighbor discovery requires 255
        ('src',  '::'),
        ('dst',  'ff02::1'),
    )

    def unpack(self, pkt):
        ( vtf,
          self.plen,
          self.nh,
          self.hlim,
          self.src,
          self.dst
          ) = struct.unpack('!IHBB16s16s', pkt[:40])

        self.ver = vtf >> 28
        self.tc = (vtf >> 20) & 0xff
        self.flow = vtf & 0xfffff

        self.src = socket.inet_ntop(socket.AF_INET6, self.src)
        self.dst = socket.inet_ntop(socket.AF_INET6, self.dst)

        # drop ethernet padding; a 0 length is a jumbogram
        end = 40 + self.plen if self.plen else len(pkt)
        return pkt[40:end]

    def next_layer(self):
        return Layer.lookup('IP_PROTO', self.nh)

    def pseudo_header(self, proto, length):
        '''TCP/UDP/ICMPv6 checksum pseudo header'''
        return struct.pack(
                '!16s16sI3xB',
                socket.inet_pton(socket.AF_INET6, self.src),
                socket.inet_pton(socket.AF_INET6, self.dst),
                length,
                proto
                )

    def build(self, data, outer):
        plen = self.plen
        if plen is None:
            plen = len(data)

        nh = self.nh
        if nh is None:
            nh = getattr(self.payload, 'IP_PROTO', IPv6.NO_NEXT_HEADER)

        return struct.pack(
                '!IHBB16s16s',
                (self.ver << 28) | (self.tc << 20) | self.flow,
                plen,
                nh,
                self.hlim,
                socket.inet_pton(socket.AF_INET6, self.src),
                socket.inet_pton(socket.AF_INET6, self.dst)
                ) + data
