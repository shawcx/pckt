
import struct
from random import randrange

from .layer import Layer, checksum

class UDP(Layer):
    IP_PROTO = 0x11

    FIELDS = (
        ('src', None), # from the payload's udp_ports(), otherwise 0
        ('dst', None),
        ('len', None), # header + payload
        ('crc', None), # needs an enclosing IP layer, otherwise 0 (none)
    )

    def randomize(self):
        self.src = randrange(65536)
        self.dst = randrange(65536)

    def unpack(self, pkt):
        ( self.src,
          self.dst,
          self.len,
          self.crc
          ) = struct.unpack('!4H', pkt[0:8])

        # drop anything past the datagram
        end = self.len if self.len >= 8 else len(pkt)
        return pkt[8:end]

    def next_layer(self):
        return Layer.lookup('UDP_PORTS', self.dst) or Layer.lookup('UDP_PORTS', self.src)

    def build(self, data, outer):
        (src, dst) = (self.src, self.dst)
        if src is None or dst is None:
            ports = self.payload.udp_ports() if hasattr(self.payload, 'udp_ports') else (0, 0)
            src = ports[0] if src is None else src
            dst = ports[1] if dst is None else dst

        length = self.len
        if length is None:
            length = 8 + len(data)

        crc = self.crc
        if crc is None:
            crc = 0
            if hasattr(outer, 'pseudo_header'):
                hdr = struct.pack('!4H', src, dst, length, 0)
                # 0 means "no checksum", so a computed 0 is sent as 0xffff
                crc = checksum(outer.pseudo_header(UDP.IP_PROTO, length) + hdr + data) or 0xffff

        return struct.pack('!4H', src, dst, length, crc) + data
