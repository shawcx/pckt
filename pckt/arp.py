
import socket
import struct
from random import randrange

from .layer import Layer, mac

class ARP(Layer):
    PROTOS = {
        0x0001 : 'ETH',
        0x0800 : 'IP',
    }

    OPS = {
        0x0001 : 'ARP REQUEST',
        0x0002 : 'ARP REPLY',
        0x0003 : 'RARP REQUEST',
        0x0004 : 'RARP REPLY',
    }

    ETHERTYPE = 0x0806

    FIELDS = (
        ('hw',        0x0001),
        ('proto',     0x0800),
        ('hwsize',    6),
        ('protosize', 4),
        ('op',        0),
        ('src_mac',   b'\x00\x00\x00\x00\x00\x00'),
        ('src_ip',    '0.0.0.0'),
        ('dst_mac',   b'\xff\xff\xff\xff\xff\xff'),
        ('dst_ip',    '255.255.255.255'),
    )
    MAC_FIELDS = ('src_mac', 'dst_mac')

    def randomize(self):
        self.src_mac = bytes(randrange(256) for x in range(6))
        self.src_ip = '.'.join(str(randrange(256)) for x in range(4))
        self.dst_mac = b'\xff\xff\xff\xff\xff\xff'
        self.dst_ip = '255.255.255.255'

    def unpack(self, pkt):
        ( self.hw,
          self.proto,
          self.hwsize,
          self.protosize,
          self.op,
          self.src_mac,
          self.src_ip,
          self.dst_mac,
          self.dst_ip
          ) = struct.unpack('!HHBBH6s4s6s4s', pkt[0:28])

        self.src_ip = socket.inet_ntoa(self.src_ip)
        self.dst_ip = socket.inet_ntoa(self.dst_ip)

        return pkt[28:]

    def build(self, data, outer):
        return struct.pack(
                    '!HHBBH6s4s6s4s',
                    self.hw,
                    self.proto,
                    self.hwsize,
                    self.protosize,
                    self.op,
                    mac(self.src_mac),
                    socket.inet_aton(self.src_ip),
                    mac(self.dst_mac),
                    socket.inet_aton(self.dst_ip)
                    ) + data

    def _fmt(self, name, value):
        if 'op' == name:
            return '0x%.4x (%s)' % (value, ARP.OPS.get(value, 'unknown'))
        return Layer._fmt(self, name, value)
