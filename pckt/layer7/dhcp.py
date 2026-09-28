
import socket
import struct
from random import randrange

class DHCP_Request:
    def __init__(self):
        self.type       = 1
        self.hwtype     = 1
        self.hwlen      = 6
        self.hops       = 0
        self.transid    = randrange(2**31)
        self.elapsed    = 0
        self.bootpflags = 0
        self.clientip   = '0.0.0.0'
        self.yourip     = '0.0.0.0'
        self.serverip   = '0.0.0.0'
        self.relayip    = '0.0.0.0'
        self.clientmac  = b'\x00\x00\x00\x00\x00\x00'
        self.magic      = 0x63825363

        self.options = []
        # option: DHCP Request
        self.options.append(b'\x35\x01\x03')
        # option: Parameters
        self.options.append(b'\x37\x0d\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a')

    def randomize(self):
        pass

    def unpack(self, pkt):
        return pkt

    def pack(self):
        pkt = struct.pack(
            '!BBBBIHH4s4s4s4s16s192sI',
            self.type,
            self.hwtype,
            self.hwlen,
            self.hops,
            self.transid,
            self.elapsed,
            self.bootpflags,
            socket.inet_aton(self.clientip),
            socket.inet_aton(self.yourip),
            socket.inet_aton(self.serverip),
            socket.inet_aton(self.relayip),
            self.clientmac,
            b'', # legacy bootp field (192 bytes)
            self.magic,
            )

        pkt += b''.join(self.options)

        # end options
        pkt += b'\xff'

        padding = 300 - len(pkt)
        if 0 < padding:
            pkt += b'\x00' * padding

        return pkt

    def __repr__(self):
        return '%d %d %d' % (self.src,self.dst,self.len)
