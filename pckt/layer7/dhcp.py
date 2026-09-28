
import socket
import struct
from random import randrange

from ..layer import Layer, mac

class DHCP(Layer):
    '''
    DHCP / BOOTP message. options is a list of (code, value bytes) tuples;
    raw bytes entries are packed verbatim. The end option is added when
    packing and dropped when unpacking.
    '''

    UDP_PORTS = (67, 68)

    BOOTREQUEST = 1
    BOOTREPLY   = 2

    # option codes
    PAD            = 0
    SUBNET_MASK    = 1
    ROUTER         = 3
    DNS            = 6
    HOSTNAME       = 12
    REQUESTED_IP   = 50
    LEASE_TIME     = 51
    MESSAGE_TYPE   = 53
    SERVER_ID      = 54
    PARAMETER_LIST = 55
    VENDOR_CLASS   = 60
    CLIENT_ID      = 61
    END            = 255

    # MESSAGE_TYPE values
    DISCOVER = 1
    OFFER    = 2
    REQUEST  = 3
    DECLINE  = 4
    ACK      = 5
    NAK      = 6
    RELEASE  = 7
    INFORM   = 8

    MAGIC = 0x63825363

    FIELDS = (
        ('type',       BOOTREQUEST), # op
        ('hwtype',     1),
        ('hwlen',      6),
        ('hops',       0),
        ('transid',    0),
        ('elapsed',    0),
        ('bootpflags', 0),
        ('clientip',   '0.0.0.0'),
        ('yourip',     '0.0.0.0'),
        ('serverip',   '0.0.0.0'),
        ('relayip',    '0.0.0.0'),
        ('clientmac',  b'\x00\x00\x00\x00\x00\x00'),
        ('sname',      b''),
        ('file',       b''),
        ('magic',      MAGIC),
        ('options',    []),
        ('padding',    None), # after the end option, defaults to the 300 byte BOOTP minimum
    )
    MAC_FIELDS = ('clientmac',)

    def __init__(self, **fields):
        Layer.__init__(self, **fields)
        # don't share the default between instances
        self.options = list(self.options)

    def randomize(self):
        self.transid = randrange(2**32)

    def udp_ports(self):
        '''(src, dst) for an enclosing UDP layer'''
        return (68, 67) if DHCP.BOOTREQUEST == self.type else (67, 68)

    def option(self, code, default=None):
        '''value of the first option with this code'''
        for entry in self.options:
            if isinstance(entry, tuple) and entry[0] == code:
                return entry[1]
        return default

    def unpack(self, pkt):
        ( self.type,
          self.hwtype,
          self.hwlen,
          self.hops,
          self.transid,
          self.elapsed,
          self.bootpflags,
          self.clientip,
          self.yourip,
          self.serverip,
          self.relayip,
          chaddr,
          sname,
          file,
          self.magic,
          ) = struct.unpack('!BBBBIHH4s4s4s4s16s64s128sI', pkt[:240])

        self.clientip = socket.inet_ntoa(self.clientip)
        self.yourip   = socket.inet_ntoa(self.yourip)
        self.serverip = socket.inet_ntoa(self.serverip)
        self.relayip  = socket.inet_ntoa(self.relayip)

        # chaddr is zero padded to 16 bytes
        if not chaddr[self.hwlen:].strip(b'\x00'):
            chaddr = chaddr[:self.hwlen]
        self.clientmac = chaddr
        self.sname = sname.rstrip(b'\x00')
        self.file = file.rstrip(b'\x00')

        self.options = []
        idx = 240
        while idx < len(pkt):
            code = pkt[idx]
            if DHCP.END == code:
                idx += 1
                break
            if DHCP.PAD == code:
                self.options.append(b'\x00')
                idx += 1
                continue
            length = pkt[idx + 1]
            self.options.append((code, pkt[idx + 2:idx + 2 + length]))
            idx += 2 + length

        self.padding = pkt[idx:]
        return b''

    def build(self, data, outer):
        pkt = struct.pack(
            '!BBBBIHH4s4s4s4s16s64s128sI',
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
            mac(self.clientmac),
            self.sname,
            self.file,
            self.magic,
            )

        for entry in self.options:
            if isinstance(entry, tuple):
                (code, value) = entry
                entry = struct.pack('!BB', code, len(value)) + value
            pkt += entry

        pkt += struct.pack('!B', DHCP.END)

        padding = self.padding
        if padding is None:
            padding = b'\x00' * max(0, 300 - len(pkt))

        return pkt + padding + data

    def _fmt(self, name, value):
        if 'options' == name:
            return '[%s]' % ', '.join(
                '(%d, %r)' % entry if isinstance(entry, tuple) else repr(entry)
                for entry in value
                )
        if 'padding' == name and value is not None:
            return '<%d bytes>' % len(value)
        if 'transid' == name:
            return '0x%.8x' % value
        return Layer._fmt(self, name, value)

class DHCP_Request(DHCP):
    '''DHCP REQUEST asking for the usual parameters, with a random transaction id'''

    def __init__(self, **fields):
        fields.setdefault('transid', randrange(2**31))
        fields.setdefault('options', [
            (DHCP.MESSAGE_TYPE, bytes([DHCP.REQUEST])),
            (DHCP.PARAMETER_LIST, b'\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a'),
            ])
        DHCP.__init__(self, **fields)
