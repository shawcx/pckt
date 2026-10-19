import socket
import struct

from .dns import DNS


class NBNS(DNS):
    '''
    NetBIOS name service message (RFC 1002): DNS's format, with the
    broadcast flag in place of DNS's z, ad and cd bits. Names are first-level
    encoded (see encode_name()), and NB record data is a list of
    (flags, address) tuples.
    '''

    UDP_PORTS = 137

    # types
    NB     = 0x20
    NBSTAT = 0x21

    # opcodes
    QUERY        = 0
    REGISTRATION = 5
    RELEASE      = 6
    WACK         = 7
    REFRESH      = 8

    # NB flags: a group name, rather than one unique to a host
    GROUP = 0x8000

    # name suffixes
    WORKSTATION = 0x00
    SERVER      = 0x20

    # DNS's fields up to ra, then broadcast in place of z, ad and cd
    FIELDS = DNS.FIELDS[:7] + (('broadcast', 0),) + DNS.FIELDS[10:]

    FLAGS = (('qr', 15, 1), ('opcode', 11, 0xf), ('aa', 10, 1), ('tc', 9, 1), ('rd', 8, 1), ('ra', 7, 1),
             ('broadcast', 4, 1), ('rcode', 0, 0xf))

    def udp_ports(self):
        return (137, 137)

    @staticmethod
    def encode_name(name, suffix=WORKSTATION, scope=''):
        '''
        first-level encoding (RFC 1001 section 14.1): the name padded to 15
        bytes plus the suffix byte, each half byte as a letter from A to P
        '''
        raw = name.encode('latin-1')
        if len(raw) > 15:
            raise ValueError('NetBIOS name %r is longer than 15 bytes' % name)
        # the wildcard name '*' is padded with zeroes, others with spaces
        raw = raw.ljust(15, b'\x00' if b'*' == raw else b' ') + bytes([suffix])
        label = ''.join(chr(0x41 + (o >> 4)) + chr(0x41 + (o & 0xf)) for o in raw)
        return label + '.' + scope if scope else label

    @staticmethod
    def decode_name(name):
        '''(name, suffix, scope) for a first-level encoded name, else None'''
        (label, _, scope) = name.partition('.')
        if 32 != len(label) or not all('A' <= c <= 'P' for c in label):
            return None
        raw = bytes(((ord(label[idx]) - 0x41) << 4) | (ord(label[idx + 1]) - 0x41) for idx in range(0, 32, 2))
        return (raw[:15].rstrip(b' \x00').decode('latin-1'), raw[15], scope)

    def _rdata(self, w, rr):
        if NBNS.NB == rr.type and isinstance(rr.data, list):
            for (flags, addr) in rr.data:
                w.pack('!H4s', flags, socket.inet_aton(addr))
        elif isinstance(rr.data, (bytes, bytearray)):
            w.buf += rr.data
        else:
            raise TypeError('%s rdata for type %d must be bytes' % (type(rr.data).__name__, rr.type))

    def _read_rdata(self, msg, offset, length, kind):
        raw = msg[offset:offset + length]
        if NBNS.NB == kind and 0 == length % 6:
            return [(flags, socket.inet_ntoa(addr)) for (flags, addr) in struct.iter_unpack('!H4s', raw)]
        # anything else, including a WACK's two bytes, is kept verbatim
        return raw
