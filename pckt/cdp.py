import socket
import struct

from .layer import Layer, checksum


def cdp_checksum(data):
    '''
    the internet checksum as Cisco computes it: an odd last byte is the low
    byte of the final word rather than the high one, and one that's 0x80 or
    more is sign extended, less one (see Wireshark's packet-cdp.c)
    '''
    if len(data) & 1:
        last = data[-1]
        data = data[:-1] + struct.pack('!H', (0xff00 | last) - 1 if last & 0x80 else last)
    return checksum(data)


class CDP(Layer):
    '''
    Cisco Discovery Protocol, sent in SNAP frames to 01:00:0c:cc:cc:cc. tlvs
    is a list of (type, bytes), like LLDP's; tlv(), capabilities() and
    addresses() read them.
    '''

    # Cisco's OUI and CDP's protocol ID
    SNAP_ID = 0x00000c2000

    MULTICAST = b'\x01\x00\x0c\xcc\xcc\xcc'

    # TLV types
    DEVICE_ID            = 0x01
    ADDRESSES            = 0x02
    PORT_ID              = 0x03
    CAPABILITIES         = 0x04
    SOFTWARE_VERSION     = 0x05
    PLATFORM             = 0x06
    NATIVE_VLAN          = 0x0a
    DUPLEX               = 0x0b
    VOICE_VLAN           = 0x0e
    SYSTEM_NAME          = 0x14
    MANAGEMENT_ADDRESSES = 0x16

    # capability bits, lowest first, as IOS's "show cdp neighbors" names them
    CAPABILITY_NAMES = ('router', 'trans-bridge', 'source-route-bridge', 'switch', 'host', 'igmp', 'repeater',
                        'phone', 'remote', 'cvta', 'mac-relay')

    # an address's protocol type and protocol: NLPID 0xcc, and 802.2 SNAP with IPv6's ethertype
    PROTOCOLS = {
        (1, b'\xcc'): socket.AF_INET,
        (2, b'\xaa\xaa\x03\x00\x00\x00\x86\xdd'): socket.AF_INET6,
        }

    FIELDS = (
        ('version', 2),
        ('ttl',     180),
        ('crc',     None),
        ('tlvs',    []),
    )

    def __init__(self, **fields):
        Layer.__init__(self, **fields)
        # don't share the default between instances
        self.tlvs = list(self.tlvs)

    def tlv(self, kind, default=None):
        '''value of the first TLV of this type'''
        for (t, value) in self.tlvs:
            if t == kind:
                return value
        return default

    def capabilities(self):
        '''names of the capabilities set'''
        value = self.tlv(CDP.CAPABILITIES, b'')
        if 4 != len(value):
            return []
        (bits,) = struct.unpack('!I', value)
        return [name for (bit, name) in enumerate(CDP.CAPABILITY_NAMES) if bits & (1 << bit)]

    def addresses(self, kind=ADDRESSES):
        '''the IPv4 and IPv6 addresses in an ADDRESSES or MANAGEMENT_ADDRESSES TLV'''
        value = self.tlv(kind, b'')
        addrs = []
        try:
            (count,) = struct.unpack('!I', value[:4])
            idx = 4
            for n in range(count):
                (ptype, length) = struct.unpack('!BB', value[idx:idx + 2])
                protocol = value[idx + 2:idx + 2 + length]
                idx += 2 + length
                (length,) = struct.unpack('!H', value[idx:idx + 2])
                addr = value[idx + 2:idx + 2 + length]
                idx += 2 + length
                family = CDP.PROTOCOLS.get((ptype, protocol))
                if family:
                    addrs.append(socket.inet_ntop(family, addr))
        except (struct.error, ValueError):
            # truncated, or an address of the wrong length
            pass
        return addrs

    def unpack(self, pkt):
        (self.version, self.ttl, self.crc) = struct.unpack('!BBH', pkt[:4])
        self.tlvs = []
        idx = 4
        while idx < len(pkt):
            (kind, length) = struct.unpack('!HH', pkt[idx:idx + 4])
            # the length includes the type and length
            if length < 4 or idx + length > len(pkt):
                raise struct.error('truncated CDP TLV')
            self.tlvs.append((kind, pkt[idx + 4:idx + length]))
            idx += length
        return b''

    def build(self, data, outer):
        body = b''.join(struct.pack('!HH', kind, 4 + len(value)) + value for (kind, value) in self.tlvs)
        crc = self.crc
        if crc is None:
            crc = cdp_checksum(struct.pack('!BBH', self.version, self.ttl, 0) + body)
        return struct.pack('!BBH', self.version, self.ttl, crc) + body + data

    def _fmt(self, name, value):
        if 'tlvs' == name:
            return '[%s]' % ', '.join('(%d, %r)' % entry for entry in value)
        if 'crc' == name and value is not None:
            return '0x%.4x' % value
        return Layer._fmt(self, name, value)
