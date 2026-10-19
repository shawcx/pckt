import socket
import struct

from .layer import Layer

class LLDP(Layer):
    '''
    Link Layer Discovery Protocol (IEEE 802.1AB) data unit. tlvs is a list
    of (type, bytes) pairs; the end TLV is added when packing, and anything
    after it is kept in padding. Send it to LLDP.MULTICAST.
    '''

    ETHERTYPE = 0x88cc

    # nearest bridge: not forwarded by switches
    MULTICAST = b'\x01\x80\xc2\x00\x00\x0e'

    # TLV types
    END                 = 0
    CHASSIS_ID          = 1
    PORT_ID             = 2
    TTL                 = 3
    PORT_DESCRIPTION    = 4
    SYSTEM_NAME         = 5
    SYSTEM_DESCRIPTION  = 6
    SYSTEM_CAPABILITIES = 7
    MANAGEMENT_ADDRESS  = 8
    ORGANIZATION        = 127

    # first byte of a chassis ID
    CHASSIS_MAC     = 4
    CHASSIS_NETWORK = 5
    CHASSIS_LOCAL   = 7

    # first byte of a port ID
    PORT_MAC       = 3
    PORT_INTERFACE = 5
    PORT_LOCAL     = 7

    # system capabilities, by bit
    CAPABILITIES = ('other', 'repeater', 'bridge', 'wlan-ap', 'router', 'phone', 'docsis', 'station', 'c-vlan', 's-vlan', 'mac-relay')

    # management address families (IANA)
    FAMILIES = {1: socket.AF_INET, 2: socket.AF_INET6}

    FIELDS = (
        ('tlvs',    []),
        ('padding', b''),
    )

    def __init__(self, **fields):
        Layer.__init__(self, **fields)
        # don't share the default between instances
        self.tlvs = list(self.tlvs)

    def tlv(self, kind, default=None):
        '''value of the first TLV of this type'''
        for (code, value) in self.tlvs:
            if code == kind:
                return value
        return default

    def capabilities(self):
        '''names of the enabled system capabilities'''
        value = self.tlv(LLDP.SYSTEM_CAPABILITIES, b'')
        if 4 != len(value):
            return []
        (supported, enabled) = struct.unpack('!HH', value)
        return [name for (bit, name) in enumerate(LLDP.CAPABILITIES) if enabled & (1 << bit)]

    def management_addresses(self):
        '''IPv4 and IPv6 management addresses, as strings'''
        addrs = []
        for (code, value) in self.tlvs:
            # length of the subtype and address, the address family, then the address
            if LLDP.MANAGEMENT_ADDRESS != code or len(value) < 2:
                continue
            (length, family) = (value[0], value[1])
            raw = value[2:1 + length]
            try:
                addrs.append(socket.inet_ntop(LLDP.FAMILIES[family], raw))
            except (KeyError, ValueError):
                pass
        return addrs

    def unpack(self, pkt):
        self.tlvs = []
        idx = 0
        while idx + 2 <= len(pkt):
            (header,) = struct.unpack('!H', pkt[idx:idx + 2])
            (code, length) = (header >> 9, header & 0x1ff)
            if idx + 2 + length > len(pkt):
                raise struct.error('truncated LLDP TLV')
            value = pkt[idx + 2:idx + 2 + length]
            idx += 2 + length
            if LLDP.END == code:
                break
            self.tlvs.append((code, value))
        self.padding = pkt[idx:]
        return b''

    def build(self, data, outer):
        pkt = b''
        for (code, value) in self.tlvs + [(LLDP.END, b'')]:
            pkt += struct.pack('!H', (code << 9) | len(value)) + value
        return pkt + self.padding + data

    def _fmt(self, name, value):
        if 'tlvs' == name:
            return '[%s]' % ', '.join('(%d, %r)' % entry for entry in value)
        return Layer._fmt(self, name, value)
