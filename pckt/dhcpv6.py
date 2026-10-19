import socket
import struct

from .layer import Layer


class DHCPv6(Layer):
    '''
    DHCPv6 message (RFC 8415) between a client and a server. options is a
    list of (code, value bytes) tuples; raw bytes entries are packed
    verbatim. Relay messages decode as DHCPv6Relay.
    '''

    UDP_PORTS = (546, 547)

    # message types
    SOLICIT             = 1
    ADVERTISE           = 2
    REQUEST             = 3
    CONFIRM             = 4
    RENEW               = 5
    REBIND              = 6
    REPLY               = 7
    RELEASE             = 8
    DECLINE             = 9
    RECONFIGURE         = 10
    INFORMATION_REQUEST = 11
    RELAY_FORW          = 12
    RELAY_REPL          = 13

    # sent by clients; servers send the others
    CLIENT_TYPES = (SOLICIT, REQUEST, CONFIRM, RENEW, REBIND, RELEASE, DECLINE, INFORMATION_REQUEST)

    # option codes
    CLIENT_ID    = 1
    SERVER_ID    = 2
    IA_NA        = 3
    IA_TA        = 4
    IA_ADDR      = 5
    ORO          = 6
    ELAPSED_TIME = 8
    RELAY_MSG    = 9
    STATUS_CODE  = 13
    USER_CLASS   = 15
    VENDOR_CLASS = 16
    VENDOR_OPTS  = 17
    DNS_SERVERS  = 23
    DOMAIN_LIST  = 24
    IA_PD        = 25
    CLIENT_FQDN  = 39

    FIELDS = (
        ('type',    SOLICIT),
        ('transid', 0), # 24 bits
        ('options', []),
    )

    def __init__(self, **fields):
        Layer.__init__(self, **fields)
        # don't share the default between instances
        self.options = list(self.options)

    @classmethod
    def subclass_for(cls, data):
        if cls is DHCPv6 and data and data[0] in (DHCPv6.RELAY_FORW, DHCPv6.RELAY_REPL):
            return DHCPv6Relay
        return cls

    def udp_ports(self):
        '''(src, dst) for an enclosing UDP layer'''
        return (546, 547) if self.type in DHCPv6.CLIENT_TYPES else (547, 546)

    def option(self, code, default=None):
        '''value of the first option with this code'''
        for entry in self.options:
            if isinstance(entry, tuple) and entry[0] == code:
                return entry[1]
        return default

    def fqdn(self):
        '''the name in the client FQDN option (RFC 4704), which may be just a host name; None if absent or malformed'''
        value = self.option(DHCPv6.CLIENT_FQDN)
        if not value:
            return None
        # flags, then the name as DNS labels, uncompressed; a partial name has no final empty label
        labels = []
        idx = 1
        while idx < len(value) and value[idx]:
            length = value[idx]
            if length > 63 or idx + 1 + length > len(value):
                return None
            labels.append(value[idx + 1:idx + 1 + length].decode('latin-1'))
            idx += 1 + length
        return '.'.join(labels) or None

    def vendor_classes(self):
        '''[(enterprise number, [data, ...]), ...] from the vendor class options'''
        classes = []
        for entry in self.options:
            if not (isinstance(entry, tuple) and DHCPv6.VENDOR_CLASS == entry[0] and len(entry[1]) >= 4):
                continue
            value = entry[1]
            data = []
            idx = 4
            while idx + 2 <= len(value):
                (length,) = struct.unpack('!H', value[idx:idx + 2])
                if idx + 2 + length > len(value):
                    break
                data.append(value[idx + 2:idx + 2 + length])
                idx += 2 + length
            classes.append((struct.unpack('!I', value[:4])[0], data))
        return classes

    def unpack(self, pkt):
        (word,) = struct.unpack('!I', pkt[:4])
        (self.type, self.transid) = (word >> 24, word & 0xffffff)
        self.options = self._unpack_options(pkt[4:])
        return b''

    def build(self, data, outer):
        return struct.pack('!I', (self.type << 24) | self.transid) + self._pack_options() + data

    @staticmethod
    def _unpack_options(data):
        options = []
        idx = 0
        while idx < len(data):
            (code, length) = struct.unpack('!HH', data[idx:idx + 4])
            if idx + 4 + length > len(data):
                raise struct.error('truncated DHCPv6 option')
            options.append((code, data[idx + 4:idx + 4 + length]))
            idx += 4 + length
        return options

    def _pack_options(self):
        packed = b''
        for entry in self.options:
            if isinstance(entry, tuple):
                (code, value) = entry
                entry = struct.pack('!HH', code, len(value)) + value
            packed += entry
        return packed

    def _fmt(self, name, value):
        if 'options' == name:
            return '[%s]' % ', '.join(
                '(%d, %r)' % entry if isinstance(entry, tuple) else repr(entry)
                for entry in value
                )
        if 'transid' == name:
            return '0x%.6x' % value
        return Layer._fmt(self, name, value)


class DHCPv6Relay(DHCPv6):
    '''relay-forward and relay-reply messages; the relayed message is the RELAY_MSG option'''

    FIELDS = (
        ('type',    DHCPv6.RELAY_FORW),
        ('hops',    0),
        ('link',    '::'),
        ('peer',    '::'),
        ('options', []),
    )

    def udp_ports(self):
        return (547, 547)

    def unpack(self, pkt):
        (self.type, self.hops, link, peer) = struct.unpack('!BB16s16s', pkt[:34])
        self.link = socket.inet_ntop(socket.AF_INET6, link)
        self.peer = socket.inet_ntop(socket.AF_INET6, peer)
        self.options = self._unpack_options(pkt[34:])
        return b''

    def build(self, data, outer):
        return struct.pack(
            '!BB16s16s',
            self.type,
            self.hops,
            socket.inet_pton(socket.AF_INET6, self.link),
            socket.inet_pton(socket.AF_INET6, self.peer),
            ) + self._pack_options() + data
