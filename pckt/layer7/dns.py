
import copy
import socket
import struct
from collections import namedtuple
from dataclasses import dataclass, field

from ..layer import Layer

# typed rdata
MX  = namedtuple('MX',  'preference exchange')
SOA = namedtuple('SOA', 'mname rname serial refresh retry expire minimum')
SRV = namedtuple('SRV', 'priority weight port target')


@dataclass
class DNSQuestion:
    name: str = ''
    type: int = 1   # DNS.A
    cls:  int = 1   # DNS.IN


@dataclass
class DNSRR:
    '''
    A resource record. data depends on type: A/AAAA an address string,
    NS/CNAME/PTR a name, MX/SOA/SRV the namedtuples above, TXT a list of
    bytes; anything else (or any type, to send it verbatim) raw bytes.
    '''
    name: str = ''
    type: int = 1   # DNS.A
    cls:  int = 1   # DNS.IN
    ttl:  int = 0
    data: object = b''


def _labels(name):
    name = name.rstrip('.')
    return name.split('.') if name else []


class _Writer:
    '''builds a message, tracking name suffix offsets for compression'''

    def __init__(self, compress):
        self.buf = bytearray()
        self.compress = compress
        self.offsets = {}

    def pack(self, fmt, *values):
        self.buf += struct.pack(fmt, *values)

    def name(self, name, compress=True):
        labels = _labels(name)
        for idx in range(len(labels)):
            suffix = '.'.join(labels[idx:])
            if self.compress and compress and suffix in self.offsets:
                self.pack('!H', 0xc000 | self.offsets[suffix])
                return
            # pointers only have 14 bits
            if len(self.buf) < 0x4000:
                self.offsets.setdefault(suffix, len(self.buf))
            label = labels[idx].encode('latin-1')
            if not 0 < len(label) < 64:
                raise ValueError('invalid DNS label %r in %r' % (labels[idx], name))
            self.buf += bytes([len(label)]) + label
        self.buf += b'\x00'


def _read_name(msg, offset):
    '''returns (name, offset after the name where it started)'''
    labels = []
    end = None
    for hops in range(128):
        if offset >= len(msg):
            raise struct.error('truncated DNS name')
        length = msg[offset]
        if 0xc0 == length & 0xc0:
            if offset + 1 >= len(msg):
                raise struct.error('truncated DNS name')
            if end is None:
                end = offset + 2
            offset = ((length & 0x3f) << 8) | msg[offset + 1]
            continue
        if length & 0xc0:
            raise struct.error('reserved DNS label type 0x%.2x' % length)
        if 0 == length:
            return ('.'.join(labels), offset + 1 if end is None else end)
        if offset + 1 + length > len(msg):
            raise struct.error('truncated DNS name')
        labels.append(msg[offset + 1:offset + 1 + length].decode('latin-1'))
        offset += 1 + length
    raise struct.error('DNS name compression loop')


def _read(msg, offset, fmt):
    size = struct.calcsize(fmt)
    return (struct.unpack(fmt, msg[offset:offset + size]), offset + size)


class DNS(Layer):
    '''
    DNS message (over UDP; no TCP length prefix). Names are dotted strings
    without the trailing dot, and are compressed when packing unless
    compress=False.

    Senders differ in what they compress, so a decoded message keeps its
    original bytes and packs them verbatim until a field is changed.
    '''

    UDP_PORTS = (53, 5353)

    # types
    A     = 1
    NS    = 2
    CNAME = 5
    SOA   = 6
    PTR   = 12
    MX    = 15
    TXT   = 16
    AAAA  = 28
    SRV   = 33
    OPT   = 41
    ANY   = 255

    # classes
    IN = 1

    # opcodes
    QUERY  = 0
    NOTIFY = 4
    UPDATE = 5

    # rcodes
    NOERROR  = 0
    FORMERR  = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP   = 4
    REFUSED  = 5

    FIELDS = (
        ('id',         0),
        ('qr',         0), # 1 in responses
        ('opcode',     0),
        ('aa',         0),
        ('tc',         0),
        ('rd',         1),
        ('ra',         0),
        ('z',          0),
        ('ad',         0),
        ('cd',         0),
        ('rcode',      0),
        ('qdcount',    None), # from the sections
        ('ancount',    None),
        ('nscount',    None),
        ('arcount',    None),
        ('questions',  []),
        ('answers',    []),
        ('authority',  []),
        ('additional', []),
        ('compress',   True),
    )

    SECTIONS = (('qdcount', 'questions'), ('ancount', 'answers'), ('nscount', 'authority'), ('arcount', 'additional'))

    # rdata names that may be compressed (RFC 3597 section 4)
    COMPRESSIBLE = (NS, CNAME, SOA, PTR, MX)

    def __init__(self, **fields):
        Layer.__init__(self, **fields)
        # don't share the defaults between instances
        for (count, section) in DNS.SECTIONS:
            setattr(self, section, list(getattr(self, section)))
        # (fields, bytes) as decoded
        self._wire = None

    def _snapshot(self):
        return copy.deepcopy(tuple(getattr(self, name) for (name, default) in self.FIELDS))

    @classmethod
    def query(cls, name, type=A, **fields):
        '''a recursive query for one name'''
        return cls(questions=[DNSQuestion(name, type)], **fields)

    def udp_ports(self):
        return (53, 53)

    def flags(self):
        return ((self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | (self.tc << 9) | (self.rd << 8) |
                (self.ra << 7) | (self.z << 6) | (self.ad << 5) | (self.cd << 4) | self.rcode)

    # packing

    def build(self, data, outer):
        if self._wire is not None and self._wire[0] == self._snapshot():
            return self._wire[1] + data

        w = _Writer(self.compress)
        counts = [
            len(getattr(self, section)) if getattr(self, count) is None else getattr(self, count)
            for (count, section) in DNS.SECTIONS
            ]
        w.pack('!HH4H', self.id, self.flags(), *counts)

        for question in self.questions:
            w.name(question.name)
            w.pack('!HH', question.type, question.cls)

        for section in (self.answers, self.authority, self.additional):
            for rr in section:
                w.name(rr.name)
                w.pack('!HHI', rr.type, rr.cls, rr.ttl)
                length_at = len(w.buf)
                w.pack('!H', 0)
                self._rdata(w, rr)
                struct.pack_into('!H', w.buf, length_at, len(w.buf) - length_at - 2)

        return bytes(w.buf) + data

    def _rdata(self, w, rr):
        (kind, value) = (rr.type, rr.data)
        compress = kind in DNS.COMPRESSIBLE

        if isinstance(value, (bytes, bytearray)):
            w.buf += value
        elif DNS.A == kind:
            w.buf += socket.inet_aton(value)
        elif DNS.AAAA == kind:
            w.buf += socket.inet_pton(socket.AF_INET6, value)
        elif kind in (DNS.NS, DNS.CNAME, DNS.PTR):
            w.name(value, compress)
        elif DNS.MX == kind:
            w.pack('!H', value[0])
            w.name(value[1], compress)
        elif DNS.TXT == kind:
            for string in value:
                if isinstance(string, str):
                    string = string.encode('utf-8')
                w.buf += bytes([len(string)]) + string
        elif DNS.SOA == kind:
            w.name(value[0], compress)
            w.name(value[1], compress)
            w.pack('!5I', *value[2:])
        elif DNS.SRV == kind:
            # the target must not be compressed (RFC 2782)
            w.pack('!HHH', *value[:3])
            w.name(value[3], False)
        else:
            raise TypeError('%s rdata for type %d must be bytes' % (type(value).__name__, kind))

    # unpacking

    def unpack(self, pkt):
        ((self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount), offset) = _read(pkt, 0, '!HH4H')

        self.qr     = flags >> 15
        self.opcode = (flags >> 11) & 0xf
        self.aa     = (flags >> 10) & 1
        self.tc     = (flags >> 9) & 1
        self.rd     = (flags >> 8) & 1
        self.ra     = (flags >> 7) & 1
        self.z      = (flags >> 6) & 1
        self.ad     = (flags >> 5) & 1
        self.cd     = (flags >> 4) & 1
        self.rcode  = flags & 0xf

        self.questions = []
        for idx in range(self.qdcount):
            (name, offset) = _read_name(pkt, offset)
            ((kind, cls), offset) = _read(pkt, offset, '!HH')
            self.questions.append(DNSQuestion(name, kind, cls))

        for (count, section) in DNS.SECTIONS[1:]:
            records = []
            for idx in range(getattr(self, count)):
                (name, offset) = _read_name(pkt, offset)
                ((kind, cls, ttl, length), offset) = _read(pkt, offset, '!HHIH')
                if offset + length > len(pkt):
                    raise struct.error('truncated DNS rdata')
                records.append(DNSRR(name, kind, cls, ttl, self._read_rdata(pkt, offset, length, kind)))
                offset += length
            setattr(self, section, records)

        self._wire = (self._snapshot(), bytes(pkt[:offset]))
        return pkt[offset:]

    def _read_rdata(self, msg, offset, length, kind):
        raw = msg[offset:offset + length]
        end = offset + length
        try:
            if DNS.A == kind and 4 == length:
                return socket.inet_ntoa(raw)
            if DNS.AAAA == kind and 16 == length:
                return socket.inet_ntop(socket.AF_INET6, raw)
            if kind in (DNS.NS, DNS.CNAME, DNS.PTR):
                (name, after) = _read_name(msg, offset)
                if after == end:
                    return name
            elif DNS.MX == kind:
                ((preference,), after) = _read(msg, offset, '!H')
                (exchange, after) = _read_name(msg, after)
                if after == end:
                    return MX(preference, exchange)
            elif DNS.TXT == kind:
                strings = []
                idx = 0
                while idx < length:
                    size = raw[idx]
                    strings.append(raw[idx + 1:idx + 1 + size])
                    idx += 1 + size
                if idx == length:
                    return strings
            elif DNS.SOA == kind:
                (mname, after) = _read_name(msg, offset)
                (rname, after) = _read_name(msg, after)
                (numbers, after) = _read(msg, after, '!5I')
                if after == end:
                    return SOA(mname, rname, *numbers)
            elif DNS.SRV == kind:
                (numbers, after) = _read(msg, offset, '!HHH')
                (target, after) = _read_name(msg, after)
                if after == end:
                    return SRV(*numbers, target)
        except (struct.error, IndexError):
            pass
        # unknown or malformed: keep it verbatim
        return raw

    def _fmt(self, name, value):
        if 'id' == name:
            return '0x%.4x' % value
        return Layer._fmt(self, name, value)
