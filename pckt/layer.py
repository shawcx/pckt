
import copy
import struct


def checksum(data):
    '''RFC 1071 internet checksum'''
    if len(data) & 1:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def mac(value):
    '''accept a MAC address as 6 bytes or as an 'aa:bb:cc:dd:ee:ff' string'''
    if isinstance(value, str):
        return bytes.fromhex(value.replace(':', '').replace('-', ''))
    return value


_missing = object()


class Layer:
    '''
    Base class for a protocol layer. A layer holds its header fields plus a
    payload, which is either the next Layer, raw bytes, any object with a
    pack() method, or None.

    Layers are chained with '/', outermost first:

        pkt = Ethernet() / IP(dst='10.0.0.2') / UDP(src=68, dst=67) / payload
        frame = pkt.pack()

    A field left as None is filled in when packing (lengths, checksums, the
    ethertype / IP protocol of the next layer). Setting it explicitly always
    wins, which allows deliberately malformed packets. Fields read by
    unpack()/decode() are concrete values, so re-packing a decoded packet
    reproduces it exactly; set a field back to None to have it recomputed.
    '''

    # (name, default) pairs, in wire order
    FIELDS = ()

    # fields shown as aa:bb:cc:dd:ee:ff by repr()
    MAC_FIELDS = ()

    _registry = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        Layer._registry.append(cls)

    @staticmethod
    def lookup(attr, value):
        '''
        find the layer class that declares attr == value, e.g. ('IP_PROTO', 17) => UDP;
        attr may also be a tuple of values, e.g. UDP_PORTS = (67, 68)
        '''
        for cls in Layer._registry:
            declared = cls.__dict__.get(attr, _missing)
            if declared == value or (isinstance(declared, tuple) and value in declared):
                return cls
        return None

    def __init__(self, **fields):
        self.payload = fields.pop('payload', None)
        for name, default in self.FIELDS:
            setattr(self, name, fields.pop(name, default))
        if fields:
            raise TypeError('%s: unknown field(s): %s' % (type(self).__name__, ', '.join(fields)))

    # chaining

    def __truediv__(self, other):
        top = copy.deepcopy(self)
        last = top._last()
        if last.payload is not None:
            raise ValueError('%s already has a %s payload' % (type(last).__name__, type(last.payload).__name__))
        last.payload = copy.deepcopy(other)
        return top

    def _last(self):
        layer = self
        while isinstance(layer.payload, Layer):
            layer = layer.payload
        return layer

    def __iter__(self):
        layer = self
        while isinstance(layer, Layer):
            yield layer
            layer = layer.payload

    def __getitem__(self, cls):
        for layer in self:
            if isinstance(layer, cls):
                return layer
        raise KeyError(cls.__name__)

    def __contains__(self, cls):
        return any(isinstance(layer, cls) for layer in self)

    # packing

    def pack(self, data=None):
        '''pack this layer and everything under it; data (bytes) overrides the payload'''
        return self._pack(None, data)

    def __bytes__(self):
        return self.pack()

    def _pack(self, outer, data=None):
        if data is None:
            data = self._payload_bytes()
        return self.build(data, outer)

    def _payload_bytes(self):
        payload = self.payload
        if payload is None:
            return b''
        if isinstance(payload, Layer):
            return payload._pack(self)
        if isinstance(payload, (bytes, bytearray)):
            return bytes(payload)
        return payload.pack()

    def build(self, data, outer):
        '''return this layer's header + data; outer is the enclosing layer or None'''
        raise NotImplementedError

    # unpacking

    def unpack(self, pkt):
        '''read this layer's header from pkt and return the rest'''
        raise NotImplementedError

    def next_layer(self):
        '''the Layer class for this layer's payload, or None to keep it as bytes'''
        return None

    @classmethod
    def subclass_for(cls, data):
        '''hook to pick a more specific class before decoding data'''
        return cls

    @classmethod
    def decode(cls, data):
        '''decode data into a chain of layers, starting with this class'''
        layer = cls.subclass_for(data)()
        rest = layer.unpack(data)
        if rest:
            layer.payload = rest
            nxt = layer.next_layer()
            if nxt:
                try:
                    layer.payload = nxt.decode(rest)
                except struct.error:
                    # truncated; leave the payload as bytes
                    pass
        return layer

    # display

    def _fmt(self, name, value):
        if name in self.MAC_FIELDS and isinstance(value, bytes):
            return ':'.join('%.2x' % o for o in value)
        return repr(value)

    def __repr__(self):
        parts = []
        for layer in self:
            fields = ', '.join(
                '%s=%s' % (name, layer._fmt(name, getattr(layer, name)))
                for name, default in layer.FIELDS
                if getattr(layer, name) != default
                )
            parts.append('%s(%s)' % (type(layer).__name__, fields))
        tail = self._last().payload
        if tail is not None:
            parts.append(repr(tail))
        return ' / '.join(parts)
