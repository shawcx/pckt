import struct

from .layer import Layer

class LLC(Layer):
    '''
    IEEE 802.2 LLC header, in 802.3 frames: those with a length in place of
    an ethertype. control is the field as a little-endian number, so its low
    two bits say whether it's one byte (0b11, unnumbered) or two.
    '''

    # ethernet and VLAN type fields up to this are the length of an LLC payload, not an ethertype
    MAX_LENGTH = 1500

    SNAP = 0xaa
    UI   = 0x03 # unnumbered information

    FIELDS = (
        ('dsap',    None), # from the payload's LLC_SAP, otherwise 0
        ('ssap',    None),
        ('control', UI),
    )

    def unpack(self, pkt):
        (self.dsap, self.ssap, self.control) = struct.unpack('!BBB', pkt[:3])
        if 0x03 == self.control & 0x03:
            return pkt[3:]
        (self.control,) = struct.unpack('<H', pkt[2:4])
        return pkt[4:]

    def next_layer(self):
        return Layer.lookup('LLC_SAP', self.dsap)

    def build(self, data, outer):
        sap = getattr(self.payload, 'LLC_SAP', 0)
        dsap = sap if self.dsap is None else self.dsap
        ssap = sap if self.ssap is None else self.ssap
        if 0x03 == self.control & 0x03:
            control = struct.pack('!B', self.control)
        else:
            control = struct.pack('<H', self.control)
        return struct.pack('!BB', dsap, ssap) + control + data

    def _fmt(self, name, value):
        if name in ('dsap', 'ssap', 'control') and value is not None:
            return '0x%.2x' % value
        return Layer._fmt(self, name, value)

class SNAP(Layer):
    '''
    SNAP header, after an LLC one: an organization's OUI and its protocol ID,
    which is an ethertype when the OUI is 0
    '''

    LLC_SAP = LLC.SNAP

    FIELDS = (
        ('oui', None), # from the payload's SNAP_ID (OUI << 16 | protocol ID), else 0 and its ETHERTYPE
        ('pid', None),
    )

    def unpack(self, pkt):
        (oui, self.pid) = struct.unpack('!3sH', pkt[:5])
        self.oui = int.from_bytes(oui, 'big')
        return pkt[5:]

    def next_layer(self):
        if 0 == self.oui:
            return Layer.lookup('ETHERTYPE', self.pid)
        return Layer.lookup('SNAP_ID', (self.oui << 16) | self.pid)

    def build(self, data, outer):
        if hasattr(self.payload, 'SNAP_ID'):
            (oui, pid) = (self.payload.SNAP_ID >> 16, self.payload.SNAP_ID & 0xffff)
        else:
            (oui, pid) = (0, getattr(self.payload, 'ETHERTYPE', 0))
        oui = oui if self.oui is None else self.oui
        pid = pid if self.pid is None else self.pid
        return oui.to_bytes(3, 'big') + struct.pack('!H', pid) + data

    def _fmt(self, name, value):
        if 'oui' == name and value is not None:
            return '0x%.6x' % value
        if 'pid' == name and value is not None:
            return '0x%.4x' % value
        return Layer._fmt(self, name, value)
