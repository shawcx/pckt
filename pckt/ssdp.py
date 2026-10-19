import struct

from .layer import Layer


class SSDP(Layer):
    '''
    SSDP message (UPnP discovery): HTTP over UDP, with no body. headers is a
    list of 'Name: value' lines, packed verbatim; header() reads one.
    '''

    UDP_PORTS = 1900

    MULTICAST  = '239.255.255.250'
    MULTICAST6 = 'ff02::c'

    # start lines
    NOTIFY = 'NOTIFY * HTTP/1.1'
    SEARCH = 'M-SEARCH * HTTP/1.1'
    OK     = 'HTTP/1.1 200 OK'

    FIELDS = (
        ('start',   SEARCH),
        ('headers', []),
    )

    def __init__(self, **fields):
        Layer.__init__(self, **fields)
        # don't share the default between instances
        self.headers = list(self.headers)

    def udp_ports(self):
        return (1900, 1900)

    def header(self, name, default=None):
        '''the value of the first header with this name, ignoring case'''
        for line in self.headers:
            (key, sep, value) = line.partition(':')
            if sep and key.strip().lower() == name.lower():
                return value.strip()
        return default

    def unpack(self, pkt):
        (head, sep, rest) = pkt.partition(b'\r\n\r\n')
        if not sep:
            raise struct.error('SSDP message without an end of headers')
        # latin-1 keeps any byte as it was
        lines = head.decode('latin-1').split('\r\n')
        (self.start, self.headers) = (lines[0], lines[1:])
        return rest

    def build(self, data, outer):
        return '\r\n'.join([self.start] + self.headers + ['', '']).encode('latin-1') + data
