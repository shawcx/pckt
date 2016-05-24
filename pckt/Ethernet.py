
import struct
from random import randrange

class Ethernet:
	PROTOS = {
		0x0800 : 'IP',
		0x0806 : 'ARP',
		0x8035 : 'RARP',
	}

	IP   = 0x0800
	ARP  = 0x0806
	RARP = 0x8035

	def __init__(self):
		self.dst = '\xff\xff\xff\xff\xff\xff'
		self.src = '\x00\x00\x00\x00\x00\x00'
		self.proto = 0

	def randomize(self):
		self.dst = '\xff' * 6
		self.src = ''.join(chr(randrange(256)) for x in range(6))
		self.proto = Ethernet.PROTOS.keys()[randrange(len(Ethernet.PROTOS))]

	def unpack(self, pkt):
		(self.dst,self.src,self.proto) = struct.unpack('!6s6sH', pkt[:14])
		return pkt[14:]

	def pack(self, data=''):
		return struct.pack('!6s6sH', self.dst, self.src, self.proto) + data

	def __repr__(self):
		r = []
		r.append(':'.join('%.2x' % ord(o) for o in self.dst))
		r.append(':'.join('%.2x' % ord(o) for o in self.src))
		r.append('0x%.4X (%s)' % (self.proto, Ethernet.PROTOS.get(self.proto, 'unknown')))
		return ' '.join(r)
