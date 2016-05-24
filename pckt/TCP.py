
import struct
from random import randrange

class TCP:
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20

	# NOT SUPPORTED YET
	#ECN = 0x40
	#CWR = 0x80
	#NS  = 0x100


	def __init__(self):
		self.src = 0
		self.dst = 0
		self.syn = 0
		self.ack = 0
		self.hlen = 5
		self.flags = 0
		self.window = 65535
		self.crc = 0
		self.urgent = 0
		self.opts = ''

	def randomize(self):
		self.src = randrange(65536)
		self.dst = randrange(65536)
		self.syn = randrange(2**32)
		self.ack = randrange(2**32)
		self.window = randrange(65536)
		self.urgent = randrange(65536)

	def unpack(self, pkt):
		( self.src,
		  self.dst,
		  self.syn,
		  self.ack,
		  self.hlen, # lower nibble contains new flags
		  self.flags,
		  self.window,
		  self.crc,
		  self.urgent
		  ) = struct.unpack('!HHIIBBHHH', pkt[0:20])

		self.hlen = (self.hlen & 0xf0) >> 4
		self.flags = self.flags & 0x3f
		self.opts = pkt[20:(self.hlen * 4)-20]

		return pkt[self.hlen * 4:]

	#def calculate_size(self):
	#	self.hlen = 5 + len(self.opts) / 4

	def pack(self, data=''):
		self.len = (self.hlen * 4) + len(data)
		pkt = struct.pack(
					'!HHIIBBHHH',
					self.src,
					self.dst,
					self.syn,
					self.ack,
					(self.hlen << 4),
					self.flags,
					self.window,
					self.crc,
					self.urgent
					)
		return pkt + self.opts + data

	def __repr__(self):
		r = []
		r.append('%s' % self.dst)
		r.append('%s' % self.src)
		return ' '.join(r)
