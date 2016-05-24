
import struct
from random import randrange

class ICMP:
	def __init__(self):
		self.type = 0
		self.code = 0
		self.crc = 0
		# type specific data
		self.block = 0

	def randomize(self):
		self.type = randrange(256)
		self.code = randrange(256)
		self.block = randrange(2**32)

	def unpack(self, pkt):
		( self.type,
		  self.code,
		  self.crc,
		  self.block
		  ) = struct.unpack('!BBHI', pkt[0:8])
		return pkt[8:]

	def pack(self, data=''):
		return struct.pack('!BBHI', self.type, self.code, self.crc, self.block) + data

	def __repr__(self):
		return '%d %d' % (self.type,self.code)

class ICMP_EchoReply(ICMP):
	def __init__(self, base=None):
		if not base:
			self.type = 0
			self.code = 0
			self.id  = 0
			self.seq = 0
		else:
			self.type = base.type
			self.code = base.code
			self.crc = base.crc
			self.block = base.block
			self.id = (base.block & 0xffff0000) >> 16
			self.seq = base.block & 0xffff
	def unpack(self, pkt):
		( self.type,
		  self.code,
		  self.crc,
		  self.id,
		  self.seq
		  ) = struct.unpack('!BBHHH', pkt[0:8])
		return pkt[8:]

	def pack(self, data=''):
		return struct.pack('!BBHHH', self.type, self.code, self.crc, self.id, self.seq) + data

	def __repr__(self):
		return 'ICMP Echo Reply: %d %d' % (self.id,self.seq)

class ICMP_EchoRequest(ICMP_EchoReply):
	def __init__(self, base=None):
		if not base:
			ICMP.__init__(self)
			self.type = 8
			self.id  = 0
			self.seq = 0
		else:
			self.type = base.type
			self.code = base.code
			self.crc = base.crc
			self.block = base.block
			self.id = (base.block & 0xffff0000) >> 16
			self.seq = base.block & 0xffff

	def __repr__(self):
		return 'ICMP Echo Request: %d %d' % (self.id,self.seq)

