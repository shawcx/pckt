
import struct
from random import randrange

class UDP:
	def __init__(self):
		self.src = 0
		self.dst = 0
		self.len = 0
		self.crc = 0

	def randomize(self):
		self.src = randrange(65536)
		self.dst = randrange(65536)

	def unpack(self, pkt):
		( self.src,
		  self.dst,
		  self.len,
		  self.crc
		  ) = struct.unpack('!4H', pkt[0:8])
		  
		return pkt[8:]

	def pack(self, data=''):
		pktlen = 8 + len(data) if not self.len else self.len
		return struct.pack('!4H', self.src, self.dst, pktlen, self.crc) + data

	def __repr__(self):
		return '%d %d %d' % (self.src,self.dst,self.len)
