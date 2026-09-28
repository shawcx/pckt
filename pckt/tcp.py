
import struct
from random import randrange

from .layer import Layer, checksum

class TCP(Layer):
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

	IP_PROTO = 0x06

	FIELDS = (
		('src',    0),
		('dst',    0),
		('syn',    0),    # sequence number
		('ack',    0),
		('hlen',   None), # 32-bit words, from opts
		('flags',  0),
		('window', 65535),
		('crc',    None), # needs an enclosing IP layer, otherwise 0
		('urgent', 0),
		('opts',   b''),
	)

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
		self.opts = pkt[20:self.hlen * 4]

		return pkt[self.hlen * 4:]

	def build(self, data, outer):
		opts = self.opts
		hlen = self.hlen
		if hlen is None:
			opts += b'\x00' * (-len(opts) % 4)
			hlen = 5 + len(opts) // 4

		def header(crc):
			return struct.pack(
					'!HHIIBBHHH',
					self.src,
					self.dst,
					self.syn,
					self.ack,
					(hlen << 4),
					self.flags,
					self.window,
					crc,
					self.urgent
					) + opts

		crc = self.crc
		if crc is None:
			crc = 0
			if hasattr(outer, 'pseudo_header'):
				segment = header(0) + data
				crc = checksum(outer.pseudo_header(TCP.IP_PROTO, len(segment)) + segment)

		return header(crc) + data
