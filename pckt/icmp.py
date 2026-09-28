
import struct
from random import randrange

from .layer import Layer, checksum

class ICMP(Layer):
	IP_PROTO = 0x01

	FIELDS = (
		('type',  0),
		('code',  0),
		('crc',   None),
		('block', 0), # type specific data
	)

	@classmethod
	def subclass_for(cls, data):
		if cls is ICMP and data:
			return {0: ICMP_EchoReply, 8: ICMP_EchoRequest}.get(data[0], ICMP)
		return cls

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

	def header(self, crc):
		return struct.pack('!BBHI', self.type, self.code, crc, self.block)

	def build(self, data, outer):
		crc = self.crc
		if crc is None:
			crc = checksum(self.header(0) + data)
		return self.header(crc) + data

class ICMP_EchoReply(ICMP):
	FIELDS = (
		('type', 0),
		('code', 0),
		('crc',  None),
		('id',   0),
		('seq',  0),
	)

	def __init__(self, base=None, **fields):
		# reinterpret a generic ICMP; the checksum is recomputed since the
		# caller usually changes the type (e.g. request => reply)
		if base is not None:
			if isinstance(base, ICMP_EchoReply):
				(ident, seq) = (base.id, base.seq)
			else:
				(ident, seq) = ((base.block & 0xffff0000) >> 16, base.block & 0xffff)
			fields = dict({
				'type'    : base.type,
				'code'    : base.code,
				'id'      : ident,
				'seq'     : seq,
				'payload' : base.payload,
				}, **fields)
		ICMP.__init__(self, **fields)

	def randomize(self):
		self.id = randrange(65536)
		self.seq = randrange(65536)

	def unpack(self, pkt):
		( self.type,
		  self.code,
		  self.crc,
		  self.id,
		  self.seq
		  ) = struct.unpack('!BBHHH', pkt[0:8])
		return pkt[8:]

	def header(self, crc):
		return struct.pack('!BBHHH', self.type, self.code, crc, self.id, self.seq)

class ICMP_EchoRequest(ICMP_EchoReply):
	FIELDS = (
		('type', 8),
		('code', 0),
		('crc',  None),
		('id',   0),
		('seq',  0),
	)
