
import socket
import struct
from random import randrange

from .layer import Layer, checksum

class IP(Layer):
	PROTOS = {
		0x01 : 'ICMP',
		0x02 : 'IGMP',
		0x06 : 'TCP',
		0x11 : 'UDP',
		0x3a : 'ICMPv6',
	}

	ICMP = 0x01
	IGMP = 0x02
	TCP  = 0x06
	UDP  = 0x11
	ICMPv6 = 0x3a

	ETHERTYPE = 0x0800

	FIELDS = (
		('ver',   4),
		('hlen',  None), # 32-bit words, from opts
		('tos',   0),
		('len',   None), # header + payload
		('id',    0),
		('frag',  0),
		('ttl',   255),
		('proto', None), # payload's IP_PROTO
		('crc',   None),
		('opts',  b''),
		('src',   '0.0.0.0'),
		('dst',   '255.255.255.255'),
	)

	def randomize(self):
		self.tos = randrange(256)
		self.id = randrange(65536)
		self.ttl = randrange(256)
		self.proto = list(IP.PROTOS)[randrange(len(IP.PROTOS))]
		self.src = '.'.join(str(randrange(256)) for x in range(4))
		self.dst = '.'.join(str(randrange(256)) for x in range(4))

	def unpack(self, pkt):
		self.ver = (pkt[0] & 0xf0) >> 4
		self.hlen = pkt[0] & 0x0f

		( self.tos,
		  self.len,
		  self.id,
		  self.frag,
		  self.ttl,
		  self.proto,
		  self.crc,
		  self.src,
		  self.dst
		  ) = struct.unpack('!BHHHBBH4s4s', pkt[1:20])

		self.src = socket.inet_ntoa(self.src)
		self.dst = socket.inet_ntoa(self.dst)

		self.opts = pkt[20:self.hlen * 4]

		# drop ethernet padding after the datagram
		end = self.len if self.len >= self.hlen * 4 else len(pkt)
		return pkt[self.hlen * 4:end]

	def next_layer(self):
		return Layer.lookup('IP_PROTO', self.proto)

	def calculate_size(self):
		self.hlen = (20 + len(self.opts)) // 4

	def pseudo_header(self, proto, length):
		'''TCP/UDP checksum pseudo header'''
		return struct.pack('!4s4sBBH', socket.inet_aton(self.src), socket.inet_aton(self.dst), 0, proto, length)

	def build(self, data, outer):
		opts = self.opts
		hlen = self.hlen
		if hlen is None:
			opts += b'\x00' * (-len(opts) % 4)
			hlen = 5 + len(opts) // 4

		length = self.len
		if length is None:
			length = (hlen * 4) + len(data)

		proto = self.proto
		if proto is None:
			proto = getattr(self.payload, 'IP_PROTO', 0)

		def header(crc):
			return struct.pack(
					'!BBHHHBBH4s4s',
					(self.ver << 4) + hlen,
					self.tos,
					length,
					self.id,
					self.frag,
					self.ttl,
					proto,
					crc,
					socket.inet_aton(self.src),
					socket.inet_aton(self.dst)
					) + opts

		crc = self.crc
		if crc is None:
			crc = checksum(header(0))

		return header(crc) + data
