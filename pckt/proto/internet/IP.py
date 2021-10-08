
import socket
import struct
from random import randrange

class IP:
	PROTOS = {
		0x01 : 'ICMP',
		0x02 : 'IGMP',
		0x06 : 'TCP',
		0x11 : 'UDP',
	}

	ICMP = 0x01
	IGMP = 0x02
	TCP  = 0x06
	UDP  = 0x11

	def __init__(self):
		self.ver = 4
		self.hlen = 5
		self.tos = 0
		self.len = 0
		self.id = 0
		self.frag = 0
		self.ttl = 255
		self.proto = 0
		self.crc = 0
		self.opts = ''
		self.src = '\x00\x00\x00\x00'
		self.dst = '\xff\xff\xff\xff'

	def randomize(self):
		self.tos = randrange(256)
		self.id = randrange(65536)
		self.ttl = randrange(256)
		self.proto = IP.PROTOS.keys()[randrange(len(IP.PROTOS))]
		self.src = ''.join(chr(randrange(256)) for x in range(4))
		self.dst = ''.join(chr(randrange(256)) for x in range(4))

	def unpack(self, pkt):
		self.ver = (ord(pkt[0]) & 0xf0) >> 4
		self.hlen = ord(pkt[0]) & 0x0f

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

		self.opts = pkt[20:(self.hlen * 4)-20]

		return pkt[self.hlen * 4:]

	def calculate_size(self):
		self.hlen = int((20 + len(self.opts)) / 4)

	def pack(self, data=''):
		self.len = (self.hlen * 4) + len(data)

		return struct.pack(
				'!BBHHHBBH4s4s',
				(self.ver << 4) + self.hlen,
				self.tos,
				self.len,
				self.id,
				self.frag,
				self.ttl,
				self.proto,
				self.crc,
				socket.inet_aton(self.src),
				socket.inet_aton(self.dst)
				) + self.opts + data

	def __repr__(self):
		r = []
		r.append(self.dst)
		r.append(self.src)
		r.append('%d (%s)' % (self.proto, IP.PROTOS.get(self.proto, 'unknown')))
		return ' '.join(r)

