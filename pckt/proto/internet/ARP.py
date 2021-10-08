
import socket
import struct
from random import randrange

class ARP:
	PROTOS = {
		0x0001 : 'ETH',
		0x0800 : 'IP',
	}

	OPS = {
		0x0001 : 'ARP REQUEST',
		0x0002 : 'ARP REPLY',
		0x0003 : 'RARP REQUEST',
		0x0004 : 'RARP REPLY',
	}

	def __init__(self):
		self.hw = 0x0001
		self.proto = 0x0800
		self.hwsize = 6
		self.protosize = 4
		self.op = 0
		self.src_mac = '\x00\x00\x00\x00\x00\x00'
		self.src_ip = '0.0.0.0'
		self.dst_mac = '\xff\xff\xff\xff\xff\xff'
		self.dst_ip = '255.255.255.255'

	def randomize(self):
		self.src_mac = ''.join(chr(randrange(256)) for x in range(6))
		self.src_ip = '.'.join(str(randrange(256)) for x in range(4))
		self.dst_mac = '\xff\xff\xff\xff\xff\xff'
		self.dst_ip = '255.255.255.255'

	def unpack(self, pkt):
		( self.hw,
		  self.proto,
		  self.hwsize,
		  self.protosize,
		  self.op,
		  self.src_mac,
		  self.src_ip,
		  self.dst_mac,
		  self.dst_ip
		  ) = struct.unpack('!HHBBH6s4s6s4s', pkt[0:28])

		self.src_ip = socket.inet_ntoa(self.src_ip)
		self.dst_ip = socket.inet_ntoa(self.dst_ip)

		return pkt[28:]

	def pack(self, data=''):
		return struct.pack(
					'!HHBBH6s4s6s4s',
					self.hw,
					self.proto,
					self.hwsize,
					self.protosize,
					self.op,
					self.src_mac,
					socket.inet_aton(self.src_ip),
					self.dst_mac,
					socket.inet_aton(self.dst_ip)
					) + data

	def __repr__(self):
		r = []
		r.append(':'.join('%.2x' % ord(o) for o in self.dst_mac))
		r.append(' / ')
		r.append('.'.join('%d' % ord(o) for o in self.dst_ip))
		r.append(' ')
		r.append(':'.join('%.2x' % ord(o) for o in self.src_mac))
		r.append(' / ')
		r.append('.'.join('%d' % ord(o) for o in self.src_ip))
		r.append(' ')
		r.append('0x%.4x (%s)' % (self.op, ARP.OPS[self.op]))
		return ''.join(r)
