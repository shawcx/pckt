#!/usr/bin/env python

import sys
import time
import random
import socket

try:
	import pypcap
except:
	print 'pypcap not found; go to code/Libraries/Python/extensions/pypcap'
	sys.exit(-1)

try:
	import packetio
except:
	print 'packetio not found; go to code/Libraries/Python/packetio'
	sys.exit(-1)

class GhostAdapter:
	@staticmethod
	def GetDevices():
		return pypcap.findalldevs()

	def __init__(self, dev, settings=None):
		self.device = dev

		if settings:
			# split on ':', convert string to integer to byte and join
			self.mac  = ''.join(chr(int(o,16)) for o in settings['mac'].split(':', 6))
			#self.ip   = socket.inet_aton(settings['ip'])
			#self.mask = socket.inet_aton(settings['netmask'])
			self.ip   = settings['ip']
			self.mask = settings['netmask']
			print settings

			action = self.Loop

		else:
			self.mac = '\x22\x33\x44\x55\x66\x77'
			self.ip = '0.0.0.0'
			self.mask = '255.255.255.255'
			action = self.DHCP

		self.pd = pypcap.open_live(self.device, 2048, False, 100)

		# only capture in bound packets; does nothing on windows
		self.pd.setdirection(pypcap.D_IN)

		# for windows, ignore when our mac addr is the src
		#self.pd.setfilter('ether src not ' + settings['mac'])

		# pre-allocate some classes
		self.ethin  = packetio.Ethernet()
		self.ethout = packetio.Ethernet()
		self.arpin  = packetio.ARP()
		self.arpout = packetio.ARP()
		self.ipin   = packetio.IP()
		self.ipout  = packetio.IP()
		self.icmpin = packetio.ICMP()

		self.udpin  = packetio.UDP()
		self.udpout = packetio.UDP()

		# call DHCP or Loop
		action()

	def DHCP(self):
		self.ethout.dst   = '\xff\xff\xff\xff\xff\xff'
		self.ethout.src   = self.mac
		self.ethout.proto = packetio.Ethernet.IP

		self.ipout.src   = '0.0.0.0'
		self.ipout.dst   = '255.255.255.255'
		self.ipout.proto = packetio.IP.UDP

		self.udpout.src = 68
		self.udpout.dst = 67

		dhcp = packetio.DHCP_Request()
		dhcp.clientmac = self.mac

		dhcp.pack()

		pkt = dhcp.pack()

		print `pkt`

		pkt = self.udpout.pack(pkt)
		pkt = self.ipout.pack(pkt)
		pkt = self.ethout.pack(pkt)

		self.Outbound(pkt)

		self.Loop()

	def Loop(self):
		try:
			self.pd.loop(self.Inbound, -1)
		except KeyboardInterrupt:
			print

		self.pd.close()

	def Outbound(self, pkt):
		print 'Sending'
		self.pd.sendpacket(pkt)

	def Inbound(self, pkt, pktlen, sec, usec, args):
		pkt = self.ethin.unpack(pkt)

		# make assumptions about return packets
		self.ethout.dst = self.ethin.src
		self.ethout.src = self.mac
		self.ethout.proto = self.ethin.proto

		if 0x0800 == self.ethin.proto:
			self.HandleIP(pkt)
		elif 0x0806 == self.ethin.proto:
			self.HandleARP(pkt)

	def HandleIP(self, pkt):
		pkt = self.ipin.unpack(pkt)

		self.ipout.dst = self.ipin.src
		self.ipout.src = self.ip
		self.ipout.proto = self.ipin.proto

		if 1 == self.ipin.proto:
			self.HandleICMP(pkt)
		elif 6 == self.ipin.proto:
			self.HandleTCP(pkt)
		elif 17 == self.ipin.proto:
			self.HandleUDP(pkt)
		else:
			print 'Unknown proto:', self.ipin.proto

	def HandleTCP(self, pkt):
		#print 'TCP'
		pass

	def HandleUDP(self, pkt):
		#print 'UDP'
		pass

	def HandleICMP(self, pkt):
		pkt = self.icmpin.unpack(pkt)
		if 0 == self.icmpin.type:
			icmp = packetio.ICMP_EchoReply(self.icmpin)
		elif 8 == self.icmpin.type:
			icmp = packetio.ICMP_EchoRequest(self.icmpin)
			resp = packetio.ICMP_EchoReply(icmp)
			resp.type = 0
			#print icmp, resp

			self.Outbound(self.ethout.pack(self.ipout.pack(resp.pack(pkt))))
		else:
			print 'Unknown ICMP:', self.icmpin

	def HandleARP(self, pkt):
		pkt = self.arpin.unpack(pkt)

		# ARP REQUEST
		if 0x0001 == self.arpin.op:
			if self.arpin.dst_ip == self.ip:
				# constrcut REPLY
				self.arpout = packetio.ARP()
				self.arpout.op = 0x0002
				self.arpout.dst_mac = self.arpin.src_mac
				self.arpout.dst_ip  = self.arpin.src_ip
				self.arpout.src_mac = self.mac
				self.arpout.src_ip  = self.ip

				print self.ethout
				print self.arpout

				self.Outbound(self.ethout.pack(self.arpout.pack()))

if '__main__' == __name__:
	devices = GhostAdapter.GetDevices()

	if 1 == len(sys.argv):
		print
		print 'Usage:', sys.argv[0], '<adapter>'
		print
		print 'Possible Devices'
		print '=' * 40
		for device in devices:
			if 'mac' not in devices[device]:
				continue

			print '%8s' % (device),
			print ':'.join('%.2x' % ord(o) for o in devices[device]['mac']),
			if 'ip' in devices[device]:
				print devices[device]['ip'],
			print

		sys.exit(0)

	device = sys.argv[1]

	if device not in devices:
		print 'Error: invalid device: %s', device
		sys.exit(-1)

	if 0:
		settings = {
			'mac'     : '00:22:44:66:88:aa',
			'ip'      : '172.30.77.66',
			'netmask' : '255.255.255.0',
			}
	else:
		settings = None

	ghost = GhostAdapter(device, settings)

