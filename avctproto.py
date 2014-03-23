#!/usr/bin/python

from twisted.internet import protocol
from twisted.python import log

import struct

from utils import hexdump
import avctpacket


class NotEnoughData(Exception):
	pass


class AvctProtocol(protocol.Protocol):
	ready = True
	passthrough = False

	def dataReceived(self, data):
		if self.passthrough:
			return self.passthroughData(data)

		if not hasattr(self, 'buf'):
			self.buf = ''

		self.buf += data

		if not self.ready:
			return

		try:
			while len(self.buf) > 4:
				if self.buf[0:4] in ('APCP', 'AVMP'):
					self.processAPCPorAVMP()
				elif self.buf[0:4] in ('BEEF', '\0\0\0\0'):
					self.processBEEF()
				else:
					self.enterPassthrough()
		except NotEnoughData:
			pass

	def enterPassthrough(self):
		log.msg("Entering passthrough mode")
		self.passthrough = True
		if len(self.buf) > 0:
			self.passthroughData(self.buf)
			self.buf = ''

	def processAPCPorAVMP(self):
		if len(self.buf) < 10:
			raise NotEnoughData()

		avctProto, messageLength, messageType = struct.unpack(">4sIH", self.buf[:10])
		if len(self.buf) < messageLength:
			raise NotEnoughData()
		data = self.buf[10:messageLength]
		self.buf = self.buf[messageLength:]
		try:
			packet = avctpacket.decode(avctProto, messageType, data)
			self.messageReceived(packet)
		except Exception, e:
			log.err()
			log.msg("Proto: {0:s} MessageType: 0x{1:04x}\n{2:s}".format(
				avctProto, messageType, hexdump(data)
			))

	def processBEEF(self):
		if len(self.buf) < 8:
			raise NotEnoughData()
		avctProto, messageType, messageLength = struct.unpack(">4sHH", self.buf[:8])
		if len(self.buf) < messageLength:
			raise NotEnoughData()
		data = self.buf[8:messageLength]
		self.buf = self.buf[messageLength:]
		try:
			packet = avctpacket.decode(avctProto, messageType, data)
			self.messageReceived(packet)
		except Exception, e:
			log.err()
			log.msg("Proto: {0:s} MessageType: 0x{1:04x}\n{2:s}".format(
				avctProto, messageType, hexdump(data)
			))

	def sendMessage(self, packet):
		"""Send an AVMP/APCP message"""
		body = packet.encode()
		if packet.proto in ('BEEF', '\0\0\0\0'):
			header = struct.pack(
				">4sHH",
				packet.proto, packet.messageType, len(body) + 8
			)
		elif packet.proto in ('APCP', 'AVMP'):
			header = struct.pack(
				">4sIH",
				packet.proto, len(body) + 10, packet.messageType
			)
		self.transport.write(header + body)

	def messageReceived(self, packet):
		"""Called when a full message is received from the peer"""

	def passthroughData(self, data):
		"""Called when we failed back to passthrough mode"""
