#!/usr/bin/python

from twisted.internet import protocol, endpoints, reactor, defer
from twisted.python import log
from zope.interface import Interface, Attribute, implements
import struct
import os
import argparse
from operator import itemgetter

NBD_REQUEST_MAGIC =     0x25609513
NBD_REPLY_MAGIC   =     0x67446698

NBD_OPT_EXPORT_NAME = 1

NBD_CMD_READ = 0
NBD_CMD_WRITE = 1
NBD_CMD_DISC = 2
NBD_CMD_FLUSH = 3
NBD_CMD_TRIM = 4

class IBlockDevice(Interface):
	size = Attribute("blocksize * nblocks")
	flags = Attribute("NBD export flags")

	def read(offset, length):
		"""Read some data from the blockdev, return a str"""

	def write(offset, data):
		"""Write some data to the blockdev"""

class NBDRequestHeader(object):
	hstruct = struct.Struct("!II8sQI")
	size = hstruct.size

	def __init__(self, data):
		self.magic, self.requestType, self.handle, self.offset, self.length = self.hstruct.unpack(data)

	def __repr__(self):
		return "NBDRequestHeader(magic=%08x, requestType=%r, handle=%r offset=%r length=%r)" % (self.magic, self.requestType, self.handle, self.offset, self.length)

class NBDServer(protocol.Protocol):
	flags = 0

	def connectionMade(self):
		# Initiate a new-new-style handshake
		log.msg("Connection established")
		self.transport.write("NBDMAGIC\x49\x48\x41\x56\x45\x4F\x50\x54\x00\x00")
		self.state = self.initSent
		
	def dataReceived(self, data):
		"""Process the TCP stream and call requestReceived when
		   we have a complete request"""
		if not hasattr(self, 'buf'):
			self.buf = data
		else:
			self.buf += data
		self.state()

	def initSent(self):
		if len(self.buf) < 4:
			return
		if self.buf[:4] != '\0\0\0\0':
			log.msg("Only old-new handshakes supported")
			self.transport.loseConnection()
			return
		self.buf = self.buf[4:]
		log.msg("Negotiated old-new connection type")
		self.state = self.receiveOpts
		self.state()

	def receiveOpts(self):
		if len(self.buf) < 16:
			log.msg("Incomplete magic received in opt")
			return
		if self.buf[:8] != '\x49\x48\x41\x56\x45\x4F\x50\x54':
			log.msg("Invalid magic received")
			self.transport.loseConnection()
			return
		(opt, length) = struct.unpack(">II", self.buf[8:16])
		if len(self.buf) < 16 + length:
			log.msg("Incomplete option received")
			return
		optData = self.buf[16:16+length]
		self.buf = self.buf[16+length:]

		if opt == NBD_OPT_EXPORT_NAME:
			try:
				self.bdev = self.factory.exports[optData]
				reply = struct.pack(">QH124x", self.bdev.size, self.flags)
				self.transport.write(reply)
				log.msg("Export %r mounted by client" % optData)
				self.state = self.dataPhase
				self.state()
			except KeyError:
				log.msg("Export %r not available" % optData)
				self.transport.loseConnection()
				return

	def dataPhase(self):
		while len(self.buf) >= NBDRequestHeader.size:
			header = NBDRequestHeader(self.buf[:NBDRequestHeader.size])
			log.msg("Received %r" % header)
			if header.requestType == NBD_CMD_WRITE:
				if len(self.buf) < header.size + header.length:
					log.msg("Incomplete write request received")
					return
				data = self.buf[header.size:header.size+header.length]
				self.buf = self.buf[header.size+header.length:]
				d = defer.maybeDeferred(self.bdev.write, header.offset, data)
				d.addCallback(self.reply, header.handle)
				d.addErrback(self.errorReply, header.handle)
			elif header.requestType == NBD_CMD_READ:
				self.buf = self.buf[header.size:]
				d = defer.maybeDeferred(self.bdev.read, header.offset, header.length)
				d.addCallback(self.reply, header.handle)
				d.addErrback(self.errorReply, header.handle)
			elif header.requestType == NBD_CMD_DISC:
				self.transport.loseConnection()
				return
			else:
				self.buf = self.buf[header.size:]
				log.msg("Unsupported request type %d" % header.requestType)
				self.transport.write(
					struct.pack(">II8s",
						NBD_REPLY_MAGIC,
						1, # Operation not permitted
						header.handle
					)
				)

	def reply(self, data, handle):
		reply = struct.pack(">II8s", NBD_REPLY_MAGIC, 0, handle)
		if data is not None:
			reply += data
		self.transport.write(reply)
		
	def errorReply(self, reason, handle):
		log.err(reason)
		reply = struct.pack(">II8s", NBD_REPLY_MAGIC, 5, handle)
		self.transport.write(reply)


class NBDServerFactory(protocol.Factory):
	protocol = NBDServer

	def __init__(self, exports):
		self.exports = exports


class FileBlockDevice(object):
	implements(IBlockDevice)

	def __init__(self, filename, readOnly=False):
		if readOnly:
			mode = "rb"
			self.flags = 3
		else:
			mode = "rb+"
			self.flags = 1
		self.fp = open(filename, mode)
		s = os.fstat(self.fp.fileno())
		self.size = s.st_size


	def read(self, offset, length):
		self.fp.seek(offset)
		return self.fp.read(length)

	def write(self, offset, data):
		self.fp.seek(offset)
		self.fp.write(data)
		self.fp.flush()


def main():
	import argparse
	import sys

	def serverEndpoint(x):
		return endpoints.serverFromString(reactor, x)

	def listenFailed(reason):
		log.err(reason)
		reactor.stop()

	def serverListening(_):
		log.msg("NBD Server running")

	log.startLogging(sys.stderr)

	parser = argparse.ArgumentParser(description='NBD Server')
	parser.add_argument('--listen',
		help='Endpoint address to listen on',
		type=serverEndpoint,
		default='tcp:10809:interface=127.0.0.1')
	parser.add_argument('--readonly',
		help='Make the export read-only',
		action='store_true')
	parser.add_argument('filename',
		help='File to serve')
	args = parser.parse_args()

	bdev = FileBlockDevice(args.filename, args.readonly)
	f = NBDServerFactory({os.path.basename(args.filename): bdev})
	d = args.listen.listen(f)
	d.addErrback(listenFailed)
	d.addCallback(serverListening)
	reactor.run()

if __name__ == "__main__":
	main()
