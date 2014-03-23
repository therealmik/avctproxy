#!/usr/bin/python

from zope.interface import Interface, Attribute, implements, classProvides
import struct
from utils import hexdump


class IAVCTPacket(Interface):
	proto = Attribute("Protocol - generally APCP or AVMP")
	messageType = Attribute("Integer (short) message type")

	def encode():
		"""Encode the packet into a (wire proto) message body"""

	def display():
		"""Create a display of the packet suitable for log files/console output"""


class IAVCTPacketFactory(Interface):
	proto = Attribute("Protocol - generally APCP or AVMP")
	messageType = Attribute("Integer (short) message type")
	minsize = Attribute("Minimum Packet Size - 0 for none")
	maxsize = Attribute("Maximum Packet Size - 65525 for none")

	def parse(data):
		"""Parse the packet and return an object that implements IAVCTPacket"""


class _AvctProto(object):
	minsize = 0
	maxsize = 65525
	#struct_ = struct.Struct(">")
	fieldnames = ()  # Ordered tuple of strings

	# parse, __init__ and encode are provided as a helper for
	# simple fixed-size packets
	@classmethod
	def parse(cls, data):
		return cls(*cls.struct_.unpack(data))

	def __init__(self, *items):
		assert(len(items) == len(self.fieldnames))
		for i in range(len(items)):
			setattr(self, self.fieldnames[i], items[i])

	def encode(self):
		data = [getattr(self, fn) for fn in self.fieldnames]
		return self.struct_.pack(*data)

	def display(self):
		fieldData = [
			fn + "=" + repr(getattr(self, fn))
			for fn in self.fieldnames
			if not fn.startswith("_")
		]
		ret = self.__class__.__name__
		if len(fieldData) > 0:
			ret += ": " + ", ".join(fieldData)
		return ret


class AVMP(_AvctProto):
	proto = "AVMP"


class APCP(_AvctProto):
	proto = "APCP"


class UnsupportedPacket(object):
	implements(IAVCTPacket)

	def __init__(self, proto, messageType, data):
		self.proto = proto
		self.messageType = messageType
		self.data = data

	def display(self):
		return "Proto={0:s} Type=0x{1:04x}:\n{2:s}".format(
			self.proto, self.messageType, hexdump(self.data)
		)

	def encode(self):
		return self.data


class _DiskInfoItem(object):
	_driveTypeStrings = {
		1: "USB",
		2: "CD",
		3: "FLOPPY",
		4: "USBFLOPPY"
	}
	_driveStatusStrings = {
		0: "IDLE",
		1: "ATTACHED",
		2: "DISABLED",
		3: "BROKEN"
	}

	def __init__(self, drivetype, status, capabilities):
		self.drivetype = drivetype
		self.status = status
		self.capabilities = capabilities

	@property
	def drivetype_str(self):
		return self._driveTypeStrings.get(self.drivetype, "Unknown")

	@property
	def drivestatus_str(self):
		return self._driveStatusStrings.get(self.status, "Unknown")

	def display(self):
		return "type={0:s} status={1:s} capabilities={2:d}".format(
			self.drivetype_str, self.drivestatus_str, self.capabilities
		)

	def encode(self):
		return struct.pack(">BBH", self.drivetype, self.status, self.capabilities)


class DiskInfo(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	messageType = 0x8200
	minsize = 4

	def __init__(self, items):
		self.items = items

	@classmethod
	def parse(cls, data):
		numDrives, = struct.unpack(">H", data[2:4])
		if 4 + (numDrives * 4) != len(data):
			raise ValueError("Incorrect length of DiskInfo packet")
		return cls([
			_DiskInfoItem(*struct.unpack(">BBH", data[(i + 1) * 4:(i + 2) * 4]))
			for i in range(numDrives)
		])

	def display(self):
		return "DiskInfo Packet:\n" + "\n".join([x.display() for x in self.items])

	def encode(self):
		header = struct.pack(">I", len(self.items))
		body = "".join([x.encode() for x in self.items])
		return header + body


class MapDisk(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	minsize = 16
	maxsize = 16
	messageType = 0x211
	fieldnames = (
		"driveIndex", "blocksize", "numblocks", "readonly", "_unknown",
		"cylinders", "heads", "sectors"
	)
	struct_ = struct.Struct(">HII?BHBB")


class MapCD(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	minsize = 14
	messageType = 0x210
	struct_ = struct.Struct(">HII?BH")
	fieldnames = (
		"driveIndex", "blocksize", "numblocks", "readonly", "_unknown", "toc"
	)

	@classmethod
	def parse(cls, data):
		fields = list(cls.struct_.unpack(data[:cls.struct_.size]))
		fields.pop(-1)
		fields.append(data[cls.struct_.size:])
		return cls(*fields)

	def encode(self):
		data = [getattr(self, fn) for fn in self.fieldnames]
		toc = data.pop(-1)
		data.append(len(toc))
		return self.struct_.pack(*data) + toc


class UnmapDrive(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	minsize = 2
	maxsize = 2
	messageType = 0x220
	struct_ = struct.Struct(">H")
	fieldnames = ("driveIndex", )

	def __init__(self, driveIndex):
		self.driveIndex = driveIndex


class DeviceStatus(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	struct_ = struct.Struct(">HI")
	minsize = 6
	maxsize = 6
	messageType = 0x8410
	fieldnames = ("driveIndex", "status")


class ReadRequest(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	struct_ = struct.Struct(">HIII")
	minsize = 14
	maxsize = 14
	messageType = 0x8300
	fieldnames = ("driveIndex", "firstBlock", "numBlocks", "blockFactor")


class ReadResponse(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	messageType = 0x300

	fieldnames = ("driveIndex", "firstBlock", "numBlocks", "data")
	struct_ = struct.Struct(">HII")

	@classmethod
	def parse(cls, data):
		fields = list(cls.struct_.unpack(data[:cls.struct_.size]))
		fields.append(data[cls.struct_.size:])
		return cls(*fields)

	def encode(self):
		return self.struct_.pack(
			self.driveIndex, self.firstBlock, self.numBlocks
		) + self.data

	def display(self):
		return self.__class__.__name__ + ": driveIndex=%r firstBlock=%r numBlocks=%r\n" % (
			self.driveIndex, self.firstBlock, self.numBlocks
		) + hexdump(self.data)


class WriteRequest(ReadResponse):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	messageType = 0x8310
	fieldnames = ("driveIndex", "firstBlock", "numBlocks", "data")


class AVMPHeartbeat(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	minsize = 2
	maxsize = 2
	messageType = 0x400
	struct_ = struct.Struct(">xx")

	def display(self):
		return "Heartbeat"


class GetDiskInfo(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	minsize = 2
	maxsize = 2
	messageType = 0x200
	struct_ = struct.Struct(">H")
	fieldnames = ("_ffff", )


class SessionRequest(APCP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	messageType = 0x100
	minsize = 11
	maxsize = 43
	struct_ = struct.Struct(">HBBBBIp")
	fieldnames = (
		"_unused", "byte1", "byte2", "byte3", "byte4",
		"connectionType", "random"
	)

	@classmethod
	def parse(cls, data):
		# Gah, unpack doesn't work for p fmt char
		fmt = struct.Struct(">HBBBBIB")
		fields = list(fmt.unpack(data[:fmt.size]))
		lastField = fields.pop(-1)
		fields.append(data[fmt.size:])
		return cls(*fields)

	def encode(self):
		return struct.pack(
			">HBBBBIB",
			self._unused, self.byte1, self.byte2, self.byte3,
			self.byte4, self.connectionType, len(self.random)
		) + self.random


class SessionSetup(APCP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	messageType = 0x8100
	minsize = 11
	maxsize = 43
	fieldnames = (
		"_unused", "major", "minor", "capabilities", "tcpport", "random"
	)

	@classmethod
	def parse(cls, data):
		# Gah, unpack doesn't work for p fmt char
		fmt = struct.Struct(">HBBIHB")
		fields = list(fmt.unpack(data[:fmt.size]))
		lastField = fields.pop(-1)
		fields.append(data[fmt.size:])
		return cls(*fields)

	def encode(self):
		return struct.pack(
			">HBBIHB",
			self._unused, self.major, self.minor, self.capabilities,
			self.tcpport, len(self.random)
		) + self.random

	def display(self):
		return "SessionSetup: capabilities={0:d} tcpport={1:d}".format(
			self.capabilities, self.tcpport
		)


class LoginRequest(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	messageType = 0x100
	struct_ = struct.Struct(">xxB96s32s8sBBx?")
	fieldnames = (
		"_usernamelen", "_username", "_password", "ripid",
		"portnumber", "cascadechannel", "preempt")
	minsize = 143
	maxsize = 143

	def _get_username(self):
		return self._username[:self._usernamelen]

	def _set_username(self, name):
		if len(name) > 96:
			raise ValueError("Username field is only 96 bytes wide")
		self._usernamelen = len(name)
		self._username = name.ljust(96, '\0')

	username = property(_get_username, _set_username)

	def _get_password(self):
		return self._password.rstrip('\0')

	def _set_password(self, password):
		if len(password) > 32:
			raise ValueError("Password field is only 32 bytes wide")
		self._password = password.ljust(32, '\0')

	password = property(_get_password, _set_password)

	def display(self):
		return "Login username=%r password=%r ripid=%r" % (
			self.username, self.password, self.ripid.encode("hex")
		)


class ClientStatus(AVMP):
	implements(IAVCTPacket)
	classProvides(IAVCTPacketFactory)

	messageType = 0x410
	struct_ = struct.Struct(">HI")
	minsize = 6
	maxsize = 6
	fieldnames = ("driveIndex", "status")


_packettypes = [IAVCTPacketFactory(c) for c in [
	SessionSetup,
	SessionRequest,
	DiskInfo,
	MapDisk,
	MapCD,
	UnmapDrive,
	DeviceStatus,
	ReadRequest,
	ReadResponse,
	WriteRequest,
	AVMPHeartbeat,
	GetDiskInfo,
	LoginRequest,
	ClientStatus,
]]

_packettype_map = {
	(cls.proto, cls.messageType): cls
	for cls in _packettypes
}


def decode(proto, messageType, data):
	try:
		cls = _packettype_map[(proto, messageType)]
	except KeyError:
		return UnsupportedPacket(proto, messageType, data)
	if len(data) < cls.minsize:
		raise ValueError("Packet too small for " + cls.__name__)
	if len(data) > cls.maxsize:
		raise ValueError("Packet too large for " + cls.__name__)
	return cls.parse(data)
