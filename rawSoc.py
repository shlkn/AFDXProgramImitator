import socket
import json
import struct
from dataclasses import dataclass

localSoc = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
#localSoc.bind(("enx34298f70051b", 0))

@dataclass
class EthernetHeader:
	macSrc: list
	macDst: list
	lvl3ProtoType: int = 8 # IPv4

	def __init__(self, macSrc, macDst, lvl3ProtoType = 8):
		self.macSrc = macSrc
		self.macDst = macDst
		self.lvl3ProtoType = lvl3ProtoType

	def makeLVl2Header(self, lvl3msg):
		ethernetHeader = bytearray()
		for fragment in self.macDst:
			ethernetHeader += bytes.fromhex(fragment)
		for fragment in self.macSrc:
			ethernetHeader += bytes.fromhex(fragment)
		ethernetHeader += self.lvl3ProtoType.to_bytes(2, 'little') # costyl` ne trogat`
		ethernetHeader += lvl3msg
		return ethernetHeader

	def parseLvl2Header(self, message):
		dest, src, prototype = struct.unpack('! 6s 6s H', message[:14])
		return dest, src, socket.htons(prototype), message[14:]

@dataclass 
class IPHeader: #https://en.wikipedia.org/wiki/Internet_Protocol_version_4#IHL
	IPSrc: list # ip source
	IPDst: list # ip destenation
	protoVer: int = 4 # lvl 3 protocol version - IPv4 
	IHL: int = 5 #idk what is this
	ToS: int = 0 #type of service
	totalLength: int = 20 #total count of bytes presented in this level frame. must be grater than 20 bytes (cause of header size)
	identification: int = 0 #increments at every msg in VL
	flagsAndFragmentOffset: int = "0000" # first 3 bits - flags, other bits - offset to fragment
	TTL: int = 1 # time to live - present how many hops we can process
	transpProto: int = 17 # shows espesialy which is transport lvl protocols will be used. 17 - udp, 6 - tcp, for more visit - https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers 
	headerChecksum: int = 0 # the checksum of all bites in the this level header


	def __init__(self, IPSrc, IPDst, totalLength = 20, transpProto = 17):
		self.IPSrc = IPSrc
		self.IPDst = IPDst
		self.totalLength = totalLength
		self.transpProto = transpProto

	def ip_checksum(self, ip_header):
		size = len(ip_header)
		cksum = 0
		pointer = 0

		while size > 1:
			cksum += int((str("%02x" % (ip_header[pointer],)) + 
						str("%02x" % (ip_header[pointer+1],))), 16)
			size -= 2
			pointer += 2
		if size: #This accounts for a situation where the header is odd
			cksum += ip_header[pointer]

		cksum = (cksum >> 16) + (cksum & 0xffff)
		cksum += (cksum >>16)
		return (~cksum) & 0xFFFF

	def parseLvl3Header(self, message):
		version_header_length = message[0]
		version = version_header_length >> 4
		header_length = (version_header_length & 15) * 4
		ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', message[:20])
		return version, header_length, ttl, proto, src, target, message[header_length:]



	def makeLVl3Header(self, lvl4msg):
		IPHeaderFirst = (((self.protoVer & 0x0F) << 4) + (self.IHL & 0x0F)).to_bytes(1, "big")
		IPHeaderFirst += self.ToS.to_bytes(1, "big")
		IPHeaderFirst += (self.totalLength + len(lvl4msg)).to_bytes(2, "big")

		IPHeaderFirst += self.identification.to_bytes(2, "big")
		self.identification += 1
		IPHeaderFirst += bytes.fromhex(self.flagsAndFragmentOffset)

		IPHeaderFirst += self.TTL.to_bytes(1, "big")
		IPHeaderFirst += self.transpProto.to_bytes(1, "big")

		self.headerChecksum.to_bytes(2, "big")

		IPHeaderSecond = bytearray()
		for fragment in self.IPSrc:
			IPHeaderSecond += int(fragment).to_bytes(1, "big")
		for fragment in self.IPDst:
			IPHeaderSecond += int(fragment).to_bytes(1, "big")

		checksum = self.ip_checksum(IPHeaderFirst + self.headerChecksum.to_bytes(2, "big") + IPHeaderSecond)
		IPHeader = IPHeaderFirst + checksum.to_bytes(2, "big") + IPHeaderSecond

		IPHeader += lvl4msg
		return IPHeader


@dataclass 
class TransportHeader: #UDP - https://en.wikipedia.org/wiki/User_Datagram_Protocol
	# TCP - https://en.wikipedia.org/wiki/Transmission_Control_Protocol
	portSrc: str # source port
	portDst: str # destenation port
	sequenceNumber: int
	ACK: int #Acknowledgment number
	dataOffset: int = 5 # offset to data  (presented in 32-bit words, 5 - min count)
	reservedAndflags: int = 2 # first 4 bits - reserved, other - flags
	windowSize: str = "7110" # count of reqiered data from other host
	length: int = 8 #total count of bytes presented in this level frame. must be grater than 8 bytes (cause of header size)
	urgentPointer: int = 0 # If the URG flag is set, then this 16-bit field is an offset from the sequence number indicating the last urgent data byte.
	checksum: int = 0 # the checksum of all bites in the this level header


	def __init__(self, portSrc, portDst, length = 8): # for UDP
		self.portSrc = portSrc
		self.portDst = portDst
		self.length = length

	def makeUDPHeader(self, message):
		UDPHeader = self.portSrc.to_bytes(2, "big")
		UDPHeader += self.portDst.to_bytes(2, "big")
		UDPHeader += (self.length + len(message)).to_bytes(2, "big")
		UDPHeader += self.checksum.to_bytes(2, "big")
		if isinstance(message, str):
			UDPHeader += bytes(message, 'utf-8')
		else:
			UDPHeader +=message
		return UDPHeader

	def parseUDPHeader(self, message):
		srcPort, dstPort, msgLen, checksum = struct.unpack('! H H H H', message[:8])
		return srcPort, dstPort, msgLen, checksum, message[8:]


@dataclass
class lo_AFDXRoute:
	ethernetHeaderMaker: EthernetHeader
	IPHeaderMaker: IPHeader
	TransportHeaderMaker: TransportHeader
	socket_to: socket
	socket_from: socket
	serialNumber: int
	
	#lo -> AFDX
	def __init__(self, etherHeaderMaker, IPHeaderMaker, TransportHeaderMaker, addrFrom):
		self.ethernetHeaderMaker = etherHeaderMaker
		self.IPHeaderMaker = IPHeaderMaker
		self.TransportHeaderMaker = TransportHeaderMaker
		self.serialNumber = 0

		#out socket configuration
		self.socket_to = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

		self.socket_to.bind(("lo", 0))
		#self.socket_to.bind(("enx34298f70051b", 0))

		#self.socket_to.setblocking(0)
		self.socket_to.settimeout(0.0000001)


		#in socket configuration
		self.socket_from = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.socket_from.bind(addrFrom)		
		#self.socket_from.setblocking(0)
		self.socket_from.settimeout(0.0000001)

	def retranslateMessagesToDstHost(self):
		try:
			data, address = self.socket_from.recvfrom(4096)
			udp_header = self.TransportHeaderMaker.makeUDPHeader(data)
			ip_header = self.IPHeaderMaker.makeLVl3Header(udp_header)
			fullMsg = self.ethernetHeaderMaker.makeLVl2Header(ip_header)
			fullMsg += self.serialData.to_bytes(1, "big")
			self.serialData += 1


			self.socket_to.send(fullMsg)
			print("Packet sended")
		except socket.timeout:
			return

	#AFDX -> lo
	def retranslateMessagesFromDstHost(self):
		try:
			#localSoc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
			
			#localSoc.bind(("lo", 0))
			localSoc.settimeout(10)
			#localSoc.set_blocking(false)
			raw_data, addr = localSoc.recvfrom(65535)
			unpackedEther = self.ethernetHeaderMaker.parseLvl2Header(raw_data)

			unpackedIP = self.IPHeaderMaker.parseLvl3Header(unpackedEther[3])
			if(socket.inet_ntoa(unpackedIP[5]) != "224.224.86.88"):
				print("not valid ip packet", socket.inet_ntoa(unpackedIP[5]))
				return

			print("mac src - ", unpackedEther[0])
			print("mac dest - ", unpackedEther[1])
			print()

			print("TTL - ", unpackedIP[2])
			print("Proto - ", unpackedIP[3])
			print("IP src - ", socket.inet_ntoa(unpackedIP[4]))
			print("IP dest - ", socket.inet_ntoa(unpackedIP[5]))

			unpackedUDP = self.TransportHeaderMaker.parseUDPHeader(unpackedIP[6])
			print("src port - ", unpackedUDP[0])
			print("dest port - ", unpackedUDP[1])
		except socket.timeout:
			return

									#AFDX -> lo
#--------------------------------------------------------------------------------------------
@dataclass
class AFDX_loRoute:
	socket_to = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socket_from = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
	dstIP: str
	srcIP: str
	dstPort: int
	srcPort: int

	def __init__(self, _dstIP, _srcIP, _dstPort, _srcPort):
		self.dstIP = _dstIP
		self.srcIP = _srcIP
		self.dstPort = _dstPort
		self.srcPort = _srcPort

	def retranslateMessagesFromDstHost(self):
		try:
			#localSoc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
			
			#localSoc.bind(("lo", 0))
			localSoc.settimeout(10)
			#localSoc.set_blocking(false)
			raw_data, addr = localSoc.recvfrom(65535)
			unpackedEther = self.ethernetHeaderMaker.parseLvl2Header(raw_data)

			unpackedIP = self.IPHeaderMaker.parseLvl3Header(unpackedEther[3])
			if(socket.inet_ntoa(unpackedIP[5]) != "224.224.86.88"):
				print("not valid ip packet", socket.inet_ntoa(unpackedIP[5]))
				return

			print("mac src - ", unpackedEther[0])
			print("mac dest - ", unpackedEther[1])
			print()

			print("TTL - ", unpackedIP[2])
			print("Proto - ", unpackedIP[3])
			print("IP src - ", socket.inet_ntoa(unpackedIP[4]))
			print("IP dest - ", socket.inet_ntoa(unpackedIP[5]))

			unpackedUDP = self.TransportHeaderMaker.parseUDPHeader(unpackedIP[6])
			print("src port - ", unpackedUDP[0])
			print("dest port - ", unpackedUDP[1])
		except socket.timeout:
			return

#json with route tables
with open("portIpMacTable.json", "r") as fh:
	myJson = json.load(fh)


#working with lo -> AFDX route
lo_AFDXSockets = list()
lo_AFDX = myJson["lo->AFDX"].items()

for item in lo_AFDX:
	lo_AFDXSockets.append(lo_AFDXRoute(EthernetHeader((item[1]["mac_from"]).split(':'), (item[1]["mac_to"]).split(':')),
	IPHeader((item[1]["ip_from"]).split('.'), (item[1]["ip_to"]).split('.')),
	TransportHeader(item[1]["port_from"], item[1]["port_to"]), tuple((item[1]["localIP_from"], item[1]["localPort_from"]))))



#working with AFDX -> lo route
AFDX_loSockets = list()
AFDX_lo = myJson["AFDX->lo"].items()

for item in lo_AFDX:
	AFDX_loSockets.append(AFDX_loRoute(item[1]["ip_to"], item[1]["ip_from"], item[1]["port_to"], item[1]["port_from"]))




while True:	
	for socketPair in lo_AFDXSockets:
		socketPair.retranslateMessagesFromDstHost()


#socketPair.retranslateMessagesToDstHost()