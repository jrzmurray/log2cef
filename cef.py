'''
log2cef
CEF (common event format) module

Copyright 2013 J.R. Murray (jr.murray@gmail.com)
This program is distributed under the terms of the GNU General Public License version 3.0.

'''
import re

def cefEscape(s):
	#re2 = r"^([^,]*),[0-9]{3} INFO exploit ([^:]*):([^ ]*) -> ([^:]*):([^ ]*) \(([^ ]*) Vulnerability: ([^\)]*)\) \(Shellcode: ([^\)]*)\)"
	s = str(s)
	backslash_escape_re = r"(\\[^rn])"
	s = re.sub(backslash_escape_re, r"\\\1", s)
	s = s.replace("=","\=")
	s = s.replace("|","\|")
	return s

class CEFMessage:
	# CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

	def __init__(self):
		self.version = 1
		
		self.signatureId = 0
		self.name = None
		self.severity = None

		self.message = None
		self.ApplicationProtocol = None
		self.baseEventCount = None
		self.bytesIn = None
		self.bytesOut = None
		self.transportProtocol = None
		
		# Timestamps (express in milliseconds since epoch)
		self.endTime = None
		self.startTime = None
		self.receiptTime = None

		self.deviceVendor = None
		self.deviceProduct = None
		self.deviceVersion = None
		self.deviceAction = None
		self.deviceAddress = None
		self.deviceHostName = None
		self.deviceDnsDomain = None
		self.deviceTranslatedAddress = None
		self.deviceMacAddress = None
		self.deviceDirection = None
		self.deviceExternalId = None
		self.deviceFacility = None
		self.deviceInboundInterface = None
		self.deviceOutboundInterface = None
		self.deviceProcessName = None
		self.deviceEventCategory = None
		self.externalId = None

		# CEFNode objects
		self.destination = CEFNode()
		self.source = CEFNode()

		self.requestClientApplication = None	# User-Agent
		self.requestCookies = None
		self.requestMethod = None
		self.requestURL = None

		self.fileName = None
		self.fileSize = None
		self.fileCreateTime = None
		self.fileHash = None
		self.fileId = None
		self.fileModificationTime = None
		self.filePath = None
		self.filePermission = None
		self.fileType = None

		self.oldFileCreateTime = None
		self.oldfileHash = None
		self.oldFileId = None
		self.oldfileModificationTime = None
		self.oldfilePath = None
		self.oldfilePermission = None
		self.oldfsize = None
		self.oldfileType =  None
		
		self.deviceCustomString1Label = None
		self.deviceCustomString2Label = None
		self.deviceCustomString3Label = None
		self.deviceCustomString4Label = None
		self.deviceCustomString5Label = None
		self.deviceCustomString6Label = None
		self.deviceCustomNumber1Label = None
		self.deviceCustomNumber2Label = None
		self.deviceCustomNumber3Label = None
		self.deviceCustomDate1Label = None
		self.deviceCustomDate2Label = None
		self.deviceCustomString1 = None
		self.deviceCustomString2 = None
		self.deviceCustomString3 = None
		self.deviceCustomString4 = None
		self.deviceCustomString5 = None
		self.deviceCustomString6 = None
		self.deviceCustomNumber1 = None
		self.deviceCustomNumber2 = None
		self.deviceCustomNumber3 = None
		self.deviceCustomDate1 = None
		self.deviceCustomDate2 = None
	
	def write(self):
		#CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
		log = "CEF:" + str(self.version) + \
			"|" + str(self.deviceVendor) + \
			"|" + str(self.deviceProduct) + \
			"|" + str(self.deviceVersion) + \
			"|" + str(self.signatureId) + \
			"|" + str(self.name) + \
			"|" + str(self.severity) + \
			"|"
		if not self.endTime is None: 
			log += "end=" + cefEscape(self.endTime) + " "
		if not self.startTime is None:
			log += "start=" + cefEscape(self.startTime) + " "
		if not self.message is None:
			log += "msg=" + cefEscape(self.message) + " "
		if not self.ApplicationProtocol is None:
			log += "app=" + cefEscape(self.ApplicationProtocol) + " "
		if not self.baseEventCount is None:
			log += "cnt=" + cefEscape(self.baseEventCount) + " "
		if not self.bytesIn is None:
			log += "in=" + cefEscape(self.bytesIn) + " "
		if not self.bytesOut is None:
			log += "out=" + cefEscape(self.bytesOut) + " "
		if not self.transportProtocol is None:
			log += "proto=" + cefEscape(self.transportProtocol) + " "
		if not self.receiptTime is None:
			log += "rt=" + cefEscape(self.receiptTime) + " "
	
		if not self.deviceAction is None:
			log += "act=" + cefEscape(self.deviceAction) + " "
		if not self.deviceAddress is None:
			log += "dvc=" + cefEscape(self.deviceAddress) + " "
		if not self.deviceHostName is None:
			log += "dvchost=" + cefEscape(self.deviceHostName) + " "
		if not self.deviceDnsDomain is None:
			log += "deviceDnsDomain=" + cefEscape(self.deviceDnsDomain) + " "
		if not self.deviceTranslatedAddress is None:
			log += "deviceTranslatedAddress=" + cefEscape(self.deviceTranslatedAddress) + " "
		if not self.deviceMacAddress is None:
			log += "deviceMacAddress=" + cefEscape(self.deviceMacAddress) + " "
		if not self.deviceDirection is None:
			log += "deviceDirection=" + cefEscape(self.deviceDirection) + " "
		if not self.deviceExternalId is None:
			log += "deviceExternalId=" + cefEscape(self.deviceExternalId) + " "
		if not self.deviceFacility is None:
			log += "deviceFacility=" + cefEscape(self.deviceFacility) + " "
		if not self.deviceInboundInterface is None:
			log += "deviceInboundInterface=" + cefEscape(self.deviceInboundInterface) + " "
		if not self.deviceOutboundInterface is None:
			log += "deviceOutboundInterface=" + cefEscape(self.deviceOutboundInterface) + " "
		if not self.deviceProcessName is None:
			log += "deviceProcessName=" + cefEscape(self.deviceProcessName) + " "
		if not self.deviceEventCategory is None:
			log += "cat=" + cefEscape(self.deviceEventCategory) + " "
		if not self.externalId is None:
			log += "externalId=" + cefEscape(self.externalId) + " "

		if not self.destination.Address is None:
			log += "dst=" + cefEscape(self.destination.Address) + " "
		if not self.destination.HostName is None:
			log += "dhost=" + cefEscape(self.destination.HostName) + " "
		if not self.destination.MacAddress is None:
			log += "dmac=" + cefEscape(self.destination.MacAddress) + " "
		if not self.destination.NtDomain is None:
			log += "dntdom=" + cefEscape(self.destination.NtDomain) + " "
		if not self.destination.DnsDomain is None:
			log += "destinationDnsDomain=" + cefEscape(self.destination.DnsDomain) + " "
		if not self.destination.Port is None:
			log += "dpt=" + cefEscape(self.destination.Port) + " "
		if not self.destination.UserID is None:
			log += "duid=" + cefEscape(self.destination.UserID) + " "
		if not self.destination.UserPrivileges is None:
			log += "dpriv=" + cefEscape(self.destination.UserPrivileges) + " "
		if not self.destination.UserName is None:
			log += "duser=" + cefEscape(self.destination.UserName) + " "
		if not self.destination.ProcessName is None:
			log += "dproc=" + cefEscape(self.destination.ProcessName) + " "
		if not self.destination.ServiceName is None:
			log += "destinationServiceName=" + cefEscape(self.destination.ServiceName) + " "
		if not self.destination.TranslatedAddress is None:
			log += "destinationTranslatedAddress=" + cefEscape(self.destination.TranslatedAddress) + " "
		if not self.destination.TranslatedPort is None:
			log += "destinationTranslatedPort=" + cefEscape(self.destination.TranslatedPort) + " "

		if not self.source.Address is None:
			log += "src=" + cefEscape(self.source.Address) + " "
		if not self.source.HostName is None:
			log += "shost=" + cefEscape(self.source.HostName) + " "
		if not self.source.MacAddress is None:
			log += "smac=" + cefEscape(self.source.MacAddress) + " "
		if not self.source.NtDomain is None:
			log += "sntdom=" + cefEscape(self.source.NtDomain) + " "
		if not self.source.DnsDomain is None:
			log += "sourceDnsDomain=" + cefEscape(self.source.DnsDomain) + " "
		if not self.source.Port is None:
			log += "spt=" + cefEscape(self.source.Port) + " "
		if not self.source.UserID is None:
			log += "suid=" + cefEscape(self.source.UserID) + " "
		if not self.source.UserPrivileges is None:
			log += "spriv=" + cefEscape(self.source.UserPrivileges) + " "
		if not self.source.UserName is None:
			log += "suser=" + cefEscape(self.source.UserName) + " "
		#if not self.source.ProcessName is None:
		#	log += "=" + cefEscape(self.source.ProcessName) + " "
		if not self.source.ServiceName is None:
			log += "ServiceName=" + cefEscape(self.source.ServiceName) + " "
		if not self.source.TranslatedAddress is None:
			log += "sourceTranslatedAddress=" + cefEscape(self.source.TranslatedAddress) + " "
		if not self.source.TranslatedPort is None:
			log += "sourceTranslatedPort=" + cefEscape(self.source.TranslatedPort) + " "

		if not self.requestClientApplication is None:
			log += "requestClientApplication=" + cefEscape(self.requestClientApplication) + " "	# User-Agent
		if not self.requestCookies is None:
			log += "requestCookies=" + cefEscape(self.requestCookies) + " "
		if not self.requestMethod is None:
			log += "requestMethod=" + cefEscape(self.requestMethod) + " "
		if not self.requestURL is None:
			log += "request=" + cefEscape(self.requestURL) + " "

		if not self.fileName is None:
			log += "fname=" + cefEscape(self.fileName) + " "
		if not self.fileSize is None:
			log += "fsize=" + cefEscape(self.fileSize) + " "
		if not self.fileCreateTime is None:
			log += "fileCreateTime=" + cefEscape(self.fileCreateTime) + " "
		if not self.fileHash is None:
			log += "fileHash=" + cefEscape(self.fileHash) + " "
		if not self.fileId is None:
			log += "fileId=" + cefEscape(self.fileId) + " "
		if not self.fileModificationTime is None:
			log += "fileModificationTime=" + cefEscape(self.fileModificationTime) + " "
		if not self.filePath is None:
			log += "filePath=" + cefEscape(self.filePath) + " "
		if not self.filePermission is None:
			log += "filePermission=" + cefEscape(self.filePermission) + " "
		if not self.fileType is None:
			log += "fileType=" + cefEscape(self.fileType) + " "

		if not self.oldFileCreateTime is None:
			log += "oldFileCreateTime=" + cefEscape(self.oldFileCreateTime) + " "
		if not self.oldfileHash is None:
			log += "oldfileHash=" + cefEscape(self.oldfileHash) + " "
		if not self.oldFileId is None:
			log += "oldFileId=" + cefEscape(self.oldFileId) + " "
		if not self.oldfileModificationTime is None:
			log += "oldfileModificationTime=" + cefEscape(self.oldfileModificationTime) + " "
		if not self.oldfilePath is None:
			log += "oldfilePath=" + cefEscape(self.oldfilePath) + " "
		if not self.oldfilePermission is None:
			log += "oldfilePermission=" + cefEscape(self.oldfilePermission) + " "
		if not self.oldfsize is None:
			log += "oldfsize=" + cefEscape(self.oldfsize) + " "
		if not self.oldfileType is  None:
			log += "oldfileType=" + cefEscape(self.oldfileType) + " "

		if not self.deviceCustomString1Label is None:
			log += "cs1Label=" + cefEscape(self.deviceCustomString1Label) + " "
		if not self.deviceCustomString2Label is None:
			log += "cs2Label=" + cefEscape(self.deviceCustomString2Label) + " "
		if not self.deviceCustomString3Label is None:
			log += "cs3Label=" + cefEscape(self.deviceCustomString3Label) + " "
		if not self.deviceCustomString4Label is None:
			log += "cs4Label=" + cefEscape(self.deviceCustomString4Label) + " "
		if not self.deviceCustomString5Label is None:
			log += "cs5Label=" + cefEscape(self.deviceCustomString5Label) + " "
		if not self.deviceCustomString6Label is None:
			log += "cs6Label=" + cefEscape(self.deviceCustomString6Label) + " "
		if not self.deviceCustomNumber1Label is None:
			log += "cn1Label=" + cefEscape(self.deviceCustomNumber1Label) + " "
		if not self.deviceCustomNumber2Label is None:
			log += "cn2Label=" + cefEscape(self.deviceCustomNumber2Label) + " "
		if not self.deviceCustomNumber3Label is None:
			log += "cn3Label=" + cefEscape(self.deviceCustomNumber3Label) + " "
		if not self.deviceCustomDate1Label is None:
			log += "deviceCustomDate1Label=" + cefEscape(self.deviceCustomDate1Label) + " "
		if not self.deviceCustomDate2Label is None:
			log += "deviceCustomDate2Label=" + cefEscape(self.deviceCustomDate2Label) + " "

		if not self.deviceCustomString1 is None:
			log += "cs1=" + cefEscape(self.deviceCustomString1) + " "
		if not self.deviceCustomString2 is None:
			log += "cs2=" + cefEscape(self.deviceCustomString2) + " "
		if not self.deviceCustomString3 is None:
			log += "cs3=" + cefEscape(self.deviceCustomString3) + " "
		if not self.deviceCustomString4 is None:
			log += "cs4=" + cefEscape(self.deviceCustomString4) + " "
		if not self.deviceCustomString5 is None:
			log += "cs5=" + cefEscape(self.deviceCustomString5) + " "
		if not self.deviceCustomString6 is None:
			log += "cs6=" + cefEscape(self.deviceCustomString6) + " "
		if not self.deviceCustomNumber1 is None:
			log += "cn1=" + cefEscape(self.deviceCustomNumber1) + " "
		if not self.deviceCustomNumber2 is None:
			log += "cn2=" + cefEscape(self.deviceCustomNumber2) + " "
		if not self.deviceCustomNumber3 is None:
			log += "cn3=" + cefEscape(self.deviceCustomNumber3) + " "
		if not self.deviceCustomDate1 is None:
			log += "deviceCustomDate1=" + cefEscape(self.deviceCustomDate1) + " "
		if not self.deviceCustomDate2 is None:
			log += "deviceCustomDate2=" + cefEscape(self.deviceCustomDate2) + " "
			
		return log

class CEFNode:
	def __init__(self):
		self.Address = None
		self.HostName = None
		self.MacAddress = None
		self.NtDomain = None
		self.DnsDomain = None
		self.Port = None
		self.UserID = None
		self.UserPrivileges = None
		self.UserName = None
		self.ProcessName = None
		self.ServiceName = None
		self.TranslatedAddress = None
		self.TranslatedPort = None

