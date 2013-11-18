#!/usr/bin/env python
'''
log2cef
Log processing (agent) module

Copyright 2013 J.R. Murray (jr.murray@gmail.com)
This program is distributed under the terms of the GNU General Public License version 3.0.

'''
import ConfigParser
import cef
import re
import time
#import datetime
from datetime import datetime, timedelta
from pytz import timezone
import pytz
import calendar

class LogProcessor(object):

	def __init__(self, agentconfig_file):
		self.log_agents = {}

		config = ConfigParser.SafeConfigParser({
			'regex': None,
			'lines': '1',
			'signatureId': None,
			'name': None,
			'severity': None,

			'message': None,
			'ApplicationProtocol': None,
			'baseEventCount': None,
			'bytesIn': None,
			'bytesOut': None,
			'transportProtocol': None,
			'endTime': None,
			'startTime': None,
			'receiptTime': None,

			'deviceVendor': None,
			'deviceProduct': None,
			'deviceVersion': None,
			'deviceAction': None,
			'deviceAddress': None,
			'deviceHostName': None,
			'deviceDnsDomain': None,
			'deviceTranslatedAddress': None,
			'deviceMacAddress': None,
			'deviceDirection': None,
			'deviceExternalId': None,
			'deviceFacility': None,
			'deviceInboundInterface': None,
			'deviceOutboundInterface': None,
			'deviceProcessName': None,
			'deviceEventCategory': None,
			'externalId': None,

			'destinationAddress': None,
			'destinationHostName': None,
			'destinationMacAddress': None,
			'destinationNtDomain': None,
			'destinationDnsDomain': None,
			'destinationPort': None,
			'destinationUserID': None,
			'destinationUserPrivileges': None,
			'destinationUserName': None,
			'destinationProcessName': None,
			'destinationServiceName': None,
			'destinationTranslatedAddress': None,
			'destinationTranslatedPort': None,

			'sourceAddress':  None,
			'sourceHostName':  None,
			'sourceMacAddress':  None,
			'sourceNtDomain':  None,
			'sourceDnsDomain':  None,
			'sourcePort':  None,
			'sourceUserID':  None,
			'sourceUserPrivileges':  None,
			'sourceUserName':  None,
			#'sourceProcessName':  None,
			'sourceServiceName':  None,
			'sourceTranslatedAddress':  None,
			'sourceTranslatedPort':  None,

			'requestClientApplication': None,
			'requestCookies': None,
			'requestMethod': None,
			'requestURL': None,

			'fileName': None,
			'fileSize': None,
			'fileCreateTime': None,
			'fileHash': None,
			'fileId': None,
			'fileModificationTime': None,
			'filePath': None,
			'filePermission': None,
			'fileType': None,

			'oldFileCreateTime': None,
			'oldfileHash': None,
			'oldFileId': None,
			'oldfileModificationTime': None,
			'oldfilePath': None,
			'oldfilePermission': None,
			'oldfsize': None,
			'oldfileType':  None,

			'deviceCustomString1Label': None,
			'deviceCustomString2Label': None,
			'deviceCustomString3Label': None,
			'deviceCustomString4Label': None,
			'deviceCustomString5Label': None,
			'deviceCustomString6Label': None,
			'deviceCustomNumber1Label': None,
			'deviceCustomNumber2Label': None,
			'deviceCustomNumber3Label': None,
			'deviceCustomDate1Label': None,
			'deviceCustomDate2Label': None,
			'deviceCustomString1': None,
			'deviceCustomString2': None,
			'deviceCustomString3': None,
			'deviceCustomString4': None,
			'deviceCustomString5': None,
			'deviceCustomString6': None,
			'deviceCustomNumber1': None,
			'deviceCustomNumber2': None,
			'deviceCustomNumber3': None,
			'deviceCustomDate1': None,
			'deviceCustomDate2': None,
			})

		config.read(agentconfig_file)
		sections = config.sections()
		for s in sections:
			# Create a new instance of LogAgent
			a = LogAgent()

			a.regex = config.get(s, 'regex')
			if a.regex is not None:
				a.pattern = re.compile(a.regex)
			a.lines = config.getint(s, 'lines')

			a.message.signatureId = config.get(s, 'signatureId')
			a.message.name = config.get(s, 'name')
			a.message.severity = config.get(s, 'severity')

			a.message.message = config.get(s, 'message')
			a.message.ApplicationProtocol = config.get(s, 'ApplicationProtocol')
			a.message.baseEventCount = config.get(s, 'baseEventCount')
			a.message.bytesIn = config.get(s, 'bytesIn')
			a.message.bytesOut = config.get(s, 'bytesOut')
			a.message.transportProtocol = config.get(s, 'transportProtocol')

			a.message.endTime = config.get(s, 'endTime')
			a.message.startTime = config.get(s, 'startTime')
			a.message.receiptTime = config.get(s, 'receiptTime')

			a.message.deviceVendor = config.get(s, 'deviceVendor')
			a.message.deviceProduct = config.get(s, 'deviceProduct')
			a.message.deviceVersion = config.get(s, 'deviceVersion')
			a.message.deviceAction = config.get(s, 'deviceAction')
			a.message.deviceAddress = config.get(s, 'deviceAddress')
			a.message.deviceHostName = config.get(s, 'deviceHostName')
			a.message.deviceDnsDomain = config.get(s, 'deviceDnsDomain')
			a.message.deviceTranslatedAddress = config.get(s, 'deviceTranslatedAddress')
			a.message.deviceMacAddress = config.get(s, 'deviceMacAddress')
			a.message.deviceDirection = config.get(s, 'deviceDirection')
			a.message.deviceExternalId = config.get(s, 'deviceExternalId')
			a.message.deviceFacility = config.get(s, 'deviceFacility')
			a.message.deviceInboundInterface = config.get(s, 'deviceInboundInterface')
			a.message.deviceOutboundInterface = config.get(s, 'deviceOutboundInterface')
			a.message.deviceProcessName = config.get(s, 'deviceProcessName')
			a.message.deviceEventCategory = config.get(s, 'deviceEventCategory')
			a.message.externalId = config.get(s, 'externalId')

			# CEFNode objects
			a.message.destination.Address = config.get(s, 'destinationAddress')
			a.message.destination.HostName = config.get(s, 'destinationHostName')
			a.message.destination.MacAddress = config.get(s, 'destinationMacAddress')
			a.message.destination.NtDomain = config.get(s, 'destinationNtDomain')
			a.message.destination.DnsDomain = config.get(s, 'destinationDnsDomain')
			a.message.destination.Port = config.get(s, 'destinationPort')
			a.message.destination.UserID = config.get(s, 'destinationUserID')
			a.message.destination.UserPrivileges = config.get(s, 'destinationUserPrivileges')
			a.message.destination.UserName = config.get(s, 'destinationUserName')
			a.message.destination.ProcessName = config.get(s, 'destinationProcessName')
			a.message.destination.ServiceName = config.get(s, 'destinationServiceName')
			a.message.destination.TranslatedAddress = config.get(s, 'destinationTranslatedAddress')
			a.message.destination.TranslatedPort = config.get(s, 'destinationTranslatedPort')
		
			a.message.source.Address = config.get(s, 'sourceAddress')
			a.message.source.HostName = config.get(s, 'sourceHostName')
			a.message.source.MacAddress = config.get(s, 'sourceMacAddress')
			a.message.source.NtDomain = config.get(s, 'sourceNtDomain')
			a.message.source.DnsDomain = config.get(s, 'sourceDnsDomain')
			a.message.source.Port = config.get(s, 'sourcePort')
			a.message.source.UserID = config.get(s, 'sourceUserID')
			a.message.source.UserPrivileges = config.get(s, 'sourceUserPrivileges')
			a.message.source.UserName = config.get(s, 'sourceUserName')
			#a.message.source.ProcessName = config.get(s, 'sourceProcessName')
			a.message.source.ServiceName = config.get(s, 'sourceServiceName')
			a.message.source.TranslatedAddress = config.get(s, 'sourceTranslatedAddress')
			a.message.source.TranslatedPort = config.get(s, 'sourceTranslatedPort')

			a.message.requestClientApplication = config.get(s, 'requestClientApplication')
			a.message.requestCookies = config.get(s, 'requestCookies')
			a.message.requestMethod = config.get(s, 'requestMethod')
			a.message.requestURL = config.get(s, 'requestURL')

			a.message.fileName = config.get(s, 'fileName')
			a.message.fileSize = config.get(s, 'fileSize')
			a.message.fileCreateTime = config.get(s, 'fileCreateTime')
			a.message.fileHash = config.get(s, 'fileHash')
			a.message.fileId = config.get(s, 'fileId')
			a.message.fileModificationTime = config.get(s, 'fileModificationTime')
			a.message.filePath = config.get(s, 'filePath')
			a.message.filePermission = config.get(s, 'filePermission')
			a.message.fileType = config.get(s, 'fileType')

			a.message.oldFileCreateTime = config.get(s, 'oldFileCreateTime')
			a.message.oldfileHash = config.get(s, 'oldfileHash')
			a.message.oldFileId = config.get(s, 'oldFileId')
			a.message.oldfileModificationTime = config.get(s, 'oldfileModificationTime')
			a.message.oldfilePath = config.get(s, 'oldfilePath')
			a.message.oldfilePermission = config.get(s, 'oldfilePermission')
			a.message.oldfsize = config.get(s, 'oldfsize')
			a.message.oldfileType = config.get(s, 'oldfileType')

			a.message.deviceCustomString1Label = config.get(s, 'deviceCustomString1Label')
			a.message.deviceCustomString2Label = config.get(s, 'deviceCustomString2Label')
			a.message.deviceCustomString3Label = config.get(s, 'deviceCustomString3Label')
			a.message.deviceCustomString4Label = config.get(s, 'deviceCustomString4Label')
			a.message.deviceCustomString5Label = config.get(s, 'deviceCustomString5Label')
			a.message.deviceCustomString6Label = config.get(s, 'deviceCustomString6Label')
			a.message.deviceCustomNumber1Label = config.get(s, 'deviceCustomNumber1Label')
			a.message.deviceCustomNumber2Label = config.get(s, 'deviceCustomNumber2Label')
			a.message.deviceCustomNumber3Label = config.get(s, 'deviceCustomNumber3Label')
			a.message.deviceCustomDate1Label = config.get(s, 'deviceCustomDate1Label')
			a.message.deviceCustomDate2Label = config.get(s, 'deviceCustomDate2Label')
			a.message.deviceCustomString1 = config.get(s, 'deviceCustomString1')
			a.message.deviceCustomString2 = config.get(s, 'deviceCustomString2')
			a.message.deviceCustomString3 = config.get(s, 'deviceCustomString3')
			a.message.deviceCustomString4 = config.get(s, 'deviceCustomString4')
			a.message.deviceCustomString5 = config.get(s, 'deviceCustomString5')
			a.message.deviceCustomString6 = config.get(s, 'deviceCustomString6')
			a.message.deviceCustomNumber1 = config.get(s, 'deviceCustomNumber1')
			a.message.deviceCustomNumber2 = config.get(s, 'deviceCustomNumber2')
			a.message.deviceCustomNumber3 = config.get(s, 'deviceCustomNumber3')
			a.message.deviceCustomDate1 = config.get(s, 'deviceCustomDate1')
			a.message.deviceCustomDate2 = config.get(s, 'deviceCustomDate2')

			self.log_agents[s] = a
		# Agents config file processing completed



	def parse(self, log_agent, line, date_format, log_timezone='UTC', tz_dst = True):
		out = cef.CEFMessage()
		a = self.log_agents[log_agent]
		m = a.pattern.search(line)

		# If there is a regular expression match, populate any fields in the CEF message
		# that are specified in the configuration.
		if m:
			# Convert the datetime using the offset and formats specified
			# Target format is ms since epoch (standard epoch * 1000)

			# Finalize the offset value based on whether or not we are currently in DST.
			#t = time.localtime
			'''
			if time.localtime().tm_isdst and tz_dst:
				tmp_offset = int(log_timezone[0:3])
				tmp_offset += 1
				
				if tmp_offset < 0:
					log_timezone = "-" + str(abs(tmp_offset)).zfill(2) + log_timezone[3:]
				else:
					log_timezone = "+" + str(tmp_offset).zfill(2) + log_timezone[3:]
			'''
			#def convert_epoch(self, timestamp, date_format, log_timezone):
			
			# Timestamps (express in milliseconds since epoch)
			if a.message.endTime is not None:
				out.endTime = m.group(int(a.message.endTime))
				out.endTime = convert_epoch(out.endTime, date_format, log_timezone)
			if a.message.startTime is not None:
				out.startTime = m.group(int(a.message.startTime))
				out.startTime = convert_epoch(out.startTime, date_format, log_timezone)
			if a.message.receiptTime is not None:
				out.receiptTime = m.group(int(a.message.receiptTime))
				out.receiptTime = convert_epoch(out.receiptTime, date_format, log_timezone)

			
			if a.message.signatureId is not None:
				out.signatureId = m.group(int(a.message.signatureId))
			if a.message.name is not None:
				out.name = m.group(int(a.message.name))
			if a.message.severity is not None:
				out.severity = m.group(int(a.message.severity))

			if a.message.message is not None:
				out.message = m.group(int(a.message.message))
			if a.message.ApplicationProtocol is not None:
				out.ApplicationProtocol = m.group(int(a.message.ApplicationProtocol))
			if a.message.baseEventCount is not None:
				out.baseEventCount = m.group(int(a.message.baseEventCount))
			if a.message.bytesIn is not None:
				out.bytesIn = m.group(int(a.message.bytesIn))
			if a.message.bytesOut is not None:
				out.bytesOut = m.group(int(a.message.bytesOut))
			if a.message.transportProtocol is not None:
				out.transportProtocol = m.group(int(a.message.transportProtocol))
		
			if a.message.deviceVendor is not None:
				out.deviceVendor = m.group(int(a.message.deviceVendor))
			if a.message.deviceProduct is not None:
				out.deviceProduct = m.group(int(a.message.deviceProduct))
			if a.message.deviceVersion is not None:
				out.deviceVersion = m.group(int(a.message.deviceVersion))
			if a.message.deviceAction is not None:
				out.deviceAction = m.group(int(a.message.deviceAction))
			if a.message.deviceAddress is not None:
				out.deviceAddress = m.group(int(a.message.deviceAddress))
			if a.message.deviceHostName is not None:
				out.deviceHostName = m.group(int(a.message.deviceHostName))
			if a.message.deviceDnsDomain is not None:
				out.deviceDnsDomain = m.group(int(a.message.deviceDnsDomain))
			if a.message.deviceTranslatedAddress is not None:
				out.deviceTranslatedAddress = m.group(int(a.message.deviceTranslatedAddress))
			if a.message.deviceMacAddress is not None:
				out.deviceMacAddress = m.group(int(a.message.deviceMacAddress))
			if a.message.deviceDirection is not None:
				out.deviceDirection = m.group(int(a.message.deviceDirection))
			if a.message.deviceExternalId is not None:
				out.deviceExternalId = m.group(int(a.message.deviceExternalId))
			if a.message.deviceFacility is not None:
				out.deviceFacility = m.group(int(a.message.deviceFacility))
			if a.message.deviceInboundInterface is not None:
				out.deviceInboundInterface = m.group(int(a.message.deviceInboundInterface))
			if a.message.deviceOutboundInterface is not None:
				out.deviceOutboundInterface = m.group(int(a.message.deviceOutboundInterface))
			if a.message.deviceProcessName is not None:
				out.deviceProcessName = m.group(int(a.message.deviceProcessName))
			if a.message.deviceEventCategory is not None:
				out.deviceEventCategory = m.group(int(a.message.deviceEventCategory))
			if a.message.externalId is not None:
				out.externalId = m.group(int(a.message.externalId))

			# CEFNode objects
			if a.message.destination.Address is not None:
				out.destination.Address = m.group(int(a.message.destination.Address))
			if a.message.destination.HostName is not None:
				out.destination.HostName = m.group(int(a.message.destination.HostName))
			if a.message.destination.MacAddress is not None:
				out.destination.MacAddress = m.group(int(a.message.destination.MacAddress))
			if a.message.destination.NtDomain is not None:
				out.destination.NtDomain = m.group(int(a.message.destination.NtDomain))
			if a.message.destination.DnsDomain is not None:
				out.destination.DnsDomain = m.group(int(a.message.destination.DnsDomain))
			if a.message.destination.Port is not None:
				out.destination.Port = m.group(int(a.message.destination.Port))
			if a.message.destination.UserID is not None:
				out.destination.UserID = m.group(int(a.message.destination.UserID))
			if a.message.destination.UserPrivileges is not None:
				out.destination.UserPrivileges = m.group(int(a.message.destination.UserPrivileges))
			if a.message.destination.UserName is not None:
				out.destination.UserName = m.group(int(a.message.destination.UserName))
			if a.message.destination.ProcessName is not None:
				out.destination.ProcessName = m.group(int(a.message.destination.ProcessName))
			if a.message.destination.ServiceName is not None:
				out.destination.ServiceName = m.group(int(a.message.destination.ServiceName))
			if a.message.destination.TranslatedAddress is not None:
				out.destination.TranslatedAddress = m.group(int(a.message.destination.TranslatedAddress))
			if a.message.destination.TranslatedPort is not None:
				out.destination.TranslatedPort = m.group(int(a.message.destination.TranslatedPort))

			if a.message.source.Address is not None:
				out.source.Address = m.group(int(a.message.source.Address))
			if a.message.source.HostName is not None:
				out.source.HostName = m.group(int(a.message.source.HostName))
			if a.message.source.MacAddress is not None:
				out.source.MacAddress = m.group(int(a.message.source.MacAddress))
			if a.message.source.NtDomain is not None:
				out.source.NtDomain = m.group(int(a.message.source.NtDomain))
			if a.message.source.DnsDomain is not None:
				out.source.DnsDomain = m.group(int(a.message.source.DnsDomain))
			if a.message.source.Port is not None:
				out.source.Port = m.group(int(a.message.source.Port))
			if a.message.source.UserID is not None:
				out.source.UserID = m.group(int(a.message.source.UserID))
			if a.message.source.UserPrivileges is not None:
				out.source.UserPrivileges = m.group(int(a.message.source.UserPrivileges))
			if a.message.source.UserName is not None:
				out.source.UserName = m.group(int(a.message.source.UserName))
			if a.message.source.ProcessName is not None:
				out.source.ProcessName = m.group(int(a.message.source.ProcessName))
			if a.message.source.ServiceName is not None:
				out.source.ServiceName = m.group(int(a.message.source.ServiceName))
			if a.message.source.TranslatedAddress is not None:
				out.source.TranslatedAddress = m.group(int(a.message.source.TranslatedAddress))
			if a.message.source.TranslatedPort is not None:
				out.source.TranslatedPort = m.group(int(a.message.source.TranslatedPort))

			if a.message.requestClientApplication is not None:
				out.requestClientApplication = m.group(int(a.message.requestClientApplication))
			if a.message.requestCookies is not None:
				out.requestCookies = m.group(int(a.message.requestCookies))
			if a.message.requestMethod is not None:
				out.requestMethod = m.group(int(a.message.requestMethod))
			if a.message.requestURL is not None:
				out.requestURL = m.group(int(a.message.requestURL))

			if a.message.fileName is not None:
				out.fileName = m.group(int(a.message.fileName))
			if a.message.fileSize is not None:
				out.fileSize = m.group(int(a.message.fileSize))
			if a.message.fileCreateTime is not None:
				out.fileCreateTime = m.group(int(a.message.fileCreateTime))
			if a.message.fileHash is not None:
				out.fileHash = m.group(int(a.message.fileHash))
			if a.message.fileId is not None:
				out.fileId = m.group(int(a.message.fileId))
			if a.message.fileModificationTime is not None:
				out.fileModificationTime = m.group(int(a.message.fileModificationTime))
			if a.message.filePath is not None:
				out.filePath = m.group(int(a.message.filePath))
			if a.message.filePermission is not None:
				out.filePermission = m.group(int(a.message.filePermission))
			if a.message.fileType is not None:
				out.fileType = m.group(int(a.message.fileType))

			if a.message.oldFileCreateTime is not None:
				out.oldFileCreateTime = m.group(int(a.message.oldFileCreateTime))
			if a.message.oldfileHash is not None:
				out.oldfileHash = m.group(int(a.message.oldfileHash))
			if a.message.oldFileId is not None:
				out.oldFileId = m.group(int(a.message.oldFileId))
			if a.message.oldfileModificationTime is not None:
				out.oldfileModificationTime = m.group(int(a.message.oldfileModificationTime))
			if a.message.oldfilePath is not None:
				out.oldfilePath = m.group(int(a.message.oldfilePath))
			if a.message.oldfilePermission is not None:
				out.oldfilePermission = m.group(int(a.message.oldfilePermission))
			if a.message.oldfsize is not None:
				out.oldfsize = m.group(int(a.message.oldfsize))
			if a.message.oldfileType is not None:
				out.oldfileType = m.group(int(a.message.oldfileType))
		
			if a.message.deviceCustomString1Label is not None:
				out.deviceCustomString1Label = m.group(int(a.message.deviceCustomString1Label))
			if a.message.deviceCustomString2Label is not None:
				out.deviceCustomString2Label = m.group(int(a.message.deviceCustomString2Label))
			if a.message.deviceCustomString3Label is not None:
				out.deviceCustomString3Label = m.group(int(a.message.deviceCustomString3Label))
			if a.message.deviceCustomString4Label is not None:
				out.deviceCustomString4Label = m.group(int(a.message.deviceCustomString4Label))
			if a.message.deviceCustomString5Label is not None:
				out.deviceCustomString5Label = m.group(int(a.message.deviceCustomString5Label))
			if a.message.deviceCustomString6Label is not None:
				out.deviceCustomString6Label = m.group(int(a.message.deviceCustomString6Label))
			if a.message.deviceCustomNumber1Label is not None:
				out.deviceCustomNumber1Label = m.group(int(a.message.deviceCustomNumber1Label))
			if a.message.deviceCustomNumber2Label is not None:
				out.deviceCustomNumber2Label = m.group(int(a.message.deviceCustomNumber2Label))
			if a.message.deviceCustomNumber3Label is not None:
				out.deviceCustomNumber3Label = m.group(int(a.message.deviceCustomNumber3Label))
			if a.message.deviceCustomDate1Label is not None:
				out.deviceCustomDate1Label = m.group(int(a.message.deviceCustomDate1Label))
			if a.message.deviceCustomDate2Label is not None:
				out.deviceCustomDate2Label = m.group(int(a.message.deviceCustomDate2Label))
			if a.message.deviceCustomString1 is not None:
				out.deviceCustomString1 = m.group(int(a.message.deviceCustomString1))
			if a.message.deviceCustomString2 is not None:
				out.deviceCustomString2 = m.group(int(a.message.deviceCustomString2))
			if a.message.deviceCustomString3 is not None:
				out.deviceCustomString3 = m.group(int(a.message.deviceCustomString3))
			if a.message.deviceCustomString4 is not None:
				out.deviceCustomString4 = m.group(int(a.message.deviceCustomString4))
			if a.message.deviceCustomString5 is not None:
				out.deviceCustomString5 = m.group(int(a.message.deviceCustomString5))
			if a.message.deviceCustomString6 is not None:
				out.deviceCustomString6 = m.group(int(a.message.deviceCustomString6))
			if a.message.deviceCustomNumber1 is not None:
				out.deviceCustomNumber1 = m.group(int(a.message.deviceCustomNumber1))
			if a.message.deviceCustomNumber2 is not None:
				out.deviceCustomNumber2 = m.group(int(a.message.deviceCustomNumber2))
			if a.message.deviceCustomNumber3 is not None:
				out.deviceCustomNumber3 = m.group(int(a.message.deviceCustomNumber3))
			if a.message.deviceCustomDate1 is not None:
				out.deviceCustomDate1 = m.group(int(a.message.deviceCustomDate1))
			if a.message.deviceCustomDate2 is not None:
				out.deviceCustomDate2 = m.group(int(a.message.deviceCustomDate2))
		else:
			print "No match"
		return out

class LogAgent():
	def __init__(self):
		self.regex = None
		self.pattern = None
		self.lines = 1
		self.message = cef.CEFMessage()

def convert_epoch(timestamp, date_format, log_timezone):

	tz = timezone(log_timezone)
	tz_utc = timezone('UTC')
	
	# Read the date and time into a datetime object based on the format specified
	log_date = datetime.strptime(timestamp, date_format)
	if log_timezone != 'UTC':
		log_date = tz.localize(log_date)
		log_date = tz_utc.normalize(log_date)
	
	# Convert to epoch time, assuming the now-converted time is in UTC
	log_epoch = calendar.timegm(log_date.timetuple())
	
	# Convert to ms since epoch (epoch seconds * 1000)
	return int(log_epoch) * 1000
