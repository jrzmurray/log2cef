#!/usr/bin/env python
'''
log2cef
Main module

Copyright 2013 J.R. Murray (jr.murray@gmail.com)
This program is distributed under the terms of the GNU General Public License version 3.0.
Tested with Python 2.7 on Windows 8

Configuration files:
1. User input
	Log file sources
	Parser agent to use

2. Parser configuration(s)
	Future setup:
	1 file - standard (built in) agents
	2 - user-defined agents

Future updates
	Filtering (boolean)
	Remote configuration / updates
		Auto-update setting
		Update log (log directory)
	Email error notifications

Input types:
	Regex
'''

import sys
import re
import socket
import os
import time
#import datetime
import ConfigParser
import logging

import cef
import cefagent

# Configuration - move to config file later
# Follow CEF specification 1:1


def is_valid_ip(ip):
	# Validates IPv4 addresses
	pattern = re.compile(r"""^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$""", re.VERBOSE | re.IGNORECASE)
	return pattern.match(ip) is not None

def ipv4_int(ip):
	# Convert IP address into an integer value
	# which can be stored in a database. 
	# This allows < and > comparison.
	if is_valid_ip(ip):
		ipa = ip.split('.')
		b1 = (256 * 256 * 256) * int(ipa[0])
		b2 = 256 * 256 * int(ipa[1])
		b3 = 256 * int(ipa[2])
		b4 = int(ipa[3])
		return b1 + b2 + b3 + b4
	else:
		return 0

def getFileSize(f):
	f_stats = os.stat(f)
	f_size = f_stats[6]
	return f_size

def xml_escape(str):
	str = str.replace("&","&amp;")
	str = str.replace("'", "&apos;")
	str = str.replace('"', "&quot;")
	str = str.replace("<", "&lt;")
	str = str.replace(">", "&gt;")
	return str

def sanitize(str):
	sanitizer = re.compile(r'[^\x20-\x7E]')
	str = re.sub(sanitizer, '', str)
	return str

def truncate(str, max_length):
	return (str[:max_length-3] + '...') if len(str) > max_length else str

def email(sender, recipients, subject, message, smtp_server):
	# recipients is an array
	
	try:
		# Determine the name of the script and capitalize the first letter
		script_base = os.path.basename(sys.argv[0])
		# Remove the file extension
		script_name = os.path.splitext(script_base)[0]
		# Capitalize
		script_name = script_name.capitalize()
		
		#email_text = "Messages generated during " + script_name + " script: \n"
		email_text = message
		
		email_msg = MIMEText(email_text)
		#email_msg['Subject'] = script_name + ' Messages'
		email_msg['Subject'] = subject
		email_msg['From'] = sender
		email_msg['To'] = recipients
		email = SMTP(smtp_server)
		email.sendmail(sender, recipients.split(","), email_msg.as_string())
	except BaseException, e:
		raise BaseException('Error sending mail: ' + str(e))

def syslog(message, host, port=514, utf8=True):
	try:
		# Convert message to UTF-8
		if utf8:
			message = message.encode('utf-8')

		# Send syslog UDP packet to given host and port.
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		# Jan 18 11:07:53 host message
		now = datetime.now()
		date_str = now.strftime("%b %d %H:%M:%S")
		data = str(message)
		#data = date_str + " " + local_host + " " + str(message)
		#print data
		sock.sendto(data, (host, port))
		sock.close()
	except:
		pass

def xor_decryption(key, ciphertext):
	loop_length = len(ciphertext)/2+1
	plaintext = ''
	
	for ptr in range (1,loop_length):
		#'The first value to be XOr-ed comes from the data to be decrypted
		cipher_ptr = ptr * 2
		xor1 = int(ciphertext[cipher_ptr-2:cipher_ptr], 16)
		#'The second value comes from the key
		xor2 = int(ord(key[ptr % len(key)]))
		plaintext = plaintext + chr(xor1 ^ xor2)
	return plaintext

def we_are_frozen():
    # Returns whether we are frozen via py2exe. This will affect how we find out where we are located.
    return hasattr(sys, "frozen")

def module_path():
	# This will get us the program's directory, even if we are frozen using py2exe
	if we_are_frozen():
		return os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding( )))
	return os.path.dirname(unicode(__file__, sys.getfilesystemencoding( )))

class InputFile(object):
	def __init__(self):
		self.path = None
		self.handle = None
		self.size = None
		#self.start = True
		self.cursor = 0
		self.agent = None
		self.filter = None
		self.destinations = None
		self.vendor = None
		self.product = None
		self.version = None
		self.whole_file = False
		self.date_format = None
		self.log_timezone = 'UTC'
		self.tz_dst = False

if __name__ == "__main__":
	# API Keys
	APIKeys = {}
	# APIKeys['example.com'] = '4d38604a1586370cf2f13c87d201b378f42b290b3f5067db4d659f162d883de0'
	
	month = {}
	month["01"] = "Jan"
	month["02"] = "Feb"
	month["03"] = "Mar"
	month["04"] = "Apr"
	month["05"] = "May"
	month["06"] = "Jun"
	month["07"] = "Jul"
	month["08"] = "Aug"
	month["09"] = "Sep"
	month["10"] = "Oct"
	month["11"] = "Nov"
	month["12"] = "Dec"

	logging_levels = {}
	logging_levels["DEBUG"] = 10
	logging_levels["INFO"] = 20
	logging_levels["WARNING"] = 30
	logging_levels["ERROR"] = 40
	logging_levels["CRITICAL"] = 50

	log_file = 'log2cef.log'
	log_dir = 'log'
	conf_dir = 'config'

	user_config = conf_dir + '\\config.ini'
	agents_config = conf_dir + '\\agents.ini'

	# Change the working directory to the same location as the exe/script
	cwd = module_path()
	os.chdir(cwd)

	# Determine the name of myself
	script_base = os.path.basename(sys.argv[0])
	# Remove the file extension
	script_name = os.path.splitext(script_base)[0]
	
	# Set default values
	config = ConfigParser.SafeConfigParser({
		# Set parameters for script
		'log_filename'         : sys.argv[0].split('.')[0] + '.log',
		'log_dir'              : 'logs',
		'data_dir'             : 'data',
		'smtp_server'          : '127.0.0.1',
		'email_sender'         : 'log2cef@yourdomain.com',
		'email_recipients'     : 'security@yourdomain.com',
		'syslog_hosts'         : '127.0.0.1',
		'debug'                : 'False',
		'whole_file'           : 'False',
		'logging_level'        : 'INFO'})
	
	'''
	# Choose which interface to use for outbound socket-based communication
	local_ips = [ i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None) if i[0] == 2 ]
	for i in local_ips:
		if i.startswith('10.'):
			local_ip = i
	local_host = socket.gethostname()
	'''
	
	files = []

	try:
		global_section = 'DEFAULT'
		#log_section = 'LOG'
		
		# Test if the file exists
		if os.path.exists(user_config):
			config.read(user_config)
		else:
			print 'Config file not found.  Exiting.'
			sys.exit(1)
		
		# Required settings
		debug                = config.getboolean(global_section, 'debug')
		
		# User input settings
		section = 'OUTPUT'
		output_syslog        = config.getboolean(section, 'output_syslog')
		output_file          = config.getboolean(section, 'output_file')
		
		log_dir              = config.get(section, 'log_dir')
		data_dir             = config.get(section, 'data_dir')
		log_filename         = config.get(section, 'log_filename')
		output_filename      = config.get(section, 'output_filename')

		section = 'EMAIL'
		smtp_server          = config.get(section, 'smtp_server')
		email_sender         = config.get(section, 'email_sender')
		email_recipients     = config.get(section, 'email_recipients')
		
		section = 'DEFAULT'
		logging_level        = config.get(section, 'logging_level')

		logging_level = logging_levels[logging_level]

		# Set the first file number / config section to read
		file_num = 1
		section = 'INPUT' + str(file_num)
		
		# Loop through each input section
		while(config.has_section('INPUT' + str(file_num))):
			try:
				n = InputFile()
				n.path            = config.get(section, 'log_path')
				n.agent           = config.get(section, 'log_agent')
				n.filter          = config.get(section, 'filter')
				n.destinations    = config.get(section, 'syslog_hosts')
				n.vendor          = config.get(section, 'vendor')
				n.product         = config.get(section, 'product')
				n.version         = config.get(section, 'version')
				n.whole_file      = config.getboolean(section, 'whole_file')
				n.date_format     = config.get(section, 'date_format')
				n.log_timezone    = config.get(section, 'log_timezone')
				n.tz_dst          = config.getboolean(section, 'tz_dst')

				# If we are not processing the whole file, read it from the end.
				if not n.whole_file:
					n.cursor = n.handle.seek(n.size)
				# Open the file and read the size of it
				n.handle = open(n.path)
				n.size = getFileSize(n.path)
				
				# Append the new object to the array of input files
				files.append(n)

			except BaseException, e:
				print "Error handling configuration section: " + section + ": " + str(e)
			file_num += 1
			section = 'INPUT' + str(file_num)

	except BaseException, e:
		print "Error reading config (using defaults): " + str(e)

	# Concatenate the log dir and log file vars
	log_file = log_dir + '\\' + log_filename
	
	# Create the log folder if it does not exist
	if not os.path.exists(log_dir):
		os.makedirs(log_dir)
	
	# Logging levels = debug / info / warn / error / critical
	logger = logging.getLogger('log2cef')
	logger.setLevel(logging_level)
	# Create file handler which logs even debug messages
	log_fh = logging.FileHandler(log_file)
	log_fh.setLevel(logging_level)
	# Create console handler with a higher log level
	console_handler = logging.StreamHandler()
	console_handler.setLevel(logging.DEBUG)
	
	# Create formatter and add it to the handlers
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	#console_handler.setFormatter(formatter)
	log_fh.setFormatter(formatter)
	 #Add the handlers to logger
	logger.addHandler(console_handler)
	logger.addHandler(log_fh)

	# Open output file
	print data_dir
	output_filename = data_dir + '\\' + output_filename
	print output_filename
	of = open(output_filename, 'w+')
	
	# Create an instance of the log processor object
	lp = cefagent.LogProcessor(agents_config)
	
	while 1:
		for f in files:
			# Repeat for this file until we reach the end
			while f.cursor != getFileSize(f.path):
				message = None
				logger.debug("Current file: " + f.path)
				f.cursor = f.handle.tell()
				#logger.debug("cursor = " + str(f.cursor) + " & size = " + str(getFileSize(f.path)))
				line = f.handle.readline()
				if not line:
					#logger.debug("No line detected in file: " + f.path + "(" + str(f.cursor) + ")")
					# If the file is smaller than the cursor value then it has been truncated; reset.
					if getFileSize(f.path) < f.cursor:
						file1.seek(0)
					else:
						f.handle.seek(f.cursor)
				else:
					# Parse the line of text into a CEF message
					#logger.debug("Processing line from file " + f.path + " (" + str(f.cursor) + ") using agent " + f.agent + "\n" + line)
					cef_data = lp.parse(f.agent, line, f.date_format, f.log_timezone, f.tz_dst)
					cef_data.deviceVendor = f.vendor
					cef_data.deviceProduct = f.product
					cef_data.deviceVersion = f.version

					# Placeholder for filtering logic

					# Convert to plain text
					message = cef_data.write()
					print message

					# Send the message to each destination
					if output_syslog:
						for d in f.destinations.split(','):
							syslog(message, d)
					# Write the message to the output file
					if output_file:
						of.write(message + '\n')

		# Sleep if all files are fully read
		time.sleep(0.5)
		
