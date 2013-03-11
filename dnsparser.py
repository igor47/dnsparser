#!/usr/bin/python
# This work is licensed under the Creative Commons Attribution 3.0 United States License.
# To view a copy of this license, visit 
#           http://creativecommons.org/licenses/by/3.0/us/ 
# or send a letter to Creative Commons, 
# 171 Second Street, Suite 300, San Francisco, California, 94105, USA.
# Copyright SingleHop Inc.
# for questions or bugs, contact igor@singlehop.com

import os, sys, re, os.path

# Some variables useful across iterations
ttl_re = re.compile(r'[0-9]+[smhdw]')
SOAFields = ['refresh','retry','expire','minimum']
recordTypes = ['soa','mx','ns','a','cname','txt','key','ptr']

class parseError(Exception):
	"""The exception class used internally"""
	pass

def parseTTL(token):
	"""Translates BIND TTL tokens to seconds"""
	try:
		int(token)
	except:								#not an integer, maybe has suffix?
		parts = ttl_re.findall(token)
		if "".join(parts) != token:
			raise parseError("Could not parse TTL value %s" % token)

		ttl = 0;
		for part in parts:
			suffix = token[-1]
			num = int(token[:-1])
		
			if suffix == 's':				ttl += num
			elif suffix == 'm':				ttl += num * 60
			elif suffix == 'h':				ttl += num * 60 * 60
			elif suffix == 'd':				ttl += num * 60 * 60 * 24
			elif suffix == 'w':				ttl += num * 60 * 60 * 24 * 7

		return str(ttl)
	else:
		return token

def qualified(token, zonename):
	"""Given a domain, returns a fully-qualified domain

	If the passed domain was already fully-qualified, it is returned unaltered"""
	if token.endswith('.'):
		return token
	else:
		return "%s.%s" % (token, zonename)

def sqlize(record):
	"""Converts a record row into an SQL insert statement"""
	tbl = 'dns_records'
	query = 'INSERT INTO dns_records(%s) VALUES (%s);'
	columns = ",".join(record.keys())
	values = ",".join( ["'%s'" % value for value in record.values()] )

	return query % (columns, values)

def parseZone(zonename, zoneData, uberid):
	"""Does the actual parsing"""
	
	state = "prerr"									#initialize the state
	ttl = '86400'									#default TTL if none is given in the zone

	if not zonename.endswith('.'):					#make sure its fully qualified
		origin = zonename + '.'
	else:
		origin = zonename

	records = []					#list of records
	record = {}						#each record is a dictionary
	N = None;						#separate state tracker just for SOA record parsing
	for line in zoneData:
		tokens = line.split()
		for token in tokens:
			token = token.lower()					#all tokens in lowercase

			if state == "prerr":					#expecting to find a record
				if token.startswith('$'):				#directive
					directive = token.lstrip('$')
					if directive == 'ttl':
						state = "setTTL"
					if directive == 'origin':
						state = "setOrigin"
				
				elif token.startswith(';'):			#comment
					break								#go to new line

				elif token == 'in':					#skipped host and ttl in record
					record['host'] = '@'					#host is @
					record['ttl'] = ttl						#default ttl
					state = "getRecordType"

				elif token == '@':					#origin is the host
					record['host'] = '@'
					state = "getTTL"

				else:								#may be host or ttl...
					if line[0] == ' ':					#must be ttl...
						record['host'] = '@'	
						record['ttl'] = parseTTL(token)
						state = "getClass"
					else:								#must be host
						record['host']= qualified(token, origin)
						state = "getTTL"
			
			elif state == 'postrr':
				if token.startswith(';'):
					break;
				else:
					raise parseError("Invalid data on line after record parsing")

			elif state == "setTTL":
				ttl = parseTTL(token);
				state = 'prerr'						#want pre-rr here since no record to add

			elif state == "setOrigin":
				if not token.endswith('.'):
					raise parseError("Invalid origin %s" % token)
				origin = token
				state = 'prerr'						#want pre-rr here since no record to add

			elif state == "getTTL":					#got the host, need ttl
				if token == 'in':					#skipped ttl
					record['ttl'] = ttl
					state = "getRecordType"

				else:
					record['ttl']=parseTTL(token) 
					state = "getClass"

			elif state == "getClass":
				if token != 'in':
					raise parseError("Invalid class %s" % token)
				state = "getRecordType"

			elif state == "getRecordType":
				if token not in recordTypes:
					raise parseError("Invalid record type %s" % token)

				record['type'] = token
				if token == 'soa':
					state = "getPrimaryNS"
				elif token == 'mx':
					state = "getMXPri"
				else:
					state = "getRecordData"

			elif state == "getMXPri":
				try:	int(token)
				except:	raise parseError("Invalid priority %s" % token)
				else:
					record['mx_priority'] = token
					state = "getRecordData"

			elif state == "getRecordData":
				if token.startswith(';'):		#no data - rest of stuff is comment
					if record['type'] in ['cname', 'ns', 'mx']:
						record['data'] = '@'
						state = "postrr"
						break;
					else:
						raise parseError("Invalid data for %s record %s" % (record['type'], record['host']))
				
				if record['type'] == 'txt':
					if not token.startswith('"'):
						raise parseError("Unquoted data in TXT record %s" % record['host'])

					record['data'] = [token]
					state = "addQuotedData"
					continue

				if record['type'] in ['cname', 'mx', 'ns']:
					record['data'] = qualified(token, origin)
				else:
					record['data'] = token
				state = "postrr"

			elif state == "addQuotedData":
				record['data'].append(token)
				if token.endswith('"'):
					record['data'] = " ".join(record['data'])
					state = "postrr"
			
			#****************** SOA Records ************
			elif state == "getPrimaryNS":
				record['data'] = qualified(token, origin)
				state = "getContact"
			elif state == "getContact":
				record['resp_person'] = qualified(token, origin)
				state = "getSerial"
			elif state == "getSerial":
				if token == '(': continue
				if token == ';': break
				try:
					int(token)
				except:
					raise parseError("Invalid serial %s" % token)
				else:
					record['serial'] = token
					state = "soa"
					N = 0
			elif state == "soa":
				if token == ';': break
				record[SOAFields[N]] = parseTTL(token)		#sets the record value based on current soa field - see global var SOAFields
				N += 1
				if N == 4: state = "endSoa"
			elif state == "endSoa":
				if token == ';': break
				if token == ')':
					state = "postrr"
		
		if state not in ['endSoa','soa','getSerial', 'postrr', 'prerr']:
			raise parseError("Invalid state on line change: %s" % line)
		if state == 'postrr':
			record['zone'] = origin
			record['uberid'] = uberid
			records.append(record)
			record = {}
			state = "prerr"
	
	output = open(origin + "sql", 'w')
	for record in records:
		output.write(sqlize(record))
		output.write('\n')
	output.close()

def main(files):
	"""Main function which reads in the zone files to be parsed"""
	for filename in files:
		zonename = os.path.basename(filename)
		name, ext = os.path.splitext(zonename)
		if ext in ['.db','.zone']:
			zonename = name

		while True:
			uberid = raw_input('Client ID for zone %s [1234]: ' % zonename)
			if uberid == "": uberid = "1234"
			try: int(uberid)
			except:	print "Invalid ID"
			else: break

		zoneData = file(filename).readlines()
		try:
			parseZone(zonename, zoneData, uberid)
		except parseError, err:
			print "Could not process %s: %s" % (filename, err)
		else:
			print "Successfully processed zone %s" % zonename

if __name__ == "__main__":
	if len(sys.argv) == 1:
		print "Usage: %s <list of zone files>" % sys.argv[0]
	else:
		main(sys.argv[1:])
