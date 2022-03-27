#!/usr/bin/env python3
################################
# NAME: MISP IDS Tag Remover for old entries
# CREATED BY: LZappy87
# ACTUAL VERSION: 1.4
# CREATED ON: 03/02/2022
# UPDATED ON: 21/02/2022
# FILES USED: 
# - toids-remove.py (this script)
# - keys.py (the configuration file)
# TESTED WITH: 
# - MISP 2.4.152
# - PyMISP 2.4.152
# - Python 3.8
# - VirusTotal APIv3
# - AbuseIPDB APIv2
# - Greynoise APIv3
################################
# DESCRIPTION:
# This script it's used to disable the attribute 'to_ids' on MISP events based on two modes:
# - [--mode rem] Removing IDS tags from events older than the range passed with the arguments --mintime and --maxtime with the possibility to exclude
#	some events based on tags (like APT);
# - [--mode reputation] Removing IDS tags based on information gathered from selected vendors through the VirusTotal APIv3 and AbuseIPDB APIv2 in the time range specified with 
#	the arguments --mintime and --maxtime.
################################
######### SCRIPT START #########
################################
#### GENERIC LIBRARY BLOCK #####
################################
# Libraries needed for suppress_output (too much lines with big databases)
from contextlib import contextmanager
import sys, os
# For the temporary file removal at the end of the script
import shutil
# Yes, now with execution timer®
import time
# Adding support for arguments
import argparse
# Output format in table
from prettytable import PrettyTable
################################
###### MISP LIBRARY BLOCK ######
################################
# Importing MISP library
from pymisp import ExpandedPyMISP
# Needed to disable InsecureRequestWarning linked to self-signed certificate of the MISP instance
# Not needed if the destination MISP have a Certificate
# Source: https://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pytho
import urllib3
################################
##### VTOTAL\ABUSEIPDB LIBRARY BLOCK #####
################################
# Library needed to execute the API request
import requests
# VTotal APIv3 accepts only encrypted URL for the URL check part
import base64
# Need for regex check with IP\URL\Domain\Hostname
import re
################################

# Initialization of counters and variables
i = 0
event_id = []
vttyperes = ''
vtotaltags = []
abipdb = False
abquerystring = None
abresponse = None
grresponse = None
abjsonresp = []
grjsonresp = []
grmessage = None
grnoise = None
grriot = None
grclass = None
grclassified = None
grname = None
abscore = 0
errorc = 0
actualid = 0

# Generating tables for final visualization
finaloutputrep = PrettyTable()
finaloutputrep.field_names = ['EventID','Status','Attribute','Type','Score','VT Tags','AbuseIPDB','Greynoise','Info']
finaloutputrem = PrettyTable()
finaloutputrem.field_names = ['EventID','Status','Attribute','Type']

# ARGUMENTS CODE BLOCK
# Creating the help menu structure
parser = argparse.ArgumentParser(description="Script used to remove IDS tag from attributes on MISP", 
prog="toids_remove.py", 
epilog='''This script it's used to disable the attribute 'to_ids' on MISP events based on two modes:
	- [--mode rem] Removing IDS tags from events based only on time range;
	- [--mode reputation] Removing IDS tags based on information gathered from selected vendors through the VirusTotal\AbuseIPDB\Greynoise API.
In both cases you can use --mintime and --maxtime to adjust time range, options like tag exclusion, vendor list for VTotal and other can be changed by modifing the keys.py file.''',
formatter_class=argparse.RawTextHelpFormatter)

# First argument: --mode
# Accepts either rem (for IDS removal on old events) or reputation (for IDS removal through VirusTotal\AbuseIPDB reputation analysis of the attribute_value, only IP\URL\Domains atm)
parser.add_argument(
	'--mode',
	metavar="<option>", 
	help="Remove IDS tags based on option selected.")

# Second argument: --mintime
# Specify the minimum time to take in consideration for the search (default set to 1 day)
parser.add_argument(
	'--mintime',
	metavar="<time>",
	type=str,
	help='Set minimum time (in s/m/d) - Default 0s (Now)')

# Third argument: --maxtime
# Specify the maximum time to take in consideration for the search (default set to 1 year)
parser.add_argument(
	'--maxtime',
	metavar="<time>",
	type=str,
	help="Set max time (in s/m/d) - Default 365d (1 Year)")

# Parsing the argument in input
args = parser.parse_args()

# If no\wrong argument for --mode print help and exit
okargs = ['rem','reputation']
if args.mode is None or args.mode not in okargs:
	parser.print_help()
	quit()

# If no parameter specified in mintime\maxtime set to default both
if args.mintime is None and args.maxtime is None:
	print('No mintime\maxtime specified, time range set to 0s\\365d...')
	time.sleep(3)
	mintime = '0s'
	maxtime = '365d'
# If no --mintime argument passed set to default mintime
elif args.mintime is None and args.maxtime is not None:
	print('No mintime specified, set to default (0s)...')
	time.sleep(3)
	mintime = '0s'
	maxtime = args.maxtime
# If no --maxtime argument passed set to default maxtime
elif args.mintime is not None and args.maxtime is None:
	print('No maxtime specified, set to default (365d)...')
	time.sleep(3)
	mintime = args.mintime
	maxtime = '365d'

# if arguments are present set them directly
# Just to make sure no wrong arguments are passed, match only arguments
# with 4 digits (1-9999) and either a d\m\s as a final character
if re.match("^[0-9]{1,4}[d,m,s]$", mintime) and re.match("^[0-9]{1,4}[d,m,s]$", maxtime):
	pass
else:
	print("Parameter in mintime\maxtime wrong.")
	quit()

# Disabling warning linked to connection towards MISP instance self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# OUTPUT SUPPRESSION FUNCTION
# Source: https://stackoverflow.com/questions/2125702/how-to-suppress-console-output-in-python
@contextmanager
def suppress_stdout():
	# Toss the output into the shadow realm (/dev/null)
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:  
            yield
        finally:
            sys.stdout = old_stdout

# MISP REST API CONNECTION BLOCK
# Establishing the connection with the MISP Rest API using the parameters imported from keys.py
try:
	# Including parameters for MISP connection from keys.py and attempt connection
	from keys import misp_url, misp_key, misp_verifycert, misp_client_cert
	print(f'Attempting to connect to the Rest API of the MISP instance {misp_url}...')
	misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, cert=misp_client_cert)

# Error Handling in case the script doesn't find any keys.py file, the script generates a default file and end the script
except ImportError:
	print('No keys.py file exists, generating a default file...')
	y = 0
	f = open("keys.py","w+")

	# Definition of the default keys.py
	deffile = [
		'#!/usr/bin/env python',
		'',
		'# MISP API Connection Parameters',
		'misp_url = \'<MISP URL HERE>\'',
		'misp_key = \'<MISP API KEY HERE>\'',
		'',
		'# If MISP have a self-signed certificate keep it to false, otherwise set it to true',
		'# and populate the misp_client_cert with the path to the certificate',
		'misp_verifycert = False',
		'misp_client_cert = None',
		'',
		'# MISP Search Paramenters',
		'misp_exclude_tags = [<here the list of the tags to exclude>]',
		'# /!\\ DO NOT TOUCH typlist VALUES FOR NOW /!\\',
		'typlist = [\'ip-src\',\'ip-dst\',\'domain\',\'url\',\'hostname\']',
		'',
		'# VirusTotal APIv3 + Search Parameters',
		'vtotal_key = \'<VIRUSTOTAL API KEY HERE>\'',
		'maltag = [\'malware\',\'malicious\']',
		'set_score = 5',
		'vlist = [\'Snort IP sample list\',\'PhishLabs\',\'OpenPhish\',\'AlienVault\',\'Sophos\',\'Fortinet\',\'Google Safebrowsing\',\'Abusix\',\'EmergingThreats\',\'MalwareDomainList\',\'Kaspersky\',\'URLhaus\',\'Spamhaus\',\'NotMining\',\'Forcepoint ThreatSeeker\',\'Certego\',\'ESET\',\'ThreatHive\',\'FraudScore\']',
		'vtrusted = [\'Fortinet\',\'Alienvault\',\'Sophos\',\'Google Safebrowsing\',\'Abusix\',\'Kaspersky\',\'Forcepoint ThreatSeeker\',\'ESET\']',
		'',
		'# AbuseIPDB APIv2 + Search Parameters',
		'abipdb_key = \'<ABUSEIPDB API KEY HERE>\'',
		'ab_maxAge = \'150\'',
		'',
		'# Greynoise API parameters',
		'grey_key = \'<GREYNOISE API KEY HERE>\''
	]
		
	for y in range(len(deffile)):
		f.write(deffile[y])
		f.write("\r\n")
	
	f.close()			
	print('Default keys.py generated, please modify it with the needed parameters, the script will now exit...')
	quit()

# Generic Exception Handling, as said this part will be revised with more precise error handling
except Exception:
	print('There is a problem with the connection to MISP or the parameters in keys.py, the script will now exit...')
	quit()

# SCRIPT MODES BLOCK
# Timer starts
start_time = time.perf_counter()
	
# VT\AbuseIPDB part: remove IDS tags based on VirusTotal\AbuseIPDB reputational scan results
# Note: AbuseIPDB part working only for IP indicator
# STATUS: 100% (COMPLETE)
if args.mode == "reputation":
	
	# Importing arguments from keys.py
	# vtotal_key: the API key of VTotal
	# maltag: series of results linked to malicious detections
	# vlist: list of vendors selected (score +1)
	# vtrusted: list of trusted vendor (score +2)
	# set_score: minimum score to take in consideration (default: 5)
	# typlist: list of types selected (maybe a bad idea to move it on keys.py, whatever)
	# misp_excluded_tags: decided to include this one too for tag exclusion (just in case)
	# abipdb_key: the API key of AbuseIPDB
	# ab_maxAge: parameter to return only the reports for the last XX days (default 150)
	# grey_key: the API key of Greynoise
	from keys import vtotal_key, maltag, vlist, vtrusted, typlist, misp_excluded_tags, set_score, abipdb_key, ab_maxAge, grey_key
	
	# Checking if set_score is initialized, if it's not set it to default (5)
	if set_score is None:
		print("No score set on keys.py, setting it to default (5)")
		set_score = 5
		
	# Set request paramenters towards the VTotal API
	vtheaders = {
    	"Accept": "application/json",
    	"x-apikey": vtotal_key
	}
	
	# Set request parameters towards AbuseIPDB API	
	aburl = "https://api.abuseipdb.com/api/v2/check"

	abheaders = {
		"Accept": "application/json",
		"Key": abipdb_key
	}
	
	# Set request parameters towards the Greynoise API
	
	grheaders = {
		"key": grey_key
	}

	# Searching and generating a list of the events where attributes with the parameters from keys.py
	try:
		# Just in case if no tags are specified into keys.py
		if misp_excluded_tags == []:			
			# The string with timestamp is for testing purposes, please uncomment the below string for production enviroment and comment the other
			result = misp.search(controller='attributes', to_ids=True, published=True, type_attribute=typlist, timestamp=(maxtime, mintime))
			# result = misp.search(controller='attributes', to_ids=True, published=True, type_attribute=typlist)
		else:			
			# Generating an exclusion query (this part can AND will be expanded for more personalization)
			tagslist = misp.build_complex_query(not_parameters=misp_excluded_tags)
			# The string with timestamp is for testing purposes, please uncomment the below string for production enviroment and comment the other
			result = misp.search(controller='attributes', to_ids=True, published=True, type_attribute=typlist, timestamp=(maxtime, mintime), tags=tagslist)
			# result = misp.search(controller='attributes', to_ids=True, published=True, type_attribute=typlist, tags=tagslist)

	# Generic Exception Handling, Same here, to be revised...
	except Exception:
		print('Check if all the informations needed are into the keys.py file, the script will now exit...')
		quit()
	
	print('Removing IDS attribute on events with ' + args.mode + 'mode (score < ' + str(set_score) + ') and time range ' + mintime + ' : ' + maxtime + '...' )
	
	# Extracting attributes from MISPr
	for attribute in result['Attribute']:
	
		# This is a counter that will be used as a global score to decide if a indicator should be or not delisted from IDS
		score = 0
				
		# Gets needed informations from MISP
		attribute_uuid = attribute['uuid']
		event_id = attribute['event_id']
		attribute_value = attribute['value']
		attribute_type = attribute['type']
		
		# IP
		if re.match("^(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})){3}$", attribute_value):
			grurl = "https://api.greynoise.io/v3/community/" + attribute_value
			vturl = "https://www.virustotal.com/api/v3/ip_addresses/" + attribute_value
			abquerystring = {
				"ipAddress": attribute_value,
				"maxAgeInDays": ab_maxAge
			}
						    	
	    	# URL
		elif re.match("^(http:\/\/|https:\/\/).+$", attribute_value):
     			# VirusTotal API accepts only encoded URL, so we need to calculate the base64 of the url to append to the end of the final URL
     			grurl = None
     			url_id = base64.urlsafe_b64encode(attribute_value.encode()).decode().strip("=")
     			vturl = "https://www.virustotal.com/api/v3/urls/" + url_id
    	
	    	# Domain\Hostname
		elif re.match("^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$", attribute_value):
			grurl = None
			vturl = "https://www.virustotal.com/api/v3/domains/" + attribute_value

	    	# Send request to the API
		vtresponse = requests.request(method='GET', url=vturl, headers=vtheaders)
		if abquerystring is not None:
			abresponse = requests.request(method='GET', url=aburl, headers=abheaders, params=abquerystring)
		if grurl is not None:
			grresponse = requests.request(method='GET', url=grurl, headers=grheaders)

		# Transform into a JSON (type: dict)
		vthttpresponse = str(vtresponse)
		vtjsonresp = vtresponse.json()
		if abresponse is not None:
			abhttpresponse = str(abresponse)
			abjsonresp = abresponse.json()
			abscore = abjsonresp['data']['abuseConfidenceScore']
		if grresponse is not None:
			grhttpresponse = str(grresponse)
			grjsonresp = grresponse.json()
			grnoise = grjsonresp['noise']
			grriot = grjsonresp['riot']
			grmessage = grjsonresp['message']
			if "404" in grhttpresponse:
				grclass = 'unknown'
				grname = 'unknown'
			else:
				grclass = grjsonresp['classification']
				grname = grjsonresp['name']
		
		
		# Response check, if not 200 end the script and print the error details
		if "20" in vthttpresponse or ("20" in vthttpresponse and "20" in abhttpresponse and ("20" in grhttpresponse or "404" in grhttpresponse)):
    			pass
		else:
			if "20" not in vthttpresponse:
				print("No connection established with VirusTotal API")
				print("Error Type: ", vtjsonresp['error']['code'])
				print("Error Message: ", vtjsonresp['error']['message'])
			if "20" not in abhttpresponse:
				print("No connection established with AbuseIPDB API, problems found:")
				if abipdb_key is None or abipdb_key == '':
					print("API key is missing, please set it on keys.py")
					errorc += 1
				if int(ab_maxAge) > 365 or int(ab_maxAge) < 1:
					print("Wrong parameter for ab_maxAge, set it between 1 and 365 on keys.py")
					errorc += 1
				if errorc == 0:
					print("Unknown error, please check the keys.py informations")
					print("Further info: " + str(abjsonresp))
			if "20" not in grhttpresponse:
				print("An error occurred with Greynoise API")
				print("Status: ", grhttpresponse)
				print("Message: ", str(grmessage))
			quit()
		
		# Generating the score for the indicator based on the parameters stored into the keys.py
		for f in vlist:
			vttyperes = vtjsonresp['data']['attributes']['last_analysis_results'][f]['result']
			# Trusted vendor list gets +2 score
			if f in vtrusted and vttyperes in maltag:
				score += 2
				vtotaltags.append(vttyperes)
			# The others gets +1 score
			elif f not in vtrusted and vttyperes in maltag:
				score += 1
				vtotaltags.append(vttyperes)
			# If no malicious tags found set no score
			else:
				pass
		
		# If score on AbuseIPDB >= 50 add another +5 to the score (IP ONLY)
		if abscore >= 50:
			score += 5
			abipdb = True
		else:
			abipdb = False
			pass
		
		# Generating the score for Greynoise (IP ONLY)
		# if not generating noise, found into RIOT database (lecit IP) or classified as benign, assign no score
		if grnoise == 'false' or grriot == 'true' or grclass == 'benign':
			score += 0
			grclassified = grclass
		# if generating noise but not classified, score +1
		if grnoise == 'true' and grclass == 'unknown':
			score += 1
			grclassified = grclass
		# if generating noise and not classified as unknown or benign, score +3
		if grnoise == 'true' and (grclass != 'unknown' or grclass != 'benign'):
			score += 3
			grclassified = grclass
		
		# If score >= setscore (configured on keys.py) the IDS tag is not disabled, if < setscore it will be disabled.
		if score >= set_score:
			# TODO: Verbose mode
			vtotaltagsfinal = str(set(vtotaltags))
			if vtotaltagsfinal == "set()":
				vtotaltagsfinal = "No Tags"
			# print('[EventID ' + event_id + '] Tag not removed from ' + attribute_value + ', total score: ' + str(score) + ', VirusTotal: ' + vtotaltagsfinal + ', AbuseIPDB: ' + str(abipdb) + ', Greynoise: ' + str(grclassified) + ' (' + str(grname) + ')')
			finaloutputrep.add_row([event_id,"Not Removed",attribute_value,attribute_type,str(score),vtotaltagsfinal,str(abipdb),str(grclassified),str(grname)])
			vtotaltags = []
			vtotaltagsfinal = ''
			if actualid == 0:
				actualid = event_id
				print("Tag IDS removal on event " + actualid + " started")
			elif actualid == event_id:
				pass
			elif actualid != event_id or actualid > 0:
				print("Tag IDS removal on event " + actualid + " finished")
				actualid = eventid
				print("Tag IDS removal on event " + actualid + " started")
			
			pass
		else:
			with suppress_stdout():
				misp.update_attribute( { 'uuid': attribute_uuid, 'to_ids': 0})
				misp.publish(event_id)
			i += 1
			# TODO: Verbose mode
			vtotaltagsfinal = str(set(vtotaltags))
			# print('[EventID ' + event_id + '] Tag removed from ' + attribute_value + ', total score: ' + str(score) + ', VirusTotal: ' + vtotaltagsfinal + ', AbuseIPDB: ' + str(abipdb) + ', Greynoise: ' + str(grclassified) + ' (' + str(grname) + ')')
			if vtotaltagsfinal == "set()":
				vtotaltagsfinal = "No Tags"
			finaloutputrep.add_row([event_id,"Removed",attribute_value,attribute_type,str(score),vtotaltagsfinal,str(abipdb),str(grclassified),str(grname)])
			if actualid == 0:
				actualid = event_id
				print("Tag IDS removal on event " + actualid + " started")
			elif actualid == event_id:
				pass
			elif actualid != event_id or actualid > 0:
				print("Tag IDS removal on event " + actualid + " finished (" + str(i) + " attributes changed)")
				actualid = eventid
				print("Tag IDS removal on event " + actualid + " started")
			vtotaltags = []
			vtotaltagsfinal = ''
			


# REM part: remove IDS tags based only on time range
# STATUS: 100% (COMPLETE)
elif args.mode == "rem":		

	# Import arguments from keys.py for REMOLD
	# misp_excluded_tags: this is used as a filter to exclude events with a certain tag(s)
	from keys import misp_excluded_tags

	# Searching and generating a list of the events where attributes with the parameters from keys.py
	try:
		# Just in case if no tags are specified into keys.py
		if misp_excluded_tags == []:
			# The string with timestamp is for testing purposes, please uncomment the below string for production enviroment and comment the other
			result = misp.search(controller='attributes', to_ids=True, timestamp=(maxtime, mintime))
			# result = misp.search(controller='attributes', to_ids=True, published=True)
		else:
			# Generating an exclusion query (this part can AND will be expanded for more personalization)
			tagslist = misp.build_complex_query(not_parameters=misp_excluded_tags)
			# The string with timestamp is for testing purposes, please uncomment the below string for production enviroment and comment the other
			result = misp.search(controller='attributes', to_ids=True, tags=tagslist, timestamp=(maxtime, mintime))
			# result = misp.search(controller='attributes', to_ids=True, published=True, tags=tagslist)

	# Generic Exception Handling, Same here, to be revised...
	except Exception:
		print('Check if all the informations needed are into the keys.py file, the script will now exit...')
		quit()

	print('Removing IDS attribute on events with ' + args.mode + ' mode and time range ' + mintime + ' : ' + maxtime + '...' )

	# Iterate attribute to find and disable the IDS tags
	for attribute in result['Attribute']:
		i += 1
		attribute_uuid = attribute['uuid']
		event_id = attribute['event_id']
		attribute_value = attribute['value']

		# As said previously: no futile output allowed
		with suppress_stdout():
			misp.update_attribute( { 'uuid': attribute_uuid, 'to_ids': 0})
			misp.publish(event_id)
		# TODO: Verbose mode
		# print('[EventID ' + event_id + '] Tag removed from ' + attribute_value)
		finaloutputrem.add_row([event_id, "Removed", attribute_value,attribute_type])
		if actualid == 0:
			actualid = event_id
			print("Tag IDS removal on event " + actualid + " started")
		elif actualid == event_id:
			pass
		elif actualid != event_id or actualid > 0:
			print("Tag IDS removal on event " + actualid + " finished (" + str(i) + " attributes changed)")
			actualid = eventid
			print("Tag IDS removal on event " + actualid + " started")
		
		

# Stop timer
print("Tag IDS removal on event " + actualid + " finished (" + str(i) + " attributes changed)")
print("All events processed.")
end_time = time.perf_counter()
print('###############')

# Show results regading the action done
if args.mode == 'reputation':
	print(finaloutputrep)
elif args.mode == 'rem':
	print(finaloutputrem)
print('###############')
print(f'IDS Tags disabled successfully in {end_time - start_time:0.2f} seconds.')
print('###############')
print('Total Events modified:',len(event_id))
print('Total IDS Attributes modified:', i)
print('###############')

# Republishing all the modified events (if present)
if len(event_id) > 0:
	print('Events republished: ', len(event_id))
	
else:
	print('No need to republish events, no entry modified.')

# Remove temporary files (because why not?)
print('Cleaning temporary files...')
shutil.rmtree("__pycache__")
print('Done!')
