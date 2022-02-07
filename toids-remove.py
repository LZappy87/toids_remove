#!/usr/bin/env python3
################################
# NAME: MISP IDS Tag Remover for old entries
# CREATED BY: LZappy87
# ACTUAL VERSION: 1.3
# CREATED ON: 03/02/2022
# UPDATED ON: 07/02/2022
# FILES USED: 
# - toids-remove.py (this script)
# - keys.py (the configuration file)
# TESTED WITH: 
# - MISP 2.4.152
# - PyMISP 2.4.152
# - Python 3.8.10
# - VirusTotal APIv3
################################
# DESCRIPTION:
# This script it's used to disable the attribute 'to_ids' on MISP events based on two modes:
# - [--mode remold] Removing IDS tags from events older than the range passed with the arguments --mintime and --maxtime with the possibility to exclude
#	some events based on tags (like APT);
# - [--mode vt] Removing IDS tags based on information gathered from selected vendors through the VirusTotal APIv3 in the time range specified with 
#	the arguments --mintime and --maxtime.
################################
# CHANGELOG
# v 1.0 (03/02/2022):
# First release
# v 1.1 (04/02/2022):
# - Removed old search string (it was not getting all the attributes);
# - Added discrimination between events with a certain tag, in this case "APT" through build_complex_query (thanks Giuseppe for the idea);
# - Various code revamp (not necessary linked to the aforemended changes);
# - Moved misp_client_cert to keys.py;
# - Added: misp_excluded_tags (for tag exclusion), mintime and maxtime (for time reference regarding the query on MISP) on keys.py;
# - Added various, basilar, error handling;
# - Added the creation of a default 'keys.py' if not present
# v 1.2 (05/02/2022):
# - Preparing VTotal implementation
# v 1.3 (07/02/2022):
# - Implemented VirusTotal Mode (vt);
# - Implemented Remove Old Mode (remold);
# - Included arguments to launch the script;
# - Moved some variables to keys.py for better configuration
# - Included the 'published=True' search constraint (this should speed up the queries);
# - Overall revamp of the code.
################################
# TODO:
# - More configuration parameters;
# - Better error handling.
################################
###### MISP LIBRARY BLOCK ######
################################
# Importing MISP library
from pymisp import ExpandedPyMISP
# Needed to disable InsecureRequestWarning linked to self-signed of the MISP URL when opening a connection with the Rest API
# Not needed if the destination MISP have a Certificate
# Source: https://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pytho
import urllib3
# This is for the function suppress_output (too much lines with big databases)
from contextlib import contextmanager
import sys, os
# Need it just to remove temporary files in the script folder
import shutil
# Yes, now with execution timer®
import time
# Adding support for arguments
import argparse
################################
##### VTOTAL LIBRARY BLOCK #####
################################
# Needed to do the request towards the API
import requests
# VTotal APIv3 accepts only encrypted URL for the URL check part
import base64
# Need for regex check with IP\URL\Domain
import re
################################

# Argument code block
# Creating the help menu structure
parser = argparse.ArgumentParser(description='''Script used to remove IDS tag from older events and more, 
	use --mode to activate either the IDS tag removal on old events (remold) or IDS tag removal based on the VTotal scan result (vt)
	set --mintime and --maxtime to decide the temporal range''', prog="toids_remove.py")

# First argument: --mode
# Accepts either remold (for IDS removal on old events) or vt (for IDS removal through VirusTotal analysis of the attribute_value, only IP\URL\Domains atm)
parser.add_argument(
	'--mode',
	metavar="<vt, remold>", 
	help="Remove IDS tags based on option selected.")

# Second argument: --mintime
# Specify the minimum time to take in consideration for the search (default set to 1 day)
parser.add_argument(
	'--mintime',
	metavar="<time>",
	type=str,
	default='1440m',
	help='Set minimum time (in m/d) - Default 1440m (1 Day)')

# Third argument: --maxtime
# Specify the maximum time to take in consideration for the search (default set to 1 year)
parser.add_argument(
	'--maxtime',
	metavar="<time>",
	type=str,
	default='365d',
	help="Set max time (in m/d) - Default 365d (1 Year)")

# Parsing the argument in input
args = parser.parse_args()

# Set min\max time
mintime = args.mintime
maxtime = args.maxtime

# If no\wrong argument print help and exit
okargs = ['vt','remold']
if args.mode is None or args.mode not in okargs:
	parser.print_help()
	quit()

# Aaaand the SSL error is gone (because certificates are overrated)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to suppress output (many thanks to the one who done it)
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

# Establishing the connection with the MISP Rest API using the information imported from keys.py
# Error Handling part (to be revised)
try:
	# Including variables from keys.py
	from keys import misp_url, misp_key, misp_verifycert, misp_client_cert
	print(f'Attempting to connect to the Rest API of the MISP instance {misp_url}...')
	misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, cert=misp_client_cert)

	# Error Handling in case the script doesn't find any keys.py file
	# In this case the script generates a default file and end the script
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
		'vlist = [\'Snort IP sample list\',\'PhishLabs\',\'OpenPhish\',\'AlienVault\',\'Sophos\',\'Fortinet\',\'Google Safebrowsing\',\'Abusix\',\'EmergingThreats\',\'MalwareDomainList\',\'Kaspersky\',\'URLhaus\',\'Spamhaus\',\'NotMining\',\'Forcepoint ThreatSeeker\',\'Certego\',\'ESET\',\'ThreatHive\',\'FraudScore\']',
		'vtrusted = [\'Fortinet\',\'Alienvault\',\'Sophos\',\'Google Safebrowsing\',\'Abusix\',\'Kaspersky\',\'Forcepoint ThreatSeeker\',\'ESET\']'
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

# VT part: remove IDS tags based on VirusTotal scan results
# STATUS: 100% (COMPLETE)
if args.mode == "vt":
	
	# Importing arguments from keys.py for VT
	# vtotal_key: the API key of VTotal
	# maltag: series of results linked to malicious detections
	# vlist: list of vendors selected (score +1)
	# vtrusted: list of trusted vendor (score +2)
	# typlist: list of types selected (maybe a bad idea to move it on keys.py, whatever)
	from keys import vtotal_key, maltag, vlist, vtrusted, typlist, misp_excluded_tags
	
	# Set request paramenters towards the VTotal API
	headers = {
    	"Accept": "application/json",
    	"x-apikey": vtotal_key
	}
	
	# Searching for MISP attributes
	# Generating an exclusion query (this part can AND will be expanded for more personalization)
	tagslist = misp.build_complex_query(not_parameters=misp_excluded_tags)
	# Searching and generating a list of the events where attributes with the parameters from keys.py
	try:
		# This is for testing purpose, please uncomment the below string for production enviroment
		# result = misp.search(controller='attributes', to_ids=True, published=True, type_attribute=typlist, timestamp=(maxtime, mintime), tags=tagslist)
		result = misp.search(controller='attributes', to_ids=True, published=True, type_attribute=typlist, tags=tagslist)

	# Generic Exception Handling, Same here, to be revised...
	except Exception:
		print('Check if all the informations needed are into the keys.py file, the script will now exit...')
		quit()
	
	print('Removing IDS attribute on events with ' + args.mode + ' mode and time range ' + mintime + ' : ' + maxtime + '...' )
	
	for attribute in result['Attribute']:
	
		# score is a counter that will be used as a global score to decide if a indicator should be or not delisted from IDS
		score = 0
		
		# Gets needed informations from MISP
		attribute_uuid = attribute['uuid']
		event_id = attribute['event_id']
		attribute_value = attribute['value']
		
		# IP
		if re.match("^(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})){3}$", attribute_value):
     			url = "https://www.virustotal.com/api/v3/ip_addresses/" + attribute_value
    	
	    	# URL
		elif re.match("^(http:\/\/|https:\/\/).+$", attribute_value):
     			# VirusTotal API accepts only encoded URL, so we need to calculate the base64 of the url to append to the end
     			# of the final URL
     			url_id = base64.urlsafe_b64encode(attribute_value.encode()).decode().strip("=")
     			url = "https://www.virustotal.com/api/v3/urls/" + url_id
    	
	    	# Domain\Hostname
		elif re.match("^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$", attribute_value):
			url = "https://www.virustotal.com/api/v3/domains/" + attribute_value

	    	# Send request to the API
		response = requests.request("GET", url, headers=headers)

		# Parsing the object in JSON
		jsonresp = response.json()

		# Timer starts
		start_time = time.perf_counter()

		for f in vlist:
		
			if f in vtrusted and jsonresp['data']['attributes']['last_analysis_results'][f]['result'] in maltag:
				score += 2
			
			elif f not in vtrusted and jsonresp['data']['attributes']['last_analysis_results'][f]['result'] in maltag:
				score += 1
			
			else:
				pass

		# If score >= 5 the IDS tag is not disabled, if < 4 it will be disabled.
		if score >= 5:
			print('Tag not removed from ' + attribute_value + ' on EventID ' + event_id + ', score: ' + str(score))
			pass
			
		else:
			with suppress_stdout():
				misp.update_attribute( { 'uuid': attribute_uuid, 'to_ids': 0})
				misp.publish(event_id)
			print('Tag removed from ' + attribute_value + ' on EventID ' + event_id + ', score: ' + str(score))

		# Aaaand timer ends
		end_time = time.perf_counter()

# REMOLD part: remove IDS tags from old entries
# STATUS: 100% (COMPLETED)
elif args.mode == "remold":		

	# Counter for attributes modified (and for show ofc)
	i = 0
	event_id = []

	# Import arguments from keys.py for REMOLD
	from keys import misp_excluded_tags

	# Searching and generating a list of the events where attributes with the parameters from keys.py
	try:
		# Generating an exclusion query (this part can AND will be expanded for more personalization)
		tagslist = misp.build_complex_query(not_parameters=misp_excluded_tags)
		# This is for testing purpose, please uncomment the below string for production enviroment
		# result = misp.search(controller='attributes', to_ids=True, tags=tagslist, timestamp=(maxtime, mintime))
		result = misp.search(controller='attributes', to_ids=True, published=True, tags=tagslist)

	# Generic Exception Handling, Same here, to be revised...
	except Exception:
		print('Check if all the informations needed are into the keys.py file, the script will now exit...')
		quit()

	print('Removing IDS attribute on events with ' + args.mode + ' mode and time range ' + mintime + ' : ' + maxtime + '...' )

	# Timer starts
	start_time = time.perf_counter()

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
		print('Tag removed from ' + attribute_value + ' on EventID ' + event_id)

	# Aaaand timer ends
	end_time = time.perf_counter()

	# Just for show and stats
	print(f'IDS Tags disabled successfully in {end_time - start_time:0.2f} seconds.')
	print('###############')
	print('Total Events modified:',len(event_id))
	print('Total IDS Attributes modified:',i)
	print('###############')

# Republishing all the modified events in result (if present)
if len(event_id) > 0:
	print(f'Done, {len(event_id)} event(s) republished!')
	
else:
	print('No need to republish events, no entry modified.')

# Remove temporary files (because why not?)
print('Cleaning temporary files...')
shutil.rmtree("__pycache__")
print('Done!')
