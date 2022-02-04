#!/usr/bin/env python3
################################
# NAME: MISP IDS Tag Remover for old entries
# CREATED BY: Luca Emanuele Zappacosta
# ACTUAL VERSION: 1.1
# CREATED ON: 03/02/2022
# UPDATED ON: 04/02/2022
# FILES USED: 
# - toids-remove.py (this script)
# - keys.py (take it as a 'config file')
# TESTED WITH: 
# - MISP 2.4.152
# - PyMISP 2.4.152
# - Python 3.8.10
################################
# DESCRIPTION:
# This script it's used to disable all 'to_ids' tags on selected MISP Events and then republish them
# fully configurable through the keys.py file wich contains:
# misp_url 						| URL of the MISP instance
# misp_key 						| The API key needed to access the Rest API
# misp_verifycert					| If the MISP instance have a certificate (default: false)
# misp_client_cert					| The path of the certificate (default: none)
# misp_excluded_tags					| List of tags to exclude (need to be a list)
# maxtime						| Maximum time for the misp.search (in days, ex: 365d)
# mintime						| Minimum time for the misp.search (in days, ex: 365d)
# 
# An idea developed from this article: https://www.vanimpe.eu/2019/09/24/tracking-false-positives-and-disabling-to_ids-in-misp/
################################
# /!\ USE THE BELOW TEMPLATE TO GENERATE THE "keys.py" FILE /!\
################################
# #!/usr/bin/env python
#
# Here the informations needed to connect to the MISP Rest API
# misp_url = '<MISP URL HERE>'
# misp_key = '<MISP API KEY HERE>'
#
#
# If the MISP instance doesn't have a self-signed certificate keep it to false, otherwise set it to true 
# and insert the path to the certificate on 'misp_client_cert'
# misp_verifycert = False
# misp_client_cert = None
#
# Here the other parameters
# misp_exclude_tags = ['APT']
# maxtime = '7300d' # 20 years
# mintime = '1095d' # 3 years
################################
# CHANGELOG
# v 1.0 (03/02/2022):
# First release
# v 1.1 (04/02/2022):
# - Removed old search string (it was not getting all the attributes);
# - Added filtering based on event tags through build_complex_query (thanks Giuseppe for the idea);
# - Various code revamp (not necessary linked to the aforemended changes);
# - Moved misp_client_cert to keys.py;
# - Added: misp_excluded_tags (for tag exclusion), mintime and maxtime (for time reference regarding the query on MISP) on keys.py;
# - Added basic error handling;
# - Added the creation of a default 'keys.py' if not present.
################################
# TODO:
# - More configuration parameters i guess;
# - VTotal API implementation (for future functions);
# - Better error handling.
################################
################################
# Importing MISP library method ExpandedPyMISP
from pymisp import ExpandedPyMISP
# Need urllib3 to disable InsecureRequestWarning error when connecting to the Rest API 
# since my instance of MISP has a self-signed certificate, not needed if the destination 
# MISP instance have a valid certificate
# Source: https://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pytho
import urllib3
# Importing this librariesthe function suppress_output (too much lines with big databases)
# and the default keys.py part
from contextlib import contextmanager
import sys, os
# Using this to clean temporary files from the source folder
import shutil
# Yes, now with execution timer®
import time

# Function to suppress output (thank god to the one who done it)
# https://stackoverflow.com/questions/2125702/how-to-suppress-console-output-in-python
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

# Initializing the counter for the attribute and the event_id list
i = 0
event_id = []

# Aaaand the SSL error is gone (because certificates are overrated)
# Note: as said it's not necessary if the MISP instance has a signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Establishing the connection with the MISP Rest API using the informations imported from keys.py (now with Error Handling®)
try:
	# Importing settings from keys.py
	from keys import misp_url, misp_key, misp_verifycert, misp_client_cert, misp_excluded_tags, mintime, maxtime
	print(f'Attempting to connect to the Rest API of {misp_url}...')
	# Command to connect to the Rest API
	misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, cert=misp_client_cert)

# First Exception Handler - ImportError
# If the keys.py does not exist it generates it
# Note: Of course it needs to be populated with valid informations, duh
except ImportError:

	print('No keys.py file exists, generating a default file...')
	y = 0
	f = open("keys.py","w+")
	
	# Definition of the list with the default keys.py strings
	deffile = [
	'#!/usr/bin/env python',
	'# Here the informations needed to connect to the MISP Rest API',
	'misp_url = <MISP URL HERE>',
	'misp_key = <MISP API KEY HERE>',
	'',
	'# If the MISP instance doesn\'t have a self-signed certificate keep it to false, otherwise set it to true',
	'# and insert the path to the certificate on misp_client_cert',
	'misp_verifycert = False',
	'misp_client_cert = None',
	'',
	'# Here the other parameters',
	'misp_exclude_tags = [\'<here the list of the tags to exclude>\']',
	'maxtime = <set max time for query, ex: \'365d\'>',
	'mintime = <set min time for query, ex: \'365d\'>'
	]
	
	# Writing the file and exiting	
	for y in range(len(deffile)):
		f.write(deffile[y])
		f.write("\r\n")
	
	f.close()			
	print('Default keys.py generated, please modify it with the needed informations, the script will now exit...')
	quit()

# Generic Exception Handler - Exception
# For all the other problems, this part will be revised with more precise Error Handling
except Exception:
	print('There is a problem with the connection to MISP or the parameters in keys.py, the script will now exit...')
	quit()

# Searching and generating a list of the events where attributes with the information gathered from keys.py
try:

	# Generating an exclusion query (this part can AND will be expanded for more personalization)
	tagslist = misp.build_complex_query(not_parameters=misp_excluded_tags)
	# Note: the commented string is for testing purpose (since i don't have a MISP database with old entries :D)
	# result = misp.search(controller='attributes', to_ids=True, tags=tagslist)
	result = misp.search(controller='attributes', to_ids=True, tags=tagslist, timestamp=(maxtime, mintime))

# Generic Exception Handler - Exception
# # Same here, to be revised...
except Exception:
	print('Check if all the informations needed are into the keys.py file, the script will now exit...')
	quit()

# From here starts the IDS tag disable part
print('Removing IDS tags...')

# Timer starts
start_time = time.perf_counter()

for attribute in result['Attribute']:
	i += 1
	attribute_uuid = attribute['uuid']
	event_id = attribute['event_id']
	# As said previously: no futile output allowed
	with suppress_stdout():
		misp.update_attribute( { 'uuid': attribute_uuid, 'to_ids': 0})
		misp.publish(event_id)

# Aaaand timer ends
end_time = time.perf_counter()

# Just for show and stats
print(f'IDS Tags disabled successfully in {end_time - start_time:0.4f} seconds.')
print('###############')
print('Total Events modified:',len(event_id))
print('Total IDS Attributes modified:',i)
print('###############')

# Republishing all the modified events in result (if present)
if len(event_id) > 0:
	print(f'Republish done on {len(event_id)} events!')
else:
	print('No need to republish events, no entry modified.')

# Remove temporary files (because why not?)
print('Cleaning temporary files...')
shutil.rmtree("__pycache__")
print('Done!')
