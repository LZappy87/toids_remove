# NAME
MISP IDS Tag Remover for old entries
CREATED BY
Luca Emanuele Zappacosta
#ACTUAL VERSION
1.1
# CREATED ON
03/02/2022
# UPDATED ON
04/02/2022
# FILES USED
- toids-remove.py (this script)
- keys.py (take it as a 'config file', auto-generated if not present)
# TESTED WITH: 
- MISP 2.4.152
- PyMISP 2.4.152
- Python 3.8.10


# DESCRIPTION:
This script it's used to disable all 'to_ids' tags on selected MISP Events and then republish them
the script is fully configurable through the keys.py file wich contains:
misp_url 						| URL of the MISP instance
misp_key 						| The API key needed to access the Rest API
misp_verifycert				| If the MISP instance have a certificate (default: false)
misp_client_cert				| The path of the certificate (default: none)
misp_excluded_tags			| List of tags to exclude (need to be a list)
maxtime						| Maximum time for the misp.search (in days, ex: 365d)
mintime						| Minimum time for the misp.search (in days, ex: 365d)
Used this as a base for the script https://www.vanimpe.eu/2019/09/24/tracking-false-positives-and-disabling-to_ids-in-misp/

# /!\ USE THE BELOW TEMPLATE TO GENERATE THE "keys.py" FILE /!\

#!/usr/bin/env python

Here the informations needed to connect to the REST API of MISP
misp_url = '<MISP URL HERE>'
misp_key = '<MISP API KEY HERE>'

#If MISP have a self-signed certificate keep it to false, otherwise set it to true 
 misp_verifycert = False
 misp_client_cert = None

#Here the other parameters
misp_exclude_tags = ['APT']
maxtime = '7300d' # 20 years
mintime = '1095d' # 3 years

# CHANGELOG
# v 1.0 (03/02/2022):
First release
# v 1.1 (04/02/2022):
- Removed old search string (it was not getting all the attributes);
- Added discrimination between events with a certain tag, in this case "APT" through build_complex_query (thanks Giuseppe for the idea);
- Various code revamp (not necessary linked to the aforemended changes);
- Moved misp_client_cert to keys.py;
- Added: misp_excluded_tags (for tag exclusion), mintime and maxtime (for time reference regarding the query on MISP) on keys.py;
- Added various, basilar, error handling;
- Added the creation of a default 'keys.py' if not present.

# TODO:
- More configuration parameters i guess;
- Better error handling.
