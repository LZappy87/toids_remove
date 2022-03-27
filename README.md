# MISP IDS Tag Remover

## CREATED BY: LZappy87

## LAST VERSION: 1.6

## CREATED ON: 03/02/2022

## UPDATED ON: 27/03/2022

## FILES USED
- toids-remove.py (this script)
- keys.py (the configuration file)

## TESTED WITH
- MISP 2.4.152
- PyMISP 2.4.152
- Python 3.8
- VirusTotal APIv3
- AbuseIPDB APIv2
- Greynoise APIv3

## LIBRARIES USED
- contextlib (contextmanager)
- sys
- os
- shutil
- time
- argparse
- prettytable (PrettyTable)
- pymisp (ExpandedPyMISP)
- urllib3
- requests
- base64
- requests
- re

## DESCRIPTION
This script it's used to disable the attribute 'to_ids' on MISP events, features removal of the IDS tag on old events or based on VirusTotal scan results.
An idea developed from this article: https://www.vanimpe.eu/2019/09/24/tracking-false-positives-and-disabling-to_ids-in-misp/

## USAGE

![image](https://user-images.githubusercontent.com/47757757/160293018-15acd81e-6e72-43c0-9d17-1df80283038c.png)

![image](https://user-images.githubusercontent.com/47757757/160292993-367a606c-30fc-4ebf-948f-76d0d51b5f14.png)


https://user-images.githubusercontent.com/47757757/160293805-00fc37a2-87ca-46a9-b6c6-40a83c52cca2.mp4


## CHANGELOG

### v 1.6 (27/03/2022):
- Minor changes to the code;
- Added further VTotal tags to maltag.

### v 1.5 (25/03/2022):
- Added Greynoise API to reputation mode;
- Added tabled results at the end of the script;
- Removed unnecessary script header informations.

### v 1.4 (21/02/2022):
- Added AbuseIPDB to the vt mode;
- vt mode now is reputation mode;
- remold mode is now rem mode;
- Added minimal error handling for AbuseIPDB API.

### v 1.3 (08/02/2022):
- Implemented VirusTotal Mode (vt);
- Implemented Remove Old Mode (remold);
- Included arguments to launch the script;
- Moved some variables to keys.py for better configuration;
- Included the 'published=True' search constraint (this should speed up the queries);
- Removed mintime and maxtime from keys.py, substituted with arguments --mintime --maxtime;
- Overall revamp of the code.

### v 1.2 (05/02/2022):
- Preparing for VirusTotal API implementation

### v 1.1 (04/02/2022):
- Removed old search string (it was not getting all the attributes);
- Added filtering based on event tags through build_complex_query (thanks Giuseppe for the idea);
- Various code revamp (not necessary linked to the aforemended changes);
- Moved misp_client_cert to keys.py;
- Added: misp_excluded_tags (for tag exclusion), mintime and maxtime (for time reference regarding the query on MISP) on keys.py;
- Added basic error handling;
- Added the creation of a default 'keys.py' if not present.

### v 1.0 (03/02/2022):
First release

## TODO:
- More configuration parameters;
- Better error handling.
