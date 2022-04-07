[![LZappy87 - toids_remove](https://img.shields.io/static/v1?label=LZappy87&message=toids_remove&color=blue&logo=github)](https://github.com/LZappy87/toids_remove "Go to GitHub repo")
[![License](https://img.shields.io/badge/License-GPL--3.0_License-blue)](/LICENSE)
![Languages](https://img.shields.io/github/languages/top/LZappy87/toids_remove)
[![CodeFactor.io](https://img.shields.io/codefactor/grade/github/LZappy87/toids_remove)](https://www.codefactor.io/repository/github/lzappy87/toids_remove)
[![issues - toids_remove](https://img.shields.io/github/issues/LZappy87/toids_remove)](https://github.com/LZappy87/toids_remove/issues)
![LastCommit](https://img.shields.io/github/last-commit/LZappy87/toids_remove)

[![stars - toids_remove](https://img.shields.io/github/stars/LZappy87/toids_remove?style=social)](https://github.com/LZappy87/toids_remove)
[![forks - toids_remove](https://img.shields.io/github/forks/LZappy87/toids_remove?style=social)](https://github.com/LZappy87/toids_remove)

# MISP IDS Tag Remover

## CREATED BY: LZappy87

## LAST VERSION: 2.0

## CREATED ON: 03/02/2022

## UPDATED ON: 07/04/2022

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

## USAGE & DEMO

### Help Menu

![help](https://user-images.githubusercontent.com/47757757/162328621-a8dae99a-5016-4c9c-8cc6-9ca57fb10c09.png)

### Remove Mode (--mode rem)

![rem](https://user-images.githubusercontent.com/47757757/162329998-7855ac57-5f35-4173-b827-8665102c15fd.png)

### Reputation IDS Removal Mode (--mode reputation)

![reputation](https://user-images.githubusercontent.com/47757757/162329467-0730af58-5f14-4344-8cda-31a43661deec.png)

### Sights Only Mode (--mode reputation --sightsonly True)

![sightsonly](https://user-images.githubusercontent.com/47757757/162328927-e6dd0a35-71a2-479b-aee5-0f1850e454d7.png)

### Sights IDS Removal Mode (--mode reputation --sightsrem True)

![sightsrem](https://user-images.githubusercontent.com/47757757/162329170-375c94ed-cbb7-4c2a-9321-908b170feb3a.png)

### Demo (v 1.6, Reputation Mode)

https://user-images.githubusercontent.com/47757757/160293805-00fc37a2-87ca-46a9-b6c6-40a83c52cca2.mp4

## CHANGELOG

### v 2.0 (07/04/2022):

- Implemented sightsonly for Reputation mode: populate only sightings without removing IDS tags;
- Implemented sightsrem for Reputation mode: remove IDS tags based on sightings\false positive percentage;
- Removal of redundant code;
- Overhaul of script messages (for better understanding).

### v 1.8 (06/04/2022):
- Testing sightings mode;
- Further code optimization.

### v 1.7 (29/03/2022):
- Added sightings based on reputation results.

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
- Add more API's (for domain\url);
- Better error handling.
