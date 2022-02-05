# MISP IDS Tag Remover for old entries

## CREATED BY: LZappy87

## LAST VERSION: 1.1

## CREATED ON: 03/02/2022

## UPDATED ON: 04/02/2022

## FILES USED
- toids-remove.py (this script)
- keys.py (take it as a 'config file', auto-generated if not present)

## TESTED WITH
- MISP 2.4.152
- PyMISP 2.4.152
- Python 3.8.10

## DESCRIPTION
This script it's used to disable all 'to_ids' tags on selected MISP Events and then republish them, fully configurable through the keys.py file wich contains:

misp_url            | URL of the MISP instance

misp_key            | The API key needed to access the Rest API

misp_verifycert     | If the MISP instance have a certificate (default: false)

misp_client_cert    | The path of the certificate (default: none)

misp_excluded_tags  | List of tags to exclude (need to be a list)

maxtime             | Maximum time for the misp.search (in days, ex: 365d)

mintime             | Minimum time for the misp.search (in days, ex: 365d)

An idea developed from this article: https://www.vanimpe.eu/2019/09/24/tracking-false-positives-and-disabling-to_ids-in-misp/

## CHANGELOG
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
- More configuration parameters i guess;
- Implement vtotal-test.py functions into the main script;
- Better error handling.

## Video Example (IT)

https://user-images.githubusercontent.com/47757757/152594113-db97c724-363e-4ec9-8a8e-b3ac4c6c75db.mp4
