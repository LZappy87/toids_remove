# MISP IDS Tag Remover

## CREATED BY: LZappy87

## LAST VERSION: 1.3

## CREATED ON: 03/02/2022

## UPDATED ON: 07/02/2022

## FILES USED
- toids-remove.py (this script)
- keys.py (the configuration file)

## TESTED WITH
- MISP 2.4.152
- PyMISP 2.4.152
- Python 3.8.10
- VirusTotal APIv3

## DESCRIPTION
This script it's used to disable the attribute 'to_ids' on MISP events based on two modes:
- [--mode remold] Removing IDS tags from events in the time range specified with the arguments --mintime and --maxtime with the possibility to exclude some events based on tags (like APT);
- [--mode vt] Removing IDS tags based on information gathered from selected vendors through the VirusTotal APIv3 in the time range specified with the arguments --mintime and --maxtime.

## USAGE
toids_remove.py --mode <vt, remold> --mintime <time> --maxtime <time>

--mode: can be used in:
- VirusTotal mode (vt): the removal of the to_ids attribute is decided based on the scan results pulled from the VTotal APIv3
- Remove Old mode (remold): the removal of the to_ids attribute is decided based only on the time range
  
in both cases can be specified a time range* (--mintime, --maxtime) specified in day(d) or minutes(m) and an eventual Event Tag exclusion

*: the default mintime is 1 day (1440m), the default maxtime is 1 year (365d)

An idea developed from this article: https://www.vanimpe.eu/2019/09/24/tracking-false-positives-and-disabling-to_ids-in-misp/

## CHANGELOG
### v 1.3 (07/02/2022):
- Implemented VirusTotal Mode (vt);
- Implemented Remove Old Mode (remold);
- Included arguments to launch the script;
- Moved some variables to keys.py for better configuration;
- Included the 'published=True' search constraint (this should speed up the queries);
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

## Video Example (IT)

https://user-images.githubusercontent.com/47757757/152594113-db97c724-363e-4ec9-8a8e-b3ac4c6c75db.mp4
