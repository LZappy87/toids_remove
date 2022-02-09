# MISP IDS Tag Remover

## CREATED BY: LZappy87

## LAST VERSION: 1.3

## CREATED ON: 03/02/2022

## UPDATED ON: 08/02/2022

## FILES USED
- toids-remove.py (this script)
- keys.py (the configuration file)

## TESTED WITH
- MISP 2.4.152
- PyMISP 2.4.152
- Python 3.8.10
- VirusTotal APIv3

## DESCRIPTION
This script it's used to disable the attribute 'to_ids' on MISP events, features removal of the IDS tag on old events or based on VirusTotal scan results.

## USAGE
toids_remove.py --mode <vt, remold> --mintime [time] --maxtime [time]

--mode: can be used in:
- VirusTotal mode (vt): the removal of the to_ids attribute is decided based on the scan results pulled from the VTotal APIv3
- Remove Old mode (remold): the removal of the to_ids attribute is decided based only on the time range
  
in both cases can be specified a time range* (--mintime, --maxtime) specified in day(d), minutes(m) or seconds(s) and an eventual Event Tag exclusion

*: the default mintime is now (0s), the default maxtime is 1 year (365d)

An idea developed from this article: https://www.vanimpe.eu/2019/09/24/tracking-false-positives-and-disabling-to_ids-in-misp/

![image](https://user-images.githubusercontent.com/47757757/153057691-78330e8a-aad7-4311-9404-99a8f1cb4b53.png)

https://user-images.githubusercontent.com/47757757/153056860-dc4d2b04-a201-474a-a1c3-1a79c36cdda3.mp4

## CHANGELOG
### v 1.3 (07/02/2022):
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
