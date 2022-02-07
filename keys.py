#!/usr/bin/env python3

# MISP API Connection Parameters
misp_url = '<MISP URL HERE>'
misp_key = '<MISP API KEY HERE>'

# If MISP have a self-signed certificate keep it to false, otherwise set it to true
# and populate the misp_client_cert with the path to the certificate
misp_verifycert = False
misp_client_cert = None

# MISP Search Parameters
misp_excluded_tags = ['<PUT HERE THE TAGS TO EXCLUDE>']
# /!\ DO NOT TOUCH typlist VALUES FOR NOW /!\
typlist = ['ip-src','ip-dst','domain','url','hostname']

# VirusTotal APIv3 + Search Parameters
vtotal_key = '<VTOTAL API KEY HERE>'
maltag = ['malware','malicious']
vlist = ['Snort IP sample list','PhishLabs','OpenPhish','AlienVault','Sophos','Fortinet','Google Safebrowsing','Abusix','EmergingThreats','MalwareDomainList','Kaspersky','URLhaus','Spamhaus','NotMining','Forcepoint ThreatSeeker','Certego','ESET','ThreatHive','FraudScore']
vtrusted = ['Fortinet','Alienvault','Sophos','Google Safebrowsing','Abusix','Kaspersky','Forcepoint ThreatSeeker','ESET']
