#!/usr/bin/env python3
# Needed to do the request towards the VTotal API
import requests
# This is for the last update timestamp (specified in epoch into the request)
import datetime
# Needed for the URL report part
import base64
# Regex to discern IP from URL
import re
# Importing informations from keys.py
from keys import vtotal_key

# Set informations to connect to the VTotal APIv3
headers = {
    "Accept": "application/json",
    "x-apikey": vtotal_key

}

# This is for testing purpose
indtype = ""

# Request in input an indicator
indicator = input("Please insert an indicator: ")

# IP
if re.match("^(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})){3}$", indicator):
    url = "https://www.virustotal.com/api/v3/ip_addresses/" + indicator
    indtype = "IP"
# URL
elif re.match("^(http:\/\/|https:\/\/).+$", indicator):
    url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
    url = "https://www.virustotal.com/api/v3/urls/" + url_id
    indtype = "URL"
# Domain
elif re.match("^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$", indicator):
    url = "https://www.virustotal.com/api/v3/domains/" + indicator
    indtype = "Domain"
# Invalid input
else:
    print("No valid indicator found, exiting...")
    quit()

# Send request to the API
response = requests.request("GET", url, headers=headers)

# Parsing the object in JSON
jsonresp = response.json()

# Response check
httpresponse = str(response)

if "20" in httpresponse:
    print("Connection established, information downloaded!")
else:
    print("No connection established")
    print("Error Type:", jsonresp['error']['code'])
    print("Error Message: ", jsonresp['error']['message'])
    quit()

# Extracting last update
lastmod = datetime.datetime.fromtimestamp(jsonresp['data']['attributes']['last_modification_date'])

# Extracting stats
malicious = jsonresp['data']['attributes']['last_analysis_stats']['malicious']
suspicious = jsonresp['data']['attributes']['last_analysis_stats']['suspicious']
undetected = jsonresp['data']['attributes']['last_analysis_stats']['undetected']
harmless = jsonresp['data']['attributes']['last_analysis_stats']['harmless']
timeout = jsonresp['data']['attributes']['last_analysis_stats']['timeout']

# Print results
print('Indicator: ', indicator)
print('Indicator type: ', indtype)
print('Last update: ', lastmod)
print('### Scan results based on vendor feedback ###')
print('Malicious: ', malicious)
print('Suspicious: ', suspicious)
print('Harmless:', harmless)
print('Undetected: ', undetected)
print('Timeout: ', timeout)
