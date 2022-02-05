#!/usr/bin/env python3
# Needed to do the request towards the VTotal API
import requests
# This is for the last update timestamp (specified in epoch into the request)
import datetime
# Needed for the URL report
import base64
# Regex to discern IP from URL
import re

# Set informations to connect to the VTotal APIv3
headers = {
	"Accept": "application/json",
	"x-apikey": "[REDACTED]"

}

# Request in input an indicator
indicator = input("Please insert an indicator: ")

# IP
if re.match("^(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})){3}$", indicator):
	url = "https://www.virustotal.com/api/v3/ip_addresses/" + indicator
# URL
elif re.match("^(http:\/\/|https:\/\/).+$", indicator):
	url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
	url = "https://www.virustotal.com/api/v3/urls/" + url_id
# Invalid input
else:
	print("No valid indicator found, exiting...")
	quit()

# Send request to the API
response = requests.request("GET", url, headers=headers)

# Parsing the object in JSON
jsonresp = response.json()

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
print('Last update: ', lastmod)
print('### Scan results based on vendor feedback ###')
print('Malicious: ', malicious)
print('Suspicious: ', suspicious)
print('Harmless:', harmless)
print('Undetected: ', undetected)
print('Timeout: ', timeout)
