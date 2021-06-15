import requests
import sys
import json
import csv
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_KEY = ''
MANAGER_URL = 'https://cloudone.trendmicro.com/'
FILENAME = 'output.csv'
COUNT_ONLY = False
REPEAT_COLUMNS = False

if not (API_KEY or MANAGER_URL):
    print("Fill the API_KEY and MANAGER_URL fields inside the script before running.")
    exit(1)

headers = {'api-secret-key': API_KEY, 'api-version': 'v1'}

# List computers
print("Listing computers...")
r = requests.get(MANAGER_URL + '/api/computers', headers=headers, verify=False)
s = json.loads(r.text)

print("Grabbing IPS information...")
with open(FILENAME, 'w', newline='') as outfile:
    wr = csv.writer(outfile, delimiter=',')
    if (COUNT_ONLY):
        wr.writerow( ['hostName', 'displayName', 'ipsState', 'ipsStatus', 'ipsRulesCount'] )
    else:
        wr.writerow( ['hostName', 'displayName', 'ipsState', 'ipsStatus', 'ipsRulesCount', 'ipsRulesID', 'ipsRulesName', 'ipsRulesSeverity', 'ipsRulesCVE'] )
    for i in s['computers']:
        print('.', end='')
        rowdata = [ i['hostName'], i['displayName'], i['intrusionPrevention']['state'], i['intrusionPrevention']['moduleStatus']['agentStatus'] ]
        if (i['intrusionPrevention']['state'] == 'off'):
            wr.writerow(rowdata + ['0'])
        else:
            t = requests.get(MANAGER_URL + '/api/computers/' + str(i['ID']) + '/intrusionprevention/rules', headers=headers, verify=False)
            u = json.loads(t.text)
            rulescount = [ len(u['intrusionPreventionRules']) ]
            if (COUNT_ONLY):
                wr.writerow(rowdata + rulescount)
            else:
                for index, j in enumerate(u['intrusionPreventionRules']):
                    ipsdata = [ j['ID'], j['name'], j['severity'] ]
                    if 'CVE' in j:
                        ipsdata = ipsdata + j['CVE']
                    if (index == 0) or (REPEAT_COLUMNS):
                        wr.writerow(rowdata + rulescount + ipsdata)
                    else:
                        wr.writerow([''] + [''] + [''] + [''] + [''] + ipsdata)

print("Done! Written to " + FILENAME)