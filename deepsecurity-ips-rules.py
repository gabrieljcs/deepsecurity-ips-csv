import requests
import sys
import json
import csv
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_KEY = ''
MANAGER_URL = ''
FILENAME = 'output.csv'

if (API_KEY == '' or MANAGER_URL == ''):
    print("Fill the API_KEY and MANAGER_URL fields inside the script before running.")
    exit(1)

headers = {'api-secret-key': API_KEY, 'api-version': 'v1'}

# List computers
print("Listing computers...")
r = requests.get(MANAGER_URL + '/api/computers', headers=headers, verify=False)
s = json.loads(r.text)

print("Grabbing IPS information...")
with open(FILENAME, 'w') as outfile:
    wr = csv.writer(outfile, delimiter=',')
    wr.writerow( ['hostName', 'displayName', 'ipsState', 'ipsStatus', 'ipsRulesCount', 'ipsRulesID', 'ipsRulesName', 'ipsRulesSeverity', 'ipsRulesCVE'] )
    for i in s['computers']:
        print('.', end='')
        rowdata = [ i['hostName'], i['displayName'], i['intrusionPrevention']['state'], i['intrusionPrevention']['moduleStatus']['agentStatus'] ]
        if (i['intrusionPrevention']['state'] == 'off'):
            wr.writerow(rowdata + ['0'])
        else:
            t = requests.get(MANAGER_URL + '/api/computers/' + str(i['ID']) + '/intrusionprevention/rules', headers=headers, verify=False)
            u = json.loads(t.text)
            ipsdata = [ len(u['intrusionPreventionRules']) ]
            for j in u['intrusionPreventionRules']:
                ipsdata = ipsdata + [ j['ID'], j['name'], j['severity'] ]
                if 'CVE' in j:
                    ipsdata = ipsdata + j['CVE']
            wr.writerow(rowdata + ipsdata)

print("Done! Written to " + FILENAME)