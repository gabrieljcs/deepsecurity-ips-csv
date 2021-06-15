# deepsecurity-ips-csv

Creates a .csv log of Deep Security computers and its associated IPS rules in the format:

hostName,displayName,ipsState,ipsStatus,ipsRulesCount,ipsRulesID,ipsRulesName,ipsRulesSeverity,ipsRulesCVE

There may be multiple ipsRulesIDs and its associated content per computer, and there may be rules with multiple or no CVEs.

Usage:
------
Generate an API key and fill it with your manager information inside the script.

Even though it shouldn't, a full API role is needed.

If you don't want the rules description, change ```COUNT_ONLY``` to ```True```.
If you want the first column to repeat (hostname _etc_), change ```REPEAT_COLUMNS``` to ```True```.