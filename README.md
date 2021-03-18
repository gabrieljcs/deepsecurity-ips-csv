# deepsecurity-ips-csv

Creates a .csv log of Deep Security computers and its associated IPS rules in the format:

hostName,displayName,ipsState,ipsStatus,ipsRulesCount,ipsRulesID,ipsRulesName,ipsRulesSeverity,ipsRulesCVE

There may be multiple ipsRulesIDs and its associated content per computer, and there may be rules with multiple or no CVEs.
