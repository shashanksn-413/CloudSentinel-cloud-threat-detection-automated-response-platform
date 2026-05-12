# CloudSentinel Attack Simulation Scenarios

## Overview
12 attack scenarios were executed to validate all 7 CloudTrail-based detection rules. Each scenario was run through AWS Lambda test events simulating real CloudTrail event payloads.

## Scenario 1: Root Account Creates Access Key
- **MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts)
- **Event:** CreateAccessKey from IP 203.0.113.99
- **Detection:** root_account_usage rule triggered immediately
- **AI Triage:** Severity 5/5, Confidence 1.0, Action: isolate
- **Response:** Alert only (root keys not auto-revoked by design)

## Scenario 2: Junior Dev Attaches AdministratorAccess
- **MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism)
- **Event:** AttachUserPolicy from IP 185.220.101.42
- **Detection:** iam_privilege_escalation rule triggered
- **AI Triage:** Severity 5/5, Confidence 0.9, Action: escalate
- **Response:** IAM key revocation attempted

## Scenario 3: S3 Bucket Enumeration
- **MITRE ATT&CK:** T1530 (Data from Cloud Storage)
- **Event:** 10 rapid ListBuckets calls from IP 45.33.32.156
- **Detection:** s3_enumeration rule triggered on 10th call
- **AI Triage:** Severity 4/5, Confidence 0.85, Action: escalate
- **Response:** IAM key revocation attempted

## Scenario 4: Security Group Opens SSH/RDP to Internet
- **MITRE ATT&CK:** T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall)
- **Event:** AuthorizeSecurityGroupIngress opening ports 22, 3389 to 0.0.0.0/0
- **Detection:** security_group_modification rule triggered
- **AI Triage:** Severity 5/5, Confidence 0.9, Action: escalate
- **Response:** Alert only (manual review required)

## Scenario 5: Impossible Travel Detection
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Event:** Same user logs in from 72.21.198.66 then 176.119.4.30 within minutes
- **Detection:** impossible_travel rule triggered on second login
- **AI Triage:** Severity 5/5, Confidence 0.9, Action: isolate
- **Response:** IAM key revocation attempted

## Scenario 6: Brute Force Console Login
- **MITRE ATT&CK:** T1110 (Brute Force)
- **Event:** 5 failed ConsoleLogin attempts from IP 91.240.118.172
- **Detection:** brute_force_login rule triggered on 5th failure
- **AI Triage:** Severity 5/5, Confidence 0.9, Action: escalate
- **Response:** IAM key revocation attempted

## Scenario 7: Access Key Used from New IP
- **MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts)
- **Event:** Key AKIAIOSFODNN7EXAMPLE used from 185.156.73.54 (previously only seen from 10.0.0.50)
- **Detection:** new_ip_access_key_usage rule triggered
- **AI Triage:** Severity 4/5, Confidence 0.85, Action: escalate
- **Response:** IAM key revocation attempted

## Scenario 8: Intern Creates Backdoor Access Key
- **MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism)
- **Event:** CreateAccessKey for user backdoor-admin from IP 45.155.205.99
- **Detection:** iam_privilege_escalation rule triggered
- **AI Triage:** Severity 5/5, Confidence 0.9, Action: escalate
- **Response:** IAM key revocation attempted

## Scenario 9: Contractor Injects Admin Policy into Lambda Role
- **MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism)
- **Event:** PutRolePolicy on lambda-execution-role from IP 194.26.29.110
- **Detection:** iam_privilege_escalation rule triggered
- **AI Triage:** Severity 5/5, Confidence 0.9, Action: escalate
- **Response:** IAM key revocation attempted

## Scenario 10: Root Console Login from Tor Exit Node
- **MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts)
- **Event:** ConsoleLogin from Tor IP 23.129.64.100
- **Detection:** root_account_usage rule triggered
- **AI Triage:** Severity 5/5, Confidence 1.0, Action: escalate
- **Response:** Alert only (root keys not auto-revoked by design)

## Scenario 11: DevOps Opens MySQL to Internet
- **MITRE ATT&CK:** T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall)
- **Event:** AuthorizeSecurityGroupIngress opening port 3306 to 0.0.0.0/0
- **Detection:** security_group_modification rule triggered
- **AI Triage:** Severity 5/5, Confidence 0.9, Action: escalate
- **Response:** Alert only (manual review required)

## Scenario 12: Compromised Dev Self-Escalates to Administrators
- **MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism)
- **Event:** AddUserToGroup adding self to Administrators from IP 89.248.167.131
- **Detection:** iam_privilege_escalation rule triggered
- **AI Triage:** Severity 5/5, Confidence 0.9, Action: escalate
- **Response:** IAM key revocation attempted