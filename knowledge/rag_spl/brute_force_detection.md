# Brute Force Attack Detection in Splunk

## Overview

Brute force attacks involve repeated authentication attempts to guess credentials. Common targets include Windows domain controllers, SSH servers, web applications, and VPN gateways.

## Detection Patterns

### Windows Failed Logon Detection

**Use Case:** Detect potential brute force attacks against Windows systems

**Key Indicators:**

- Multiple EventCode 4625 (failed logon) events
- Same source IP targeting multiple accounts
- Rapid succession of failed attempts
- Different usernames from single source

**SPL Query Pattern:**

```spl
index=windows EventCode=4625 earliest=-1h
| stats count dc(user) as unique_users by src_ip
| where count > 10 OR unique_users > 5
| eval risk_score = count * unique_users
| sort -risk_score
| head 20
```

**Field Explanation:**

- `EventCode=4625`: Windows failed logon event
- `src_ip`: Source IP address of attack
- `user`: Target username
- `count`: Number of failed attempts
- `dc(user)`: Distinct count of targeted users

### Linux SSH Brute Force

**Use Case:** Detect SSH brute force attempts on Linux servers

**SPL Query Pattern:**

```spl
index=linux sourcetype=linux_secure "Failed password" earliest=-1h
| rex field=_raw "Failed password for (?<target_user>\S+) from (?<src_ip>[\d.]+)"
| stats count by src_ip, target_user
| where count > 5
| sort -count
```

**Detection Logic:**

- Parse SSH authentication logs
- Extract source IP and target username
- Count failed attempts per IP/user combination
- Alert on threshold exceeds

### Web Application Login Failures

**Use Case:** Detect web application credential stuffing

**SPL Query Pattern:**

```spl
index=web sourcetype=access_combined status=401 earliest=-1h
| stats count dc(user) as unique_users by src_ip, uri
| where count > 20
| eval attack_type = if(unique_users > 10, "credential_stuffing", "brute_force")
| sort -count
```

## Risk Scoring Formula

**High Risk (Score > 80):**

- More than 50 failed attempts
- Targeting 10+ different accounts
- Multiple systems targeted
- Success after failures (account compromise)

**Medium Risk (Score 40-80):**

- 20-50 failed attempts
- 5-10 different accounts targeted
- Single system targeted

**Low Risk (Score < 40):**

- Less than 20 attempts
- Could be legitimate user error
- Single account targeted

## Response Actions

### Immediate Actions:

1. Check if any successful logins occurred after failures
2. Identify if IP is internal or external
3. Check threat intelligence for known malicious IP
4. Review account lockout status

### Investigation Queries:

**Check for successful logins after failures:**

```spl
index=windows (EventCode=4625 OR EventCode=4624) src_ip="<suspicious_ip>" earliest=-2h
| eval event_type = case(EventCode=4625, "Failed", EventCode=4624, "Success")
| table _time, event_type, user, src_ip
| sort _time
```

**Find all activity from suspicious IP:**

```spl
index=* src_ip="<suspicious_ip>" earliest=-24h
| stats count by index, sourcetype, action
| sort -count
```

### Containment:

- Block source IP at firewall
- Force password reset for targeted accounts
- Enable MFA if not already active
- Monitor for lateral movement

## Common False Positives

1. **Service Account Misconfigurations:**

   - Scheduled tasks with wrong credentials
   - Application connection strings
   - **Mitigation:** Exclude known service accounts

2. **VPN Reconnection Issues:**

   - Users with connectivity problems
   - **Mitigation:** Set higher thresholds for VPN sources

3. **Password Expiration:**
   - Users trying old passwords
   - **Mitigation:** Correlate with password change events

## Optimization Tips

1. **Index Selection:** Use specific indexes (windows, linux) instead of index=\*
2. **Time Range:** Start with recent time ranges (earliest=-1h)
3. **Field Extraction:** Pre-extract common fields at index time
4. **Baseline:** Establish normal failed login rates per user/IP
5. **Exclude Known Sources:** Filter out legitimate retry sources

## Integration with Threat Intel

Enhance detection by correlating with threat intelligence:

```spl
index=windows EventCode=4625 earliest=-1h
| stats count by src_ip
| where count > 10
| lookup threat_intel_ips ip as src_ip OUTPUT threat_level, threat_type
| where isnotnull(threat_level)
| eval priority = case(
    threat_level="high", "Critical",
    threat_level="medium", "High",
    1=1, "Medium"
  )
| sort -count
```

## MITRE ATT&CK Mapping

- **Tactic:** Credential Access
- **Technique:** T1110 - Brute Force
  - T1110.001 - Password Guessing
  - T1110.002 - Password Cracking
  - T1110.003 - Password Spraying
  - T1110.004 - Credential Stuffing
