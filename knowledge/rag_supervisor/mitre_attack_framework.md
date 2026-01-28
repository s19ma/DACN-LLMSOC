# MITRE ATT&CK Framework for SOC Analysts

## Overview

The MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) framework is a comprehensive knowledge base of adversary tactics and techniques based on real-world observations.

## Tactics Overview

### TA0001: Initial Access

**Goal:** Get into your network

**Common Techniques:**

- **T1078 - Valid Accounts:** Using legitimate credentials
- **T1133 - External Remote Services:** VPN, RDP exploitation
- **T1566 - Phishing:** Email-based attacks
- **T1190 - Exploit Public-Facing Application:** Web server exploitation

**Detection Strategies:**

- Monitor authentication logs (EventID 4624/4625)
- Track VPN/RDP connections from unusual locations
- Email gateway analysis
- WAF logs for exploitation attempts

**Splunk Queries:**

```spl
# Detect external RDP connections
index=windows EventCode=4624 LogonType=10
| where NOT like(IpAddress, "10.%") AND NOT like(IpAddress, "192.168.%")
| stats count by user, IpAddress, ComputerName
```

---

### TA0002: Execution

**Goal:** Run malicious code

**Common Techniques:**

- **T1059 - Command and Scripting Interpreter**
  - T1059.001 - PowerShell
  - T1059.003 - Windows Command Shell
  - T1059.005 - Visual Basic
- **T1053 - Scheduled Task/Job:** Persistence via scheduled tasks
- **T1204 - User Execution:** Trick user into running malware

**Detection Strategies:**

- Monitor process creation (EventID 4688)
- PowerShell script block logging (EventID 4104)
- Scheduled task creation (EventID 4698)

**Indicators:**

- PowerShell with `-encodedcommand`, `-bypass`, `downloadstring`
- Processes launched from unusual locations (Temp, AppData)
- Obfuscated scripts

**Splunk Queries:**

```spl
# Suspicious PowerShell execution
index=windows EventCode=4688 NewProcessName="*powershell.exe"
| where like(CommandLine, "%-enc%") OR like(CommandLine, "%bypass%") OR like(CommandLine, "%downloadstring%")
| table _time, user, CommandLine, ParentProcessName, ComputerName
```

---

### TA0003: Persistence

**Goal:** Maintain access

**Common Techniques:**

- **T1136 - Create Account:** New user accounts for backdoor
- **T1053 - Scheduled Task:** Recurring execution
- **T1547 - Boot or Logon Autostart:** Registry run keys
- **T1543 - Create or Modify System Process:** Malicious services

**Detection Strategies:**

- New account creation (EventID 4720)
- Scheduled task creation (EventID 4698)
- Service installation (EventID 7045)
- Registry modifications

**Splunk Queries:**

```spl
# Detect new accounts created
index=windows EventCode=4720
| table _time, TargetUserName, SubjectUserName, ComputerName
| where NOT like(SubjectUserName, "admin%")

# Suspicious scheduled tasks
index=windows EventCode=4698
| spath input=TaskContent
| where like(Command, "%powershell%") OR like(Command, "%cmd%") OR like(Command, "%script%")
| table _time, TaskName, Command, SubjectUserName
```

---

### TA0004: Privilege Escalation

**Goal:** Gain higher-level permissions

**Common Techniques:**

- **T1068 - Exploitation for Privilege Escalation:** Exploit vulnerabilities
- **T1134 - Access Token Manipulation:** Impersonate higher privileges
- **T1055 - Process Injection:** Inject code into privileged process
- **T1548 - Abuse Elevation Control:** UAC bypass

**Detection Strategies:**

- Monitor privilege assignment (EventID 4672)
- Track group membership changes (EventID 4732/4728)
- Unusual access to LSASS process
- Token manipulation events

**Splunk Queries:**

```spl
# Track privilege escalation
index=windows EventCode=4672
| eval hour = strftime(_time, "%H")
| where hour < 6 OR hour > 20
| stats count by SubjectUserName, ComputerName
| where count > 5

# Users added to privileged groups
index=windows (EventCode=4732 OR EventCode=4728)
| where like(TargetUserName, "%Admin%") OR like(TargetUserName, "%Operator%")
| table _time, SubjectUserName, MemberName, TargetUserName
```

---

### TA0005: Defense Evasion

**Goal:** Avoid detection

**Common Techniques:**

- **T1070 - Indicator Removal:** Clear logs, delete files
  - T1070.001 - Clear Windows Event Logs
  - T1070.004 - File Deletion
- **T1027 - Obfuscated Files or Information:** Encode/encrypt malware
- **T1562 - Impair Defenses:** Disable AV, firewall

**Detection Strategies:**

- Event log clearing (EventID 1102, 1100)
- Windows Defender disabled
- PowerShell execution policy changes
- Mass file deletions

**Splunk Queries:**

```spl
# Detect log clearing
index=windows EventCode=1102
| table _time, user, SubjectUserName, ComputerName

# Windows Defender disabled
index=windows EventCode=5001 OR EventCode=5010 OR EventCode=5012
| table _time, EventCode, ComputerName
```

---

### TA0006: Credential Access

**Goal:** Steal credentials

**Common Techniques:**

- **T1110 - Brute Force**
  - T1110.001 - Password Guessing
  - T1110.003 - Password Spraying
- **T1003 - OS Credential Dumping**
  - T1003.001 - LSASS Memory
  - T1003.002 - Security Account Manager
- **T1056 - Input Capture:** Keylogging

**Detection Strategies:**

- Failed login monitoring (EventID 4625)
- LSASS access attempts
- Credential dumping tool detection (Mimikatz, etc.)
- Account lockouts (EventID 4740)

**Splunk Queries:**

```spl
# Brute force detection
index=windows EventCode=4625
| stats count dc(TargetUserName) as unique_targets by IpAddress
| where count > 10 OR unique_targets > 5
| eval attack_type = case(
    unique_targets > 10, "Password Spraying",
    count > 50, "Brute Force",
    1=1, "Credential Guessing"
  )

# LSASS access (potential credential dumping)
index=windows EventCode=10 TargetImage="*lsass.exe"
| table _time, SourceImage, SourceUser, GrantedAccess, ComputerName
```

---

### TA0007: Discovery

**Goal:** Learn about the environment

**Common Techniques:**

- **T1087 - Account Discovery:** Enumerate users
- **T1083 - File and Directory Discovery:** Search for sensitive files
- **T1018 - Remote System Discovery:** Find other systems
- **T1082 - System Information Discovery:** OS, hardware info

**Detection Strategies:**

- Excessive `net` command usage
- LDAP queries
- File system scanning
- Network enumeration

**Splunk Queries:**

```spl
# Reconnaissance commands
index=windows EventCode=4688
| where like(CommandLine, "%net user%") OR like(CommandLine, "%net group%") OR like(CommandLine, "%net localgroup%") OR like(CommandLine, "%whoami%")
| stats count by user, CommandLine, ComputerName
| where count > 5
```

---

### TA0008: Lateral Movement

**Goal:** Move through the network

**Common Techniques:**

- **T1021 - Remote Services**
  - T1021.001 - Remote Desktop Protocol
  - T1021.002 - SMB/Windows Admin Shares
  - T1021.006 - Windows Remote Management
- **T1550 - Use Alternate Authentication Material**
  - T1550.002 - Pass the Hash

**Detection Strategies:**

- Network logons (EventID 4624 LogonType=3)
- RDP connections from internal systems
- Admin share access ($C, $ADMIN)
- NTLM authentication patterns

**Splunk Queries:**

```spl
# Lateral movement via network logons
index=windows EventCode=4624 LogonType=3
| stats dc(WorkstationName) as unique_targets by SubjectUserName, IpAddress
| where unique_targets > 5
| sort -unique_targets

# Pass-the-hash detection
index=windows EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| where NOT like(IpAddress, "127.%") AND NOT like(IpAddress, "::1")
| stats count by IpAddress, TargetUserName
| where count > 10
```

---

### TA0009: Collection

**Goal:** Gather data of interest

**Common Techniques:**

- **T1005 - Data from Local System:** Copy files
- **T1039 - Data from Network Shared Drive:** Access shares
- **T1074 - Data Staged:** Prepare for exfiltration
- **T1113 - Screen Capture:** Screenshots

**Detection Strategies:**

- Large file access
- Data compression (zip, rar)
- Staging directories usage
- USB device connections

**Splunk Queries:**

```spl
# Detect data staging
index=windows EventCode=4663
| where like(ObjectName, "%Temp%") OR like(ObjectName, "%staging%")
| stats dc(ObjectName) as unique_files sum(eval(ObjectSize/1024/1024)) as total_mb by SubjectUserName
| where unique_files > 100 OR total_mb > 1000
```

---

### TA0010: Exfiltration

**Goal:** Steal data

**Common Techniques:**

- **T1041 - Exfiltration Over C2 Channel:** Use existing C2
- **T1048 - Exfiltration Over Alternative Protocol:** DNS, ICMP tunneling
- **T1567 - Exfiltration Over Web Service:** Cloud storage upload

**Detection Strategies:**

- Unusual outbound traffic volume
- DNS tunneling (long queries, high volume)
- Large uploads to external IPs
- After-hours data transfers

**Splunk Queries:**

```spl
# Large data transfers
index=network earliest=-1h
| eval bytes_mb = bytes / 1024 / 1024
| where bytes_mb > 100
| stats sum(bytes_mb) as total_mb by src_ip, dest_ip
| where total_mb > 1000
| sort -total_mb

# DNS tunneling detection
index=dns
| eval query_length = len(query)
| where query_length > 50
| stats count avg(query_length) as avg_len by src_ip
| where count > 100
```

---

### TA0011: Impact

**Goal:** Disrupt operations

**Common Techniques:**

- **T1486 - Data Encrypted for Impact:** Ransomware
- **T1490 - Inhibit System Recovery:** Delete backups
- **T1485 - Data Destruction:** Delete files
- **T1489 - Service Stop:** Stop critical services

**Detection Strategies:**

- Mass file modifications
- Backup deletion
- Volume Shadow Copy deletion
- Service stops

**Splunk Queries:**

```spl
# Ransomware detection (mass file changes)
index=windows EventCode=4663 AccessMask="0x2"
| stats dc(ObjectName) as files_modified by SubjectUserName, ProcessName
| where files_modified > 100
| eval alert_level = case(
    files_modified > 1000, "Critical",
    files_modified > 500, "High",
    1=1, "Medium"
  )

# Shadow copy deletion (ransomware indicator)
index=windows EventCode=4688
| where like(CommandLine, "%vssadmin%delete%shadows%") OR like(CommandLine, "%wmic%shadowcopy%delete%")
| table _time, user, CommandLine, ComputerName
```

---

## Mapping Alerts to MITRE ATT&CK

When investigating an alert, map it to ATT&CK:

1. **Identify the Tactic:** What is the adversary trying to achieve?
2. **Find the Technique:** How are they doing it?
3. **Search for Related Techniques:** What else might they do?
4. **Build Detection:** Create queries for the technique
5. **Document Findings:** Reference ATT&CK IDs in reports

**Example Mapping:**

- Alert: Multiple failed logins
- Tactic: TA0006 - Credential Access
- Technique: T1110.001 - Password Guessing
- Related: T1110.003 - Password Spraying
- Detection: Monitor EventID 4625 patterns

---

## Integration with SOC Workflow

### Alert Triage

```
1. Receive alert
2. Identify MITRE technique
3. Check for related techniques
4. Search for indicators
5. Assess impact
```

### Investigation

```
1. Map alert to ATT&CK tactic
2. Review technique details
3. Check for prerequisites
4. Look for next stages
5. Hunt for related activity
```

### Reporting

```
Observed Techniques:
- T1078: Valid Accounts (Initial Access)
- T1059.001: PowerShell (Execution)
- T1070.001: Clear Event Logs (Defense Evasion)

Kill Chain Stage: Mid-stage attack with privilege escalation
```

---

## Resources

- **MITRE ATT&CK Website:** https://attack.mitre.org/
- **ATT&CK Navigator:** Visualize coverage
- **MITRE CAR:** Cyber Analytics Repository
- **Splunk Security Content:** Pre-built detections

---

## Quick Reference

| Tactic               | Focus              | Key Events          |
| -------------------- | ------------------ | ------------------- |
| Initial Access       | Entry points       | 4624, VPN logs      |
| Execution            | Code running       | 4688, 4104          |
| Persistence          | Maintaining access | 4720, 4698, 7045    |
| Privilege Escalation | Gaining privileges | 4672, 4732          |
| Defense Evasion      | Hiding activity    | 1102, 5001          |
| Credential Access    | Stealing creds     | 4625, 4740          |
| Discovery            | Reconnaissance     | 4688 (net commands) |
| Lateral Movement     | Spreading          | 4624 (Type 3)       |
| Collection           | Gathering data     | 4663                |
| Exfiltration         | Stealing data      | Network logs        |
| Impact               | Destruction        | 4663 (mass changes) |
