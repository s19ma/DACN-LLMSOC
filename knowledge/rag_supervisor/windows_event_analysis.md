# Windows Event Log Analysis for Security Investigations

## Overview

Windows Event Logs are critical data sources for security investigations. This guide covers key event IDs, analysis techniques, and investigation patterns.

## Critical Security Event IDs

### Authentication Events

#### EventID 4624 - Successful Logon

**Category:** Account Logon
**Severity:** Informational (Audit Success)

**Key Fields:**

- `LogonType`: Method of authentication

  - **2**: Interactive (Console logon)
  - **3**: Network (SMB, RPC, network share)
  - **4**: Batch (Scheduled task)
  - **5**: Service (Windows service)
  - **7**: Unlock (Workstation unlock)
  - **10**: RemoteInteractive (RDP/Terminal Services)
  - **11**: CachedInteractive (Cached credentials)

- `TargetUserName`: Account that logged on
- `WorkstationName`: Computer name where logon occurred
- `IpAddress`: Source IP address
- `LogonProcessName`: Process that authenticated
- `AuthenticationPackageName`: Protocol used (NTLM, Kerberos)

**Investigation Questions:**

1. Is the logon type normal for this user?
2. Is the source IP expected?
3. Was this preceded by failed logon attempts?
4. Does the time match user's normal working hours?

**SPL Query:**

```spl
index=windows EventCode=4624 earliest=-24h
| eval LogonType_Description = case(
    LogonType=2, "Interactive",
    LogonType=3, "Network",
    LogonType=4, "Batch",
    LogonType=5, "Service",
    LogonType=7, "Unlock",
    LogonType=10, "Remote Interactive (RDP)",
    LogonType=11, "Cached Interactive",
    1=1, "Other"
  )
| stats count by user, src_ip, LogonType_Description, computer
| where LogonType_Description="Remote Interactive (RDP)"
| sort -count
```

#### EventID 4625 - Failed Logon

**Category:** Account Logon  
**Severity:** Warning (Audit Failure)

**Key Fields:**

- `Status` and `SubStatus`: Failure reason codes
  - **0xC0000064**: User name does not exist
  - **0xC000006A**: Correct user name, wrong password
  - **0xC000006D**: Bad user name or password
  - **0xC000006E**: Account restriction
  - **0xC000006F**: Logon outside allowed time
  - **0xC0000070**: Workstation restriction
  - **0xC0000071**: Password expired
  - **0xC0000072**: Account disabled
  - **0xC000015B**: Logon type not granted
  - **0xC0000193**: Account expiration
  - **0xC0000234**: Account locked out

**Attack Indicators:**

- Multiple failures from single IP
- Failures targeting multiple accounts
- Rapid succession (< 1 second between attempts)
- After-hours activity
- Success immediately following failures

**Investigation Workflow:**

```spl
# Step 1: Identify suspicious IPs
index=windows EventCode=4625 earliest=-1h
| stats count dc(TargetUserName) as unique_users by IpAddress
| where count > 10 OR unique_users > 5
| eval priority = case(
    count > 50, "Critical",
    count > 20, "High",
    unique_users > 10, "High",
    1=1, "Medium"
  )
| sort -count

# Step 2: Timeline of activity for suspicious IP
index=windows (EventCode=4625 OR EventCode=4624) IpAddress="<suspicious_ip>" earliest=-2h
| eval event_type = case(EventCode=4625, "Failed", EventCode=4624, "Success", 1=1, "Other")
| table _time, event_type, TargetUserName, WorkstationName, Status, SubStatus
| sort _time

# Step 3: Check if any accounts were compromised
index=windows EventCode=4624 IpAddress="<suspicious_ip>" earliest=-2h
| table _time, TargetUserName, LogonType, WorkstationName
| join type=inner TargetUserName [
    search index=windows EventCode=4625 IpAddress="<suspicious_ip>" earliest=-2h
    | stats min(_time) as first_failed by TargetUserName
  ]
| where _time > first_failed
```

#### EventID 4740 - Account Lockout

**Category:** Account Management
**Severity:** Warning

**Investigation:**

```spl
index=windows EventCode=4740 earliest=-24h
| stats count by TargetUserName, TargetDomainName, Caller_Computer_Name
| sort -count
```

**Response Actions:**

1. Identify source of failed attempts (EventID 4625)
2. Check if legitimate user or attack
3. Reset password if compromised
4. Monitor for continued attempts after unlock

### Privileged Access Events

#### EventID 4672 - Special Privileges Assigned

**Category:** Privilege Use
**Severity:** Informational

**Indicates:** Administrative logon occurred
**Monitor For:**

- After-hours admin access
- Admin access from unexpected systems
- Service accounts with interactive logons

**SPL Query:**

```spl
index=windows EventCode=4672 earliest=-24h
| eval hour = strftime(_time, "%H")
| where (hour < 6 OR hour > 20)
| stats count by SubjectUserName, ComputerName, hour
| sort -count
```

#### EventID 4720 - User Account Created

**Category:** Account Management
**Severity:** Informational (High Risk)

**Investigation:**

```spl
index=windows EventCode=4720 earliest=-7d
| table _time, TargetUserName, SubjectUserName, ComputerName
| sort -_time
```

**Red Flags:**

- Account created outside change window
- Created by non-admin user
- Suspicious account name
- Creation followed by privileged activity

#### EventID 4732/4728 - User Added to Security Group

**Category:** Account Management
**Severity:** Informational (High Risk for privileged groups)

**Monitor Groups:**

- Domain Admins
- Enterprise Admins
- Administrators (local)
- Backup Operators
- Account Operators

**SPL Query:**

```spl
index=windows (EventCode=4732 OR EventCode=4728) earliest=-7d
| eval GroupName = if(isnotnull(TargetUserName), TargetUserName, TargetSid)
| where like(GroupName, "%Admin%") OR like(GroupName, "%Operator%")
| table _time, SubjectUserName, MemberName, GroupName, ComputerName
| sort -_time
```

### Process Execution Events

#### EventID 4688 - Process Creation

**Category:** Detailed Tracking
**Severity:** Informational
**Note:** Requires audit policy enabled

**Key Fields:**

- `NewProcessName`: Executable path
- `CommandLine`: Full command line arguments
- `SubjectUserName`: User who launched process
- `ParentProcessName`: Parent process

**Suspicious Indicators:**

- PowerShell with encoded commands
- Processes launched from temp directories
- Unusual parent-child relationships
- Living-off-the-land binaries (LOLBins)

**Detection Queries:**

**Suspicious PowerShell:**

```spl
index=windows EventCode=4688 NewProcessName="*powershell.exe" earliest=-24h
| where like(CommandLine, "%-enc%") OR like(CommandLine, "%-e %") OR like(CommandLine, "%bypass%") OR like(CommandLine, "%downloadstring%")
| table _time, SubjectUserName, CommandLine, ParentProcessName, ComputerName
| sort -_time
```

**Processes from Temp Directories:**

```spl
index=windows EventCode=4688 earliest=-24h
| rex field=NewProcessName "(?<process_dir>.*\\\\)"
| where like(process_dir, "%Temp%") OR like(process_dir, "%tmp%") OR like(process_dir, "%AppData\\\\Local%")
| stats count by NewProcessName, SubjectUserName, ComputerName
| sort -count
```

**Suspicious Parent-Child Relationships:**

```spl
index=windows EventCode=4688 earliest=-24h
| where (like(ParentProcessName, "%winword.exe%") OR like(ParentProcessName, "%excel.exe%"))
    AND (like(NewProcessName, "%powershell%") OR like(NewProcessName, "%cmd.exe%") OR like(NewProcessName, "%wscript%"))
| table _time, SubjectUserName, ParentProcessName, NewProcessName, CommandLine, ComputerName
```

### File Access and Modification

#### EventID 4663 - File Access Attempt

**Category:** Object Access
**Severity:** Informational
**Note:** Requires auditing on specific files/folders

**Use Cases:**

- Monitor sensitive file access
- Detect ransomware (mass file modifications)
- Insider threat detection

**Ransomware Detection:**

```spl
index=windows EventCode=4663 AccessMask="0x2" earliest=-15m
| stats dc(ObjectName) as unique_files by SubjectUserName, ProcessName
| where unique_files > 100
| eval alert = "Potential ransomware: " + unique_files + " files modified"
```

### Scheduled Tasks

#### EventID 4698 - Scheduled Task Created

**Category:** Object Access
**Severity:** Informational (High Risk)

**Attack Use:** Persistence mechanism

**Detection:**

```spl
index=windows EventCode=4698 earliest=-7d
| spath input=TaskContent
| table _time, SubjectUserName, TaskName, Command, Arguments, ComputerName
| sort -_time
```

## Investigation Playbooks

### Brute Force Investigation

**Step 1: Identify Attack Pattern**

```spl
index=windows EventCode=4625 earliest=-1h
| stats count dc(TargetUserName) as unique_targets by IpAddress
| where count > 10
| sort -count
```

**Step 2: Check Success After Failures**

```spl
index=windows (EventCode=4625 OR EventCode=4624) IpAddress="<ip>" earliest=-2h
| eval result = if(EventCode=4625, "Failed", "Success")
| table _time, result, TargetUserName, LogonType
| sort _time
```

**Step 3: Assess Impact**

```spl
index=windows EventCode=4624 IpAddress="<ip>" LogonType=10 earliest=-24h
| table _time, TargetUserName, WorkstationName
| join TargetUserName [search index=windows EventCode=4672]
```

### Lateral Movement Detection

**Suspicious Network Logons:**

```spl
index=windows EventCode=4624 LogonType=3 earliest=-1h
| stats count dc(WorkstationName) as unique_systems by TargetUserName, IpAddress
| where unique_systems > 5
| sort -unique_systems
```

**Pass-the-Hash Detection:**

```spl
index=windows EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM earliest=-1h
| where NOT like(IpAddress, "127.0.0.1") AND NOT like(IpAddress, "::1")
| stats count by IpAddress, TargetUserName, WorkstationName
| where count > 10
```

### Privilege Escalation

**Track Privilege Changes:**

```spl
index=windows (EventCode=4672 OR EventCode=4732 OR EventCode=4728) earliest=-24h
| eval event_desc = case(
    EventCode=4672, "Admin Logon",
    EventCode=4732, "Added to Local Group",
    EventCode=4728, "Added to Global Group",
    1=1, "Other"
  )
| table _time, event_desc, SubjectUserName, TargetUserName, ComputerName
| sort _time
```

## MITRE ATT&CK Mapping

### Initial Access

- T1078: Valid Accounts → Monitor 4624 with unusual patterns
- T1133: External Remote Services → Monitor 4624 LogonType=10

### Execution

- T1059: Command and Scripting → Monitor 4688 for PowerShell/cmd
- T1053: Scheduled Task → Monitor 4698

### Persistence

- T1136: Create Account → Monitor 4720
- T1053: Scheduled Task → Monitor 4698

### Privilege Escalation

- T1078: Valid Accounts → Monitor 4672
- T1134: Access Token Manipulation → Monitor 4672

### Defense Evasion

- T1070: Indicator Removal → Monitor 1102 (Event log cleared)

### Credential Access

- T1110: Brute Force → Monitor 4625 patterns

### Lateral Movement

- T1021: Remote Services → Monitor 4624 LogonType=3,10
- T1550: Use Alternate Authentication → Monitor 4624 NTLM

## Best Practices

1. **Enable Command Line Logging** - Critical for 4688 investigations
2. **Centralize Logs** - Forward to SIEM immediately
3. **Baseline Normal Activity** - Understand user behavior
4. **Alert on Anomalies** - Not just known bad
5. **Correlate Multiple Events** - Single events rarely tell full story
6. **Time Synchronization** - Ensure accurate timestamps
7. **Retention Policy** - Keep logs 90+ days minimum
8. **Protect Logs** - Event log tampering is common
