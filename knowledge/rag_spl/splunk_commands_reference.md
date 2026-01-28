# Splunk SPL Commands Reference for Security Operations

## Core Search Commands

### search

**Purpose:** Filter events based on keywords and field values

**Syntax:**

```spl
search <search-expression>
```

**Examples:**

```spl
search error
search src_ip="192.168.1.100"
search EventCode=4625 OR EventCode=4624
```

**Best Practices:**

- Not required at start of query (implied)
- Use specific field searches instead of keywords when possible
- Combine with AND/OR/NOT for complex logic

### where

**Purpose:** Filter results using boolean expressions and eval functions

**Syntax:**

```spl
where <predicate-expression>
```

**Examples:**

```spl
| where count > 10
| where src_ip != dest_ip
| where like(user, "admin%")
| where isnotnull(malware_name)
```

**Best Practices:**

- Use after aggregation commands (stats, timechart)
- Supports complex boolean logic
- Can use eval functions (like, match, etc.)

## Aggregation Commands

### stats

**Purpose:** Calculate statistics and aggregate data

**Syntax:**

```spl
stats <stats-function>... [by <field-list>]
```

**Common Functions:**

- `count`: Count events
- `dc(field)`: Distinct count
- `sum(field)`: Sum values
- `avg(field)`: Average values
- `max(field)`, `min(field)`: Max/min values
- `values(field)`: List unique values
- `list(field)`: List all values

**Examples:**

```spl
| stats count by src_ip, dest_ip
| stats dc(user) as unique_users, sum(bytes) as total_bytes by src_ip
| stats count, avg(response_time) by application
```

**Security Use Cases:**

```spl
# Count failed logins per IP
index=windows EventCode=4625
| stats count by src_ip
| where count > 10

# Find IPs targeting multiple accounts
index=windows EventCode=4625
| stats dc(user) as targeted_accounts by src_ip
| where targeted_accounts > 5
```

### timechart

**Purpose:** Create time-series statistics

**Syntax:**

```spl
timechart [span=<time>] <stats-function>... [by <field>]
```

**Examples:**

```spl
| timechart span=1h count by severity
| timechart span=5m avg(response_time)
| timechart span=1d dc(src_ip) as unique_ips
```

**Best Practices:**

- Use appropriate span (don't over-granular)
- Limit "by" field cardinality (< 10 series)
- Use for trend analysis and visualization

## Transformation Commands

### eval

**Purpose:** Calculate and create new fields

**Syntax:**

```spl
eval <field>=<expression>
```

**Common Functions:**

- Math: `+`, `-`, `*`, `/`, `%`
- String: `upper()`, `lower()`, `len()`, `substr()`, `replace()`
- Conditional: `case()`, `if()`, `coalesce()`
- Type conversion: `tonumber()`, `tostring()`

**Security Examples:**

```spl
# Calculate risk score
| eval risk_score = failed_logins * 10 + successful_logins * 5

# Classify severity
| eval severity_level = case(
    count > 100, "Critical",
    count > 50, "High",
    count > 10, "Medium",
    1=1, "Low"
  )

# Convert bytes to MB
| eval bytes_mb = bytes / 1024 / 1024

# Extract domain from email
| eval domain = replace(email, ".*@(.*)$", "\1")
```

### rex

**Purpose:** Extract fields using regular expressions

**Syntax:**

```spl
rex field=<field> "<regex-with-named-groups>"
```

**Examples:**

```spl
# Extract IP from message
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"

# Extract user and action
| rex field=message "User (?<user>\w+) performed (?<action>\w+)"

# Extract multiple fields
| rex field=_raw "(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?<severity>\w+)\] (?<message>.*)"
```

**Best Practices:**

- Use field extraction at index time when possible
- Test regex before deployment
- Use named groups for clarity
- Consider performance impact on large datasets

### table

**Purpose:** Display specific fields in tabular format

**Syntax:**

```spl
table <field-list>
```

**Examples:**

```spl
| table _time, src_ip, dest_ip, action, user
| table alert_id, severity, description
```

**Best Practices:**

- Use at end of query for final output
- Include \_time for temporal context
- Order fields logically (time, source, destination, action)

## Filtering Commands

### head / tail

**Purpose:** Return first/last N results

**Syntax:**

```spl
head <n>
tail <n>
```

**Examples:**

```spl
| head 20
| tail 10
```

**Security Use Cases:**

```spl
# Top 10 talkers
| stats sum(bytes) as total_bytes by src_ip
| sort -total_bytes
| head 10

# Most recent alerts
| sort -_time
| head 50
```

### dedup

**Purpose:** Remove duplicate events

**Syntax:**

```spl
dedup <field-list> [keepevents=true|false]
```

**Examples:**

```spl
| dedup src_ip
| dedup src_ip, dest_ip
| dedup user keepevents=true
```

**Best Practices:**

- Use after initial filtering
- Consider if you need first or last occurrence
- Be careful with large datasets (performance impact)

## Lookup Commands

### lookup

**Purpose:** Enrich data with external lookup tables

**Syntax:**

```spl
lookup <lookup-name> <lookup-field> as <event-field> OUTPUT <output-fields>
```

**Security Examples:**

```spl
# Threat intel enrichment
| lookup threat_intel_ips ip as src_ip OUTPUT threat_level, threat_type

# Asset information
| lookup asset_inventory ip as dest_ip OUTPUT hostname, owner, criticality

# User information
| lookup user_directory username as user OUTPUT department, manager, risk_score
```

**Best Practices:**

- Keep lookup tables up to date
- Use automatic lookups for common enrichments
- Consider performance with large lookup tables
- Index important lookup data when possible

## Join and Append Commands

### join

**Purpose:** Combine results from two searches

**Syntax:**

```spl
... | join [type=inner|left|right] <field-list> [subsearch]
```

**Examples:**

```spl
index=firewall action=blocked
| join src_ip [search index=threat_intel malicious=true]

index=windows EventCode=4625
| stats count by src_ip
| join src_ip [search index=firewall | stats dc(dest_ip) as targets by src_ip]
```

**Best Practices:**

- Avoid when possible (use stats instead)
- Use only for small result sets
- Consider using append or stats with "by" clause
- Limit subsearch results

### append

**Purpose:** Append results from subsearch

**Syntax:**

```spl
... | append [subsearch]
```

**Examples:**

```spl
index=windows EventCode=4625
| append [search index=linux source="/var/log/auth.log" "Failed password"]
```

## Performance Optimization Tips

### Index Selection

```spl
# Good: Specific index
index=windows EventCode=4625

# Bad: All indexes
index=* EventCode=4625
```

### Time Range

```spl
# Always specify time range
index=windows EventCode=4625 earliest=-1h latest=now

# For historical analysis
index=windows EventCode=4625 earliest=-7d@d latest=@d
```

### Field Filtering

```spl
# Filter early in query
index=windows EventCode=4625 src_ip="10.*"
| stats count by user

# Don't filter late
index=windows
| stats count by src_ip, user, EventCode
| where EventCode=4625 AND like(src_ip, "10.%")
```

### Stats vs Transaction

```spl
# Preferred: Use stats
index=web
| stats count by session_id, user

# Avoid: Transaction is slower
index=web
| transaction session_id, user maxspan=30m
```

## Security-Specific Commands

### tstats (for accelerated data models)

**Purpose:** Fast statistics on indexed data

**Syntax:**

```spl
| tstats <stats-function>... from datamodel=<datamodel> where <filter> by <field>
```

**Examples:**

```spl
| tstats count from datamodel=Authentication where Authentication.action=failure by Authentication.src, Authentication.user

| tstats sum(Web.bytes) as total_bytes from datamodel=Web by Web.src, Web.dest
```

**Best Practices:**

- Requires accelerated data models
- Much faster than regular search for large time ranges
- Use for summary dashboards and reports

## Common Security Query Patterns

### Failed Login Investigation

```spl
index=windows EventCode=4625 earliest=-24h
| eval Failure_Reason=case(
    like(Failure_Reason, "%0xC000006D%"), "Bad Username",
    like(Failure_Reason, "%0xC000006A%"), "Bad Password",
    like(Failure_Reason, "%0xC0000234%"), "Account Locked",
    1=1, "Other"
  )
| stats count by src_ip, user, Failure_Reason
| where count > 5
| sort -count
```

### Network Connection Baseline

```spl
index=network earliest=-7d
| stats dc(dest_ip) as unique_destinations, sum(bytes) as total_bytes by src_ip, hour
| eventstats avg(unique_destinations) as avg_dest, stdev(unique_destinations) as stdev_dest by src_ip
| eval zscore = (unique_destinations - avg_dest) / stdev_dest
| where zscore > 3
```

### Malware Process Detection

```spl
index=endpoint (process_name=*.exe OR process_name=*.dll)
| rex field=process_path "(?<drive>[A-Z]:)"
| where drive!="C:" OR NOT like(process_path, "%Windows%")
| stats count by computer, process_name, process_path, user
| where count < 5
```
