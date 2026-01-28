# IP Address Enrichment and Threat Intelligence Procedures

## Overview

IP address enrichment is critical for security investigations. This document covers procedures for gathering threat intelligence from multiple sources and calculating risk scores.

## Threat Intelligence Sources

### Primary Sources

#### 1. VirusTotal

**API Endpoint:** `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
**Authentication:** API Key in header `x-apikey`

**Data Provided:**

- Reputation score
- Malicious detections count
- Suspicious detections count
- Community votes (harmless/malicious)
- Associated malware samples
- Communicating files
- Historical WHOIS data

**Rate Limits:**

- Free tier: 4 requests/minute
- Standard: 500 requests/day

**Response Interpretation:**

```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 15,
        "suspicious": 3,
        "harmless": 50,
        "undetected": 20
      },
      "reputation": -50,
      "country": "CN"
    }
  }
}
```

**Risk Assessment:**

- `malicious > 5`: High risk - Known malicious IP
- `malicious 1-5`: Medium risk - Some detections
- `suspicious > 10`: Medium risk - Suspicious activity
- `malicious = 0 AND reputation < -10`: Low-Medium risk
- `malicious = 0 AND reputation >= 0`: Low risk

#### 2. AbuseIPDB

**API Endpoint:** `https://api.abuseipdb.com/api/v2/check`
**Authentication:** API Key in header `Key`

**Data Provided:**

- Abuse confidence score (0-100)
- Total reports count
- Number of distinct users who reported
- Last reported date
- Usage type (ISP, hosting, etc.)
- Is whitelisted flag

**Rate Limits:**

- Free tier: 1,000 requests/day
- Paid: Higher limits based on plan

**Response Interpretation:**

```json
{
  "data": {
    "abuseConfidenceScore": 95,
    "totalReports": 47,
    "numDistinctUsers": 15,
    "isWhitelisted": false,
    "usageType": "Data Center/Web Hosting/Transit"
  }
}
```

**Risk Assessment:**

- `abuseConfidenceScore >= 90`: High risk - Confirmed abuse
- `abuseConfidenceScore 50-89`: Medium risk - Likely malicious
- `abuseConfidenceScore 25-49`: Low-Medium risk - Some reports
- `abuseConfidenceScore < 25`: Low risk - Few or old reports

### Secondary Sources (Optional)

#### 3. AlienVault OTX

**Purpose:** Community threat intelligence
**Data:** Pulses, indicators, related malware

#### 4. Shodan

**Purpose:** Open port scanning, service identification
**Data:** Open ports, running services, vulnerabilities

#### 5. GreyNoise

**Purpose:** Distinguish targeted attacks from internet noise
**Data:** Scanner classification, tags, intent

## IP Enrichment Workflow

### Step 1: Validate IP Address

```python
def validate_ip(ip_address):
    """Validate and check if IP is public"""
    import ipaddress

    try:
        ip_obj = ipaddress.ip_address(ip_address)

        # Check if private/internal
        if ip_obj.is_private:
            return False, "Private IP - RFC1918"

        if ip_obj.is_loopback:
            return False, "Loopback address"

        if ip_obj.is_reserved:
            return False, "Reserved IP"

        if ip_obj.is_multicast:
            return False, "Multicast address"

        return True, "Valid public IP"

    except ValueError:
        return False, "Invalid IP format"
```

### Step 2: Check Local Cache

```python
def check_cache(ioc_value, max_age_hours=24):
    """Check if IOC enrichment exists in cache"""
    import json
    from datetime import datetime, timedelta

    cache_file = f"cache_data/{ioc_value}.json"

    if not os.path.exists(cache_file):
        return None

    try:
        with open(cache_file, 'r') as f:
            cached_data = json.load(f)

        # Check cache age
        cached_time = datetime.fromisoformat(cached_data['timestamp'])
        if datetime.now() - cached_time < timedelta(hours=max_age_hours):
            return cached_data

    except Exception as e:
        logger.error(f"Cache read error: {e}")

    return None
```

### Step 3: Query Threat Intelligence APIs

#### VirusTotal Query

```python
def query_virustotal_ip(ip_address, api_key):
    """Query VirusTotal for IP reputation"""
    import requests

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']

            return {
                "source": "VirusTotal",
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "reputation": data['data']['attributes'].get('reputation', 0),
                "country": data['data']['attributes'].get('country', 'Unknown')
            }

        elif response.status_code == 429:
            # Rate limit exceeded
            return {"source": "VirusTotal", "error": "Rate limit exceeded"}

        else:
            return {"source": "VirusTotal", "error": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}
```

#### AbuseIPDB Query

```python
def query_abuseipdb(ip_address, api_key):
    """Query AbuseIPDB for IP abuse reports"""
    import requests

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json()['data']

            return {
                "source": "AbuseIPDB",
                "abuse_score": data.get('abuseConfidenceScore', 0),
                "total_reports": data.get('totalReports', 0),
                "distinct_users": data.get('numDistinctUsers', 0),
                "is_whitelisted": data.get('isWhitelisted', False),
                "usage_type": data.get('usageType', 'Unknown')
            }

        else:
            return {"source": "AbuseIPDB", "error": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}
```

### Step 4: Aggregate and Calculate Risk Score

```python
def calculate_risk_score(virustotal_data, abuseipdb_data):
    """
    Calculate overall risk score from multiple threat intel sources.

    Returns:
        dict: {
            "risk_level": "HIGH|MEDIUM|LOW",
            "risk_score": 0-100,
            "confidence": 0-100,
            "risk_factors": [...],
            "verdict": "..."
        }
    """
    risk_factors = []
    total_score = 0
    confidence = 0

    # VirusTotal scoring (0-50 points)
    if 'malicious' in virustotal_data:
        vt_malicious = virustotal_data['malicious']
        vt_suspicious = virustotal_data['suspicious']
        vt_reputation = virustotal_data.get('reputation', 0)

        if vt_malicious > 10:
            total_score += 50
            risk_factors.append(f"Flagged as malicious by {vt_malicious} vendors")
            confidence += 30
        elif vt_malicious > 5:
            total_score += 40
            risk_factors.append(f"Flagged as malicious by {vt_malicious} vendors")
            confidence += 25
        elif vt_malicious > 0:
            total_score += 25
            risk_factors.append(f"Some malicious detections ({vt_malicious})")
            confidence += 15

        if vt_suspicious > 5:
            total_score += 10
            risk_factors.append(f"{vt_suspicious} suspicious detections")
            confidence += 10

        if vt_reputation < -20:
            total_score += 15
            risk_factors.append(f"Poor reputation score: {vt_reputation}")
            confidence += 10

    # AbuseIPDB scoring (0-50 points)
    if 'abuse_score' in abuseipdb_data:
        abuse_score = abuseipdb_data['abuse_score']
        total_reports = abuseipdb_data['total_reports']

        if abuse_score >= 90:
            total_score += 50
            risk_factors.append(f"High abuse confidence: {abuse_score}%")
            confidence += 30
        elif abuse_score >= 50:
            total_score += 35
            risk_factors.append(f"Medium abuse confidence: {abuse_score}%")
            confidence += 20
        elif abuse_score >= 25:
            total_score += 20
            risk_factors.append(f"Some abuse reports: {abuse_score}%")
            confidence += 10

        if total_reports > 20:
            total_score += 10
            risk_factors.append(f"{total_reports} abuse reports")
            confidence += 10

    # Determine risk level
    if total_score >= 80:
        risk_level = "HIGH"
        verdict = "Known malicious IP - immediate action required"
    elif total_score >= 50:
        risk_level = "MEDIUM"
        verdict = "Suspicious activity detected - investigation recommended"
    elif total_score >= 25:
        risk_level = "LOW"
        verdict = "Minor risk indicators - monitor activity"
    else:
        risk_level = "CLEAN"
        verdict = "No significant threats detected"

    # Cap confidence at 100
    confidence = min(confidence, 100)

    return {
        "risk_level": risk_level,
        "risk_score": total_score,
        "confidence": confidence,
        "risk_factors": risk_factors,
        "verdict": verdict
    }
```

### Step 5: Cache Results

```python
def cache_enrichment(ioc_value, enrichment_data):
    """Cache enrichment data for future use"""
    import json
    from datetime import datetime

    cache_file = f"cache_data/{ioc_value}.json"

    enrichment_data['timestamp'] = datetime.now().isoformat()
    enrichment_data['cached_at'] = datetime.now().isoformat()

    try:
        os.makedirs('cache_data', exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(enrichment_data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Cache write error: {e}")
        return False
```

## Error Handling

### API Rate Limits

```python
def handle_rate_limit(source, retry_after=60):
    """Handle API rate limit with exponential backoff"""
    import time

    logger.warning(f"{source} rate limit exceeded. Waiting {retry_after}s")

    # Use cached data if available
    # Otherwise wait and retry
    time.sleep(retry_after)
```

### API Timeout

```python
def query_with_retry(query_func, max_retries=3):
    """Retry query with exponential backoff"""
    import time

    for attempt in range(max_retries):
        try:
            return query_func()
        except requests.Timeout:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logger.warning(f"Timeout, retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                return {"error": "Timeout after retries"}
```

## Output Format

### Standard Enrichment Response

```json
{
  "ioc_type": "ip",
  "ioc_value": "192.0.2.1",
  "risk_level": "HIGH",
  "risk_score": 85,
  "confidence": 90,
  "verdict": "Known malicious IP - immediate action required",
  "risk_factors": [
    "Flagged as malicious by 15 vendors",
    "High abuse confidence: 95%",
    "47 abuse reports"
  ],
  "sources": {
    "virustotal": {
      "malicious": 15,
      "suspicious": 3,
      "reputation": -50,
      "country": "CN"
    },
    "abuseipdb": {
      "abuse_score": 95,
      "total_reports": 47,
      "distinct_users": 15
    }
  },
  "timestamp": "2025-10-29T10:30:00Z",
  "cached": false
}
```

## Best Practices

1. **Always check cache first** - Reduce API calls and costs
2. **Validate IP addresses** - Skip private/reserved IPs
3. **Handle errors gracefully** - Don't fail entire investigation on one API error
4. **Respect rate limits** - Implement backoff and queuing
5. **Cache aggressively** - 24-hour cache for IPs, 7 days for hashes
6. **Aggregate multiple sources** - Don't rely on single source
7. **Log all queries** - Audit trail for investigations
8. **Monitor API quotas** - Alert when approaching limits

## Integration with Playbook Runner

```python
def enrich_ioc(self, ioc_type, ioc_value):
    """Enrich IOC with threat intelligence"""

    # Step 1: Validate
    if ioc_type == "ip":
        is_valid, reason = validate_ip(ioc_value)
        if not is_valid:
            return {"error": reason, "ioc_value": ioc_value}

    # Step 2: Check cache
    cached = check_cache(ioc_value)
    if cached:
        cached['cached'] = True
        return cached

    # Step 3: Query APIs
    vt_data = query_virustotal_ip(ioc_value, self.vt_api_key)
    abuse_data = query_abuseipdb(ioc_value, self.abuse_api_key)

    # Step 4: Calculate risk
    risk_assessment = calculate_risk_score(vt_data, abuse_data)

    # Step 5: Build response
    enrichment = {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        **risk_assessment,
        "sources": {
            "virustotal": vt_data,
            "abuseipdb": abuse_data
        },
        "timestamp": datetime.now().isoformat(),
        "cached": False
    }

    # Step 6: Cache result
    cache_enrichment(ioc_value, enrichment)

    return enrichment
```
