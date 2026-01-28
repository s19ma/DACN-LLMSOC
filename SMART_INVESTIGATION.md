# Smart Investigation với Threat Intelligence MCP

## Tổng quan

Smart Investigation tự động enrichment IOCs (Indicators of Compromise) từ alert bằng cách gọi các dịch vụ threat intelligence qua MCP (Model Context Protocol).

## Tính năng

### 🔍 Threat Intelligence Sources

1. **VirusTotal**

   - IP reputation checks
   - File hash malware detection
   - URL safety checks
   - Community votes and comments

2. **AbuseIPDB**

   - IP abuse confidence score
   - Historical abuse reports
   - ISP and geolocation data
   - Report timestamps

3. **Shodan** (Optional)

   - Open port scanning
   - Service identification
   - Banner information

4. **AlienVault OTX** (Optional)
   - Threat pulse subscriptions
   - IOC sharing
   - Malware samples

### 🎯 Smart Investigation Flow

```
Alert → Extract IOCs → Enrich with TI → Generate Verdict
  │         │              │                │
  │         │              │                └─> Risk Score
  │         │              │
  │         │              ├─> VirusTotal
  │         │              ├─> AbuseIPDB
  │         │              └─> Other Sources
  │         │
  │         ├─> IPs (public only)
  │         ├─> Hashes
  │         ├─> URLs
  │         └─> Domains
  │
  └─> Alert Data (JSON)
```

## Cài đặt

### 1. Thêm API Keys vào `.env`

Copy `config_example.env` thành `.env`:

```bash
cp config_example.env .env
```

Thêm API keys của bạn:

```env
# VirusTotal API Key
# Free tier: 4 requests/minute, 500 requests/day
VIRUSTOTAL_API_KEY=abc123...

# AbuseIPDB API Key
# Free tier: 1000 requests/day
ABUSEIPDB_API_KEY=def456...

# Optional
SHODAN_API_KEY=ghi789...
OTX_API_KEY=jkl012...
```

### 2. Cách lấy API Keys

#### VirusTotal

1. Đăng ký tại: https://www.virustotal.com/gui/join-us
2. Vào: https://www.virustotal.com/gui/my-apikey
3. Copy API key

#### AbuseIPDB

1. Đăng ký tại: https://www.abuseipdb.com/register
2. Vào: https://www.abuseipdb.com/account/api
3. Tạo API key mới
4. Copy key

#### Shodan (Optional)

1. Đăng ký tại: https://account.shodan.io/register
2. Vào: https://account.shodan.io/
3. Copy API Key

#### AlienVault OTX (Optional)

1. Đăng ký tại: https://otx.alienvault.com/
2. Vào Settings → API Integration
3. Copy OTX Key

## Sử dụng

### API Endpoint

```http
POST /api/smart-investigation
Content-Type: application/json

{
  "alert_id": "ALERT-001"
}
```

### Response Format

```json
{
  "status": "success",
  "alert_id": "ALERT-001",
  "investigation": {
    "alert_id": "ALERT-001",
    "timestamp": "2025-10-29T12:00:00",
    "iocs_found": [{ "type": "ip", "value": "206.123.145.234" }],
    "enrichment_results": {
      "ip_206.123.145.234": {
        "ioc_type": "ip",
        "ioc_value": "206.123.145.234",
        "sources": {
          "virustotal": {
            "status": "success",
            "malicious": 5,
            "suspicious": 2,
            "harmless": 75,
            "country": "US",
            "summary": "⚠️ MALICIOUS: 5/82 vendors flagged as malicious"
          },
          "abuseipdb": {
            "status": "success",
            "abuse_confidence_score": 85,
            "total_reports": 42,
            "summary": "⚠️ HIGH RISK: Confidence 85%, 42 abuse reports"
          }
        },
        "verdict": {
          "risk_level": "HIGH",
          "risk_color": "🔴",
          "confidence": 85.0,
          "malicious_indicators": 5,
          "suspicious_indicators": 2,
          "summary": "🔴 Risk Level: HIGH | Malicious: 5 | Suspicious: 2"
        }
      }
    }
  },
  "iocs_analyzed": 1,
  "timestamp": "2025-10-29T12:00:01"
}
```

### Python Code

```python
from agents.playbook_runner import PlaybookRunnerAgent

# Initialize
runner = PlaybookRunnerAgent()

# Run smart investigation
results = runner.smart_investigation(alert_data)

# Access results
verdict = results['enrichment_results']['ip_xxx.xxx.xxx.xxx']['verdict']
print(f"Risk Level: {verdict['risk_level']}")
print(f"Summary: {verdict['summary']}")
```

### Direct MCP Call

```python
from agents.threat_intel_mcp import get_threat_intel_mcp

# Get singleton
mcp = get_threat_intel_mcp()

# Check single IP
result = mcp.check_ip_virustotal('8.8.8.8')
print(result['summary'])

# Enrich IOC (combined sources)
enrichment = mcp.enrich_ioc('ip', '206.123.145.234')
print(enrichment['verdict']['summary'])
```

## Testing

### Test Threat Intel MCP

```bash
python test_threat_intel.py
```

Output:

```
======================================================================
Testing Threat Intelligence MCP Integration
======================================================================

📍 Testing: 206.123.145.234 (Test IP 1)
----------------------------------------------------------------------

🔍 VirusTotal Check:
  ✓ Status: success
  ✓ Malicious: 5
  ✓ Suspicious: 2
  ✓ Summary: ⚠️ MALICIOUS: 5/82 vendors flagged as malicious

🔍 AbuseIPDB Check:
  ✓ Status: success
  ✓ Abuse Score: 85%
  ✓ Reports: 42
  ✓ Summary: ⚠️ HIGH RISK: Confidence 85%, 42 abuse reports
```

### Test via API

```bash
curl -X POST http://localhost:5000/api/smart-investigation \
  -H "Content-Type: application/json" \
  -d '{"alert_id": "ALERT-001"}'
```

## Tích hợp vào Playbook Runner

Smart Investigation tự động được gọi trong playbook steps:

```python
# Trong execute_step, khi detect IOC investigation:
if "ioc" in step['detail_actions'].lower():
    # Tự động enrich IOCs
    enrichment = self.smart_investigation(alert_data)
    # Thêm vào execution context
    context += f"\nThreat Intelligence:\n{json.dumps(enrichment, indent=2)}"
```

## Verdict Scoring

### Risk Levels

| Level         | Criteria                             |
| ------------- | ------------------------------------ |
| 🔴 **HIGH**   | Malicious > 0 OR Abuse Score >= 75%  |
| 🟡 **MEDIUM** | Suspicious > 0 OR Abuse Score >= 25% |
| 🟢 **LOW**    | No malicious/suspicious indicators   |

### Confidence Score

Trung bình từ tất cả sources:

- VirusTotal: % detections / total scans
- AbuseIPDB: Abuse confidence score
- Shodan: Risk scoring (if available)

## Rate Limits

### Free Tier Limits

| Service    | Requests/Min | Requests/Day |
| ---------- | ------------ | ------------ |
| VirusTotal | 4            | 500          |
| AbuseIPDB  | -            | 1000         |
| Shodan     | 1            | 100          |
| OTX        | 10           | 10000        |

**Tip**: Kết quả được cache trong playbook runner để tránh duplicate requests.

## Troubleshooting

### API Key không hoạt động

```bash
# Check .env file
cat .env | grep API_KEY

# Test từng service
python test_threat_intel.py
```

### Rate limit exceeded

```json
{
  "status": "error",
  "message": "VirusTotal API error: 429"
}
```

**Giải pháp**: Đợi 1 phút hoặc upgrade plan.

### Kết quả rỗng

Kiểm tra:

1. ✓ API keys đã đúng?
2. ✓ IOC là public IP? (Private IPs bị skip)
3. ✓ Internet connection OK?

## Roadmap

- [ ] Cache threat intel results (TTL 24h)
- [ ] Batch IOC lookups (giảm API calls)
- [ ] UI hiển thị enrichment trong alert detail
- [ ] Export enrichment reports (PDF/JSON)
- [ ] Webhook notifications cho high-risk IOCs
- [ ] Custom scoring rules
- [ ] Integration với MISP, STIX/TAXII

## Tài liệu tham khảo

- [VirusTotal API v3](https://developers.virustotal.com/reference/overview)
- [AbuseIPDB API v2](https://docs.abuseipdb.com/)
- [Shodan API](https://developer.shodan.io/api)
- [AlienVault OTX API](https://otx.alienvault.com/assets/static/external_api.html)
