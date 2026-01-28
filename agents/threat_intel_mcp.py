"""
Threat Intelligence MCP Integration
====================================

This module provides integration with threat intelligence services via MCP.
Supports VirusTotal, AbuseIPDB, Shodan, and other threat intel platforms.
"""

import os
import logging
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env if present; fall back to config_example.env
load_dotenv(override=False)
try:
    _here = os.path.dirname(os.path.abspath(__file__))
    _project_root = os.path.abspath(os.path.join(_here, os.pardir))
    _example_env = os.path.join(_project_root, "config_example.env")
    if os.path.exists(_example_env):
        load_dotenv(dotenv_path=_example_env, override=False)
except Exception as _e:
    # Non-fatal: continue without raising
    pass

logger = logging.getLogger(__name__)


class ThreatIntelMCP:
    """MCP client for threat intelligence services"""
    
    def __init__(self):
        """Initialize MCP client with API keys from environment"""
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        # Support both ABUSEIPDB_API_KEY and legacy ABUSEIP_API_KEY names
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY') or os.getenv('ABUSEIP_API_KEY')
        self.shodan_key = os.getenv('SHODAN_API_KEY')
        self.otx_key = os.getenv('OTX_API_KEY')
        
        # API endpoints
        self.virustotal_base = "https://www.virustotal.com/api/v3"
        self.abuseipdb_base = "https://api.abuseipdb.com/api/v2"
        self.shodan_base = "https://api.shodan.io"
        self.otx_base = "https://otx.alienvault.com/api/v1"
        
        logger.info("🔍 Threat Intel MCP initialized")
    
    def check_ip_virustotal(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation on VirusTotal
        
        Args:
            ip: IP address to check
            
        Returns:
            Dict with reputation data and analysis results
        """
        if not self.virustotal_key or self.virustotal_key == 'your_virustotal_api_key_here':
            return {
                "status": "error",
                "message": "VirusTotal API key not configured",
                "ip": ip
            }
        
        try:
            url = f"{self.virustotal_base}/ip_addresses/{ip}"
            headers = {
                "x-apikey": self.virustotal_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis = attributes.get('last_analysis_stats', {})
                
                return {
                    "status": "success",
                    "ip": ip,
                    "source": "VirusTotal",
                    "reputation_score": attributes.get('reputation', 0),
                    "malicious": last_analysis.get('malicious', 0),
                    "suspicious": last_analysis.get('suspicious', 0),
                    "harmless": last_analysis.get('harmless', 0),
                    "undetected": last_analysis.get('undetected', 0),
                    "country": attributes.get('country', 'Unknown'),
                    "as_owner": attributes.get('as_owner', 'Unknown'),
                    "last_seen": attributes.get('last_analysis_date', 'Unknown'),
                    "summary": self._generate_vt_summary(last_analysis)
                }
            else:
                return {
                    "status": "error",
                    "ip": ip,
                    "message": f"VirusTotal API error: {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"VirusTotal IP check error: {e}")
            return {
                "status": "error",
                "ip": ip,
                "message": str(e)
            }
    
    def check_ip_abuseipdb(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Check IP reputation on AbuseIPDB
        
        Args:
            ip: IP address to check
            max_age_days: Max age of reports to include (default 90 days)
            
        Returns:
            Dict with abuse reports and confidence score
        """
        if (not self.abuseipdb_key 
            or self.abuseipdb_key in ('your_abuseipdb_api_key_here', 'your_abuseip_api_key_here')):
            return {
                "status": "error",
                "message": "AbuseIPDB API key not configured. Set ABUSEIPDB_API_KEY (preferred) or ABUSEIP_API_KEY in your .env",
                "ip": ip
            }
        
        try:
            url = f"{self.abuseipdb_base}/check"
            headers = {
                "Key": self.abuseipdb_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": max_age_days,
                "verbose": True
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                return {
                    "status": "success",
                    "ip": ip,
                    "source": "AbuseIPDB",
                    "abuse_confidence_score": data.get('abuseConfidenceScore', 0),
                    "country": data.get('countryCode', 'Unknown'),
                    "usage_type": data.get('usageType', 'Unknown'),
                    "isp": data.get('isp', 'Unknown'),
                    "domain": data.get('domain', 'Unknown'),
                    "total_reports": data.get('totalReports', 0),
                    "num_distinct_users": data.get('numDistinctUsers', 0),
                    "last_reported": data.get('lastReportedAt', 'Never'),
                    "is_whitelisted": data.get('isWhitelisted', False),
                    "is_tor": data.get('isTor', False),
                    "summary": self._generate_abuseip_summary(data)
                }
            else:
                return {
                    "status": "error",
                    "ip": ip,
                    "message": f"AbuseIPDB API error: {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"AbuseIPDB check error: {e}")
            return {
                "status": "error",
                "ip": ip,
                "message": str(e)
            }
    
    def check_hash_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash on VirusTotal
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            Dict with malware detection results
        """
        if not self.virustotal_key or self.virustotal_key == 'your_virustotal_api_key_here':
            return {
                "status": "error",
                "message": "VirusTotal API key not configured",
                "hash": file_hash
            }
        
        try:
            url = f"{self.virustotal_base}/files/{file_hash}"
            headers = {
                "x-apikey": self.virustotal_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis = attributes.get('last_analysis_stats', {})
                
                return {
                    "status": "success",
                    "hash": file_hash,
                    "source": "VirusTotal",
                    "malicious": last_analysis.get('malicious', 0),
                    "suspicious": last_analysis.get('suspicious', 0),
                    "harmless": last_analysis.get('harmless', 0),
                    "undetected": last_analysis.get('undetected', 0),
                    "file_type": attributes.get('type_description', 'Unknown'),
                    "file_size": attributes.get('size', 0),
                    "names": attributes.get('names', [])[:5],  # First 5 names
                    "tags": attributes.get('tags', [])[:10],  # First 10 tags
                    "last_seen": attributes.get('last_analysis_date', 'Unknown'),
                    "summary": self._generate_hash_summary(last_analysis, attributes)
                }
            elif response.status_code == 404:
                return {
                    "status": "success",
                    "hash": file_hash,
                    "source": "VirusTotal",
                    "message": "Hash not found in VirusTotal database",
                    "malicious": 0
                }
            else:
                return {
                    "status": "error",
                    "hash": file_hash,
                    "message": f"VirusTotal API error: {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"VirusTotal hash check error: {e}")
            return {
                "status": "error",
                "hash": file_hash,
                "message": str(e)
            }
    
    def check_url_virustotal(self, url: str) -> Dict[str, Any]:
        """
        Check URL reputation on VirusTotal
        
        Args:
            url: URL to check
            
        Returns:
            Dict with URL analysis results
        """
        if not self.virustotal_key or self.virustotal_key == 'your_virustotal_api_key_here':
            return {
                "status": "error",
                "message": "VirusTotal API key not configured",
                "url": url
            }
        
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            api_url = f"{self.virustotal_base}/urls/{url_id}"
            headers = {
                "x-apikey": self.virustotal_key
            }
            
            response = requests.get(api_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis = attributes.get('last_analysis_stats', {})
                
                return {
                    "status": "success",
                    "url": url,
                    "source": "VirusTotal",
                    "malicious": last_analysis.get('malicious', 0),
                    "suspicious": last_analysis.get('suspicious', 0),
                    "harmless": last_analysis.get('harmless', 0),
                    "undetected": last_analysis.get('undetected', 0),
                    "categories": attributes.get('categories', {}),
                    "last_seen": attributes.get('last_analysis_date', 'Unknown'),
                    "summary": self._generate_url_summary(last_analysis, url)
                }
            else:
                return {
                    "status": "error",
                    "url": url,
                    "message": f"VirusTotal API error: {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"VirusTotal URL check error: {e}")
            return {
                "status": "error",
                "url": url,
                "message": str(e)
            }
    
    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """
        Enrich IOC with threat intelligence from multiple sources
        
        Args:
            ioc_type: Type of IOC (ip, hash, url, domain)
            ioc_value: The IOC value to enrich
            
        Returns:
            Dict with enriched intelligence from all available sources
        """
        results = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "timestamp": datetime.now().isoformat(),
            "sources": {}
        }
        
        if ioc_type == "ip":
            # Check VirusTotal
            vt_result = self.check_ip_virustotal(ioc_value)
            if vt_result.get('status') == 'success':
                results['sources']['virustotal'] = vt_result
            
            # Check AbuseIPDB
            abuse_result = self.check_ip_abuseipdb(ioc_value)
            if abuse_result.get('status') == 'success':
                results['sources']['abuseipdb'] = abuse_result
        
        elif ioc_type == "hash":
            # Check VirusTotal
            vt_result = self.check_hash_virustotal(ioc_value)
            if vt_result.get('status') == 'success':
                results['sources']['virustotal'] = vt_result
        
        elif ioc_type == "url":
            # Check VirusTotal
            vt_result = self.check_url_virustotal(ioc_value)
            if vt_result.get('status') == 'success':
                results['sources']['virustotal'] = vt_result
        
        # Generate overall verdict
        results['verdict'] = self._generate_verdict(results['sources'])
        
        return results
    
    def _generate_vt_summary(self, analysis: Dict) -> str:
        """Generate human-readable summary from VirusTotal analysis"""
        malicious = analysis.get('malicious', 0)
        suspicious = analysis.get('suspicious', 0)
        total = sum(analysis.values())
        
        if malicious > 0:
            return f"⚠️ MALICIOUS: {malicious}/{total} vendors flagged as malicious"
        elif suspicious > 0:
            return f"⚠️ SUSPICIOUS: {suspicious}/{total} vendors flagged as suspicious"
        else:
            return f"✅ CLEAN: No malicious detections from {total} vendors"
    
    def _generate_abuseip_summary(self, data: Dict) -> str:
        """Generate human-readable summary from AbuseIPDB data"""
        score = data.get('abuseConfidenceScore', 0)
        reports = data.get('totalReports', 0)
        
        if score >= 75:
            return f"⚠️ HIGH RISK: Confidence {score}%, {reports} abuse reports"
        elif score >= 25:
            return f"⚠️ MEDIUM RISK: Confidence {score}%, {reports} abuse reports"
        elif reports > 0:
            return f"ℹ️ LOW RISK: Confidence {score}%, {reports} abuse reports"
        else:
            return "✅ CLEAN: No abuse reports found"
    
    def _generate_hash_summary(self, analysis: Dict, attributes: Dict) -> str:
        """Generate human-readable summary from hash analysis"""
        malicious = analysis.get('malicious', 0)
        file_type = attributes.get('type_description', 'Unknown')
        
        if malicious > 0:
            return f"⚠️ MALWARE DETECTED: {malicious} vendors identified as malicious ({file_type})"
        else:
            return f"✅ CLEAN: No malware detected ({file_type})"
    
    def _generate_url_summary(self, analysis: Dict, url: str) -> str:
        """Generate human-readable summary from URL analysis"""
        malicious = analysis.get('malicious', 0)
        suspicious = analysis.get('suspicious', 0)
        
        if malicious > 0:
            return f"⚠️ MALICIOUS URL: {malicious} vendors flagged as dangerous"
        elif suspicious > 0:
            return f"⚠️ SUSPICIOUS URL: {suspicious} vendors flagged as suspicious"
        else:
            return "✅ SAFE: No malicious detections"
    
    def _generate_verdict(self, sources: Dict) -> Dict[str, Any]:
        """
        Generate overall verdict from multiple threat intel sources
        
        Returns:
            Dict with risk_level, confidence, and summary
        """
        total_malicious = 0
        total_suspicious = 0
        confidence_scores = []
        
        for source_name, source_data in sources.items():
            if source_name == 'virustotal':
                total_malicious += source_data.get('malicious', 0)
                total_suspicious += source_data.get('suspicious', 0)
            elif source_name == 'abuseipdb':
                score = source_data.get('abuse_confidence_score', 0)
                confidence_scores.append(score)
                if score >= 75:
                    total_malicious += 1
                elif score >= 25:
                    total_suspicious += 1
        
        # Determine risk level
        if total_malicious > 0:
            risk_level = "HIGH"
            risk_color = "🔴"
        elif total_suspicious > 0:
            risk_level = "MEDIUM"
            risk_color = "🟡"
        else:
            risk_level = "LOW"
            risk_color = "🟢"
        
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        return {
            "risk_level": risk_level,
            "risk_color": risk_color,
            "confidence": round(avg_confidence, 2),
            "malicious_indicators": total_malicious,
            "suspicious_indicators": total_suspicious,
            "summary": f"{risk_color} Risk Level: {risk_level} | Malicious: {total_malicious} | Suspicious: {total_suspicious}"
        }


# Singleton instance
_threat_intel_mcp = None

def get_threat_intel_mcp() -> ThreatIntelMCP:
    """Get or create singleton ThreatIntelMCP instance"""
    global _threat_intel_mcp
    if _threat_intel_mcp is None:
        _threat_intel_mcp = ThreatIntelMCP()
    return _threat_intel_mcp
