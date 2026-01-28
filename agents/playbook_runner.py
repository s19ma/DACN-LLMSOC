"""
SOC AI Assistant v2 - Playbook Runner Agent
===========================================

The Playbook Runner Agent is responsible for executing security investigation playbooks
step-by-step. It follows predefined investigation procedures and makes API calls as needed
to gather information and perform security actions.

Key Responsibilities:
1. Execute investigation playbooks provided by the Supervisor Agent
2. Parse playbook steps and execute them sequentially
3. Make API calls when required by playbook steps (GET, POST, etc.)
4. Request SPL queries from Supervisor when investigation steps require Splunk searches
5. Provide detailed execution results and findings for each step

Architecture:
- No RAG system (uses system prompts with playbook context)
- Single tool: API call capability for external system interactions
- Integrates with Supervisor for SPL query requests
- Maintains execution state and step-by-step results
"""

import os
import json
import csv
import requests
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timezone
from urllib.parse import urljoin
from dotenv import load_dotenv

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field
try:
    from langchain_ollama import ChatOllama
except ImportError:
    ChatOllama = None

# Import RAG utilities
try:
    from agents.rag_utils import get_rag_manager
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class APICallInput(BaseModel):
    """Input schema for API call tool"""
    method: str = Field(description="HTTP method (GET, POST, PUT, DELETE)")
    url: str = Field(description="Target URL for the API call")
    headers: Optional[Dict[str, str]] = Field(default=None, description="HTTP headers")
    data: Optional[Dict[str, Any]] = Field(default=None, description="Request body data")
    params: Optional[Dict[str, str]] = Field(default=None, description="URL parameters")

class APICallTool(BaseTool):
    """
    Tool for making HTTP API calls during playbook execution.
    
    This tool enables the Playbook Runner Agent to interact with external systems
    such as Splunk, SIEM platforms, threat intelligence APIs, and other security tools.
    """
    name: str = "api_call"
    description: str = "Make HTTP API calls to external systems and services"
    args_schema: type = APICallInput
    
    def _run(self, method: str, url: str, headers: Optional[Dict] = None, 
            data: Optional[Dict] = None, params: Optional[Dict] = None) -> str:
        """
        Execute HTTP API call with specified parameters.
        
        Args:
            method: HTTP method to use
            url: Target URL
            headers: Optional HTTP headers
            data: Optional request body data
            params: Optional URL parameters
            
        Returns:
            JSON string with API response or error information
        """
        try:
            logger.info(f"🔧 API CALL TOOL: Making {method} request to {url}")
            
            # Prepare request parameters
            request_kwargs = {
                'method': method.upper(),
                'url': url,
                'timeout': int(os.getenv('API_TIMEOUT', 30))
            }
            
            if headers:
                request_kwargs['headers'] = headers
            if data:
                request_kwargs['json'] = data
            if params:
                request_kwargs['params'] = params
            
            # Make the API call
            response = requests.request(**request_kwargs)
            
            # Prepare result
            result = {
                'status_code': response.status_code,
                'success': response.status_code < 400,
                'headers': dict(response.headers),
                'url': response.url,
                'method': method.upper()
            }
            
            # Add response content
            try:
                result['data'] = response.json()
            except ValueError:
                result['data'] = response.text
            
            logger.info(f"🔧 API CALL TOOL: Request completed with status {response.status_code}")
            return json.dumps(result, indent=2)
            
        except Exception as e:
            error_result = {
                'success': False,
                'error': str(e),
                'method': method.upper(),
                'url': url
            }
            logger.error(f"🔧 API CALL TOOL: Request failed - {str(e)}")
            return json.dumps(error_result, indent=2)

class PlaybookRunnerAgent:
    """
    Agent responsible for executing security investigation playbooks step-by-step.
    
    This agent takes playbooks from the Supervisor, executes each step systematically,
    and coordinates with other agents when specialized tasks are required.
    """
    
    def __init__(self):
        """
        Initialize the Playbook Runner Agent with tools and configuration.
        """
        # Optimized LLM for faster playbook execution
        self.llm = ChatOllama(
            model="qwen2.5:3b", 
            temperature=0.1,
            num_ctx=2048,  # Reduced for speed
            timeout=30   # Timeout for long operations
        )

        # Initialize RAG Manager
        self.rag_manager = None
        self.rag_enabled = False
        if RAG_AVAILABLE:
            try:
                self.rag_manager = get_rag_manager()
                self.rag_enabled = self.rag_manager.enabled
                if self.rag_enabled:
                    logger.info("📚 RAG system enabled for Playbook Runner")
            except Exception as e:
                logger.warning(f"RAG initialization failed: {e}")
        
        # Initialize tools
        self.api_tool = APICallTool()
        
        # Initialize threat intel MCP
        try:
            from agents.threat_intel_mcp import get_threat_intel_mcp
            self.threat_intel = get_threat_intel_mcp()
        except Exception as e:
            logger.warning(f"Threat Intel MCP not available: {e}")
            self.threat_intel = None
        
        # API configuration
        self.api_base_url = os.getenv("API_BASE_URL", "http://192.168.7.110:8089")
        self.splunk_host = os.getenv("SPLUNK_HOST", "192.168.7.110")
        self.splunk_port = os.getenv("SPLUNK_PORT", "8089")
        
        logger.info("📋 Playbook Runner Agent initialized successfully")
    
    
    def _get_system_prompt(self) -> str:
        """
        Generate the system prompt for the Playbook Runner Agent.
        
        Returns:
            System prompt string with playbook execution guidelines
        """
        return f"""You are the Playbook Runner Agent, a specialized security analyst focused on executing investigation playbooks systematically and thoroughly.

**Your Role:**
Execute security investigation playbooks step-by-step, following standard operating procedures to ensure comprehensive and consistent incident response.

**Execution Capabilities:**
1. **Playbook Parsing**: Read and understand CSV-based investigation playbooks
2. **Step Execution**: Execute each playbook step systematically in sequence
3. **API Integration**: Make HTTP calls to external systems when required
4. **SPL Coordination**: Request Splunk queries from Supervisor when needed
5. **Result Documentation**: Record findings and outcomes for each step

**Available Tools:**
- **API Call Tool**: Make HTTP requests (GET, POST, PUT, DELETE) to external systems
  - Splunk API endpoints: {self.api_base_url}
  - Authentication and session management
  - Data retrieval and submission

**API Endpoints Available:**
- Splunk Search API: {self.api_base_url}/services/search/jobs
- Splunk Results API: {self.api_base_url}/services/search/jobs/{{sid}}/results
- Custom SOC APIs: Various endpoints for SIEM, threat intel, etc.

**Playbook Execution Process:**
1. **Parse Playbook**: Load CSV playbook and understand all steps
2. **Sequential Execution**: Execute steps in order, ensuring prerequisites are met
3. **Dynamic Adaptation**: Request additional resources (SPL queries) when needed
4. **API Calls**: Use API tool when steps require external system interaction
5. **Documentation**: Record detailed results for each step
6. **Validation**: Ensure each step completion criteria are met

**Step Types You Handle:**
- **Information Gathering**: Collect data from various security tools
- **Analysis Steps**: Examine logs, alerts, and security indicators
- **Correlation**: Cross-reference data across multiple sources
- **Threat Hunting**: Active searching for indicators of compromise
- **Containment**: Execute containment procedures when required
- **Documentation**: Record findings and create reports

**When to Request SPL Queries:**
- Step requires Splunk log analysis
- Need to search specific indexes for indicators
- Correlation across multiple data sources required
- Custom threat hunting queries needed

**API Call Guidelines:**
- Always authenticate properly with target systems
- Handle errors gracefully and retry when appropriate
- Log all API interactions for audit purposes
- Respect rate limits and system constraints
- Validate response data before proceeding

**Communication Style:**
- Always announce: "📋 PLAYBOOK RUNNER AGENT: Executing step [X] - [step_name]..."
- Provide clear status updates for each step
- Document findings with security context
- Highlight critical discoveries and anomalies
- Maintain professional incident response tone

**Error Handling:**
- If a step fails, document the failure and continue if possible
- Request assistance from Supervisor for complex decisions
- Provide clear error descriptions and suggested remediation
- Maintain execution state even when errors occur

**Output Format:**
For each step execution, provide:
1. **Step Summary**: What was executed
2. **Actions Taken**: Specific actions and API calls made
3. **Findings**: Results and discoveries
4. **Status**: Success/Failure/Partial completion
5. **Next Steps**: Recommendations for continuation
6. **Evidence**: Any artifacts or data collected

Execute playbooks with the precision and thoroughness expected in professional security operations."""

    def load_playbook(self, playbook_name: str) -> List[Dict[str, Any]]:
        """
        Load investigation playbook from CSV file.
        
        Args:
            playbook_name: Name of the playbook CSV file
            
        Returns:
            List of playbook steps with metadata
        """
        logger.info(f"📋 PLAYBOOK RUNNER AGENT: Loading playbook '{playbook_name}'...")
        
        steps = []
        playbook_path = f"playbook/{playbook_name}"
        
        if not playbook_name.endswith('.csv'):
            playbook_path += '.csv'
        
        try:
            if not os.path.exists(playbook_path):
                logger.warning(f"Playbook file not found: {playbook_path}")
                return []
            
            with open(playbook_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader, 1):
                    step = {
                        'step_number': i,
                        'phase': row.get('Phase', ''),
                        'phase_description': row.get('Phase description', ''),
                        'detail_actions': row.get('Detail actions', ''),
                        'requires_api': self._detect_api_requirement(row.get('Detail actions', '')),
                        'requires_spl': self._detect_spl_requirement(row.get('Detail actions', '')),
                        'status': 'pending',
                        'results': None,
                        'timestamp': None
                    }
                    steps.append(step)
            
            logger.info(f"📋 PLAYBOOK RUNNER AGENT: Loaded {len(steps)} steps from playbook")
            return steps
            
        except Exception as e:
            logger.error(f"Error loading playbook: {e}")
            return []
    
    def _detect_api_requirement(self, actions: str) -> bool:
        """
        Detect if a playbook step requires API calls.
        
        Args:
            actions: Step actions description
            
        Returns:
            True if API calls are likely required
        """
        api_keywords = [
            'query', 'search', 'retrieve', 'fetch', 'call', 'request',
            'splunk', 'api', 'endpoint', 'service', 'database'
        ]
        return any(keyword in actions.lower() for keyword in api_keywords)
    
    def _detect_spl_requirement(self, actions: str) -> bool:
        """
        Detect if a playbook step requires SPL queries.
        
        Args:
            actions: Step actions description
            
        Returns:
            True if SPL queries are likely required
        """
        spl_keywords = [
            'splunk', 'search', 'logs', 'index', 'events', 'correlation',
            'hunt', 'analyze', 'investigate', 'query'
        ]
        return any(keyword in actions.lower() for keyword in spl_keywords)
    
    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """
        Enrich IOC with threat intelligence from multiple sources and RAG context.
        
        Args:
            ioc_type: Type of IOC (ip, hash, url, domain)
            ioc_value: The IOC value to enrich
            
        Returns:
            Dict with enriched intelligence
        """
        if not self.threat_intel:
            return {
                "error": "Threat Intel MCP not configured",
                "ioc_type": ioc_type,
                "ioc_value": ioc_value
            }
        
        logger.info(f"🔍 Enriching IOC: {ioc_type} = {ioc_value}")
        
        # Get RAG context for enrichment procedures
        rag_context_parts: List[str] = []
        if self.rag_enabled and self.rag_manager:
            try:
                query = f"How to enrich {ioc_type} IOC threat intelligence best practices"
                playbook_results = self.rag_manager.search(
                    query=query,
                    collection_name="playbook_knowledge",
                    k=2
                )
                if playbook_results:
                    rag_context_parts.append("\n".join([r['content'][:300] for r in playbook_results]))

                alert_research = self.rag_manager.search(
                    query=query,
                    collection_name="alert_research",
                    k=1
                )
                if alert_research:
                    rag_context_parts.append("\n".join([r['content'][:300] for r in alert_research]))

                if rag_context_parts:
                    logger.debug("Retrieved RAG context for IOC enrichment")
            except Exception as e:
                logger.warning(f"RAG search failed: {e}")
        
        try:
            result = self.threat_intel.enrich_ioc(ioc_type, ioc_value)
            if rag_context_parts:
                result['rag_context_used'] = True
                result['rag_context'] = "\n\n".join(rag_context_parts)
            return result
        except Exception as e:
            logger.error(f"IOC enrichment failed: {e}")
            return {"error": str(e), "ioc_type": ioc_type, "ioc_value": ioc_value}
    
    def smart_investigation(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform smart investigation by automatically enriching IOCs from alert.
        
        Args:
            alert_data: Alert data containing potential IOCs
            
        Returns:
            Dict with enriched threat intelligence for all found IOCs
        """
        logger.info("🔍 Starting smart investigation...")
        
        investigation_results = {
            "alert_id": alert_data.get('id', 'Unknown'),
            "timestamp": datetime.now().isoformat(),
            "iocs_found": [],
            "enrichment_results": {}
        }
        
        # Extract IOCs from alert
        import re
        import json as j
        
        # Extract IPs (support common field variants)
        ips = set()
        # Common variants for source IP
        for key in ('src_ip', 'source_ip'):
            val = alert_data.get(key)
            if val:
                ips.add(val)
        # Common variants for destination IP
        for key in ('dest_ip', 'destination_ip', 'dst_ip'):
            val = alert_data.get(key)
            if val:
                ips.add(val)
        
        # Parse result JSON for more IPs
        result_str = alert_data.get('result', '')
        if result_str:
            try:
                result_data = j.loads(result_str) if isinstance(result_str, str) else result_str

                # 1) Extract from top-level keys in parsed result JSON
                for key in ('src_ip', 'source_ip', 'dest_ip', 'destination_ip', 'dst_ip'):
                    if isinstance(result_data, dict) and result_data.get(key):
                        ips.add(result_data.get(key))

                # 2) Extract from logs[] entries if present
                logs = result_data.get('logs', []) if isinstance(result_data, dict) else []
                for log in logs:
                    if 'src_ip' in log:
                        ips.add(log['src_ip'])
                    if 'source_ip' in log:
                        ips.add(log['source_ip'])
                    if 'dest_ip' in log:
                        ips.add(log['dest_ip'])
                    if 'destination_ip' in log:
                        ips.add(log['destination_ip'])
            except Exception as _e:
                # If result is not valid JSON, ignore gracefully
                pass
        
        # Remove private IPs
        public_ips = [ip for ip in ips if ip and not self._is_private_ip(ip)]
        
        # Enrich each public IP
        for ip in public_ips:
            investigation_results['iocs_found'].append({'type': 'ip', 'value': ip})
            enrichment = self.enrich_ioc('ip', ip)
            investigation_results['enrichment_results'][f'ip_{ip}'] = enrichment
        
        logger.info(f"✅ Smart investigation complete: Found {len(public_ips)} public IPs")
        return investigation_results
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return False
    
    def execute_step(self, step: Dict[str, Any], alert_data: Optional[Dict] = None, 
                    spl_queries: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute a single playbook step with full context and tools.
        
        Args:
            step: Playbook step to execute
            alert_data: Optional alert context
            spl_queries: Optional pre-generated SPL queries
            
        Returns:
            Dictionary with step execution results
        """
        step_num = step['step_number']
        phase = step['phase']
        actions = step['detail_actions']
        
        logger.info(f"📋 PLAYBOOK RUNNER AGENT: Executing step {step_num} - {phase}")
        
        # Prepare execution context
        execution_context = f"""
        **Step {step_num}: {phase}**
        Description: {step['phase_description']}
        Required Actions: {actions}
        
        **Alert Context:**
        {json.dumps(alert_data, indent=2) if alert_data else "No alert context provided"}
        
        **Available SPL Queries:**
        {json.dumps(spl_queries, indent=2) if spl_queries else "No SPL queries provided"}
        
        **Available Tools:**
        - API Call Tool: Use this to make HTTP requests to external systems
        
        **Your Task:**
        Execute this playbook step thoroughly. If the step requires:
        1. API calls - Use the api_call tool with appropriate parameters
        2. SPL queries - Use provided queries or request new ones through your response
        3. Analysis - Provide detailed security analysis based on available data
        4. Documentation - Record all findings and evidence
        
        Provide a comprehensive execution report including:
        - Actions taken
        - API calls made (if any)
        - Findings and results
        - Evidence collected
        - Status (success/failure/partial)
        - Recommendations for next steps
        
        RULE:
        - Provide a clear and structured response, with bulleted lists where appropriate
        - Seperate the output into sections for clarity, provide a comprehensive execution report including as describe above
        """
        
        try:
            messages = [
                SystemMessage(content=self._get_system_prompt()),
                HumanMessage(content=execution_context)
            ]
            
            # Execute step with LLM
            response = self.llm.invoke(messages)
            execution_result = response.content
            
            # Check if API calls are needed and execute them
            api_results = []
            if step['requires_api']:
                api_results = self._handle_api_requirements(execution_result, alert_data)
            
            # Prepare step results
            step_results = {
                'step_number': step_num,
                'phase': phase,
                'status': 'completed',
                'execution_details': execution_result,
                'api_calls': api_results,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'findings': self._extract_findings(execution_result),
                'recommendations': self._extract_recommendations(execution_result),
                'evidence': self._extract_evidence(execution_result)
            }
            
            logger.info(f"📋 PLAYBOOK RUNNER AGENT: Step {step_num} completed successfully")
            # logger.info(f"📋 PLAYBOOK RUNNER AGENT: Step {step_num} result: {step_results}")
            return step_results
            
        except Exception as e:
            logger.error(f"Error executing step {step_num}: {e}")
            return {
                'step_number': step_num,
                'phase': phase,
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _handle_api_requirements(self, execution_result: str, alert_data: Optional[Dict]) -> List[Dict]:
        """
        Handle API call requirements detected in step execution.
        
        Args:
            execution_result: LLM execution result that may contain API requirements
            alert_data: Alert context for API calls
            
        Returns:
            List of API call results
        """
        api_results = []
        
        if not alert_data:
            return api_results
        
        # Check if this is a threat intelligence gathering step
        if any(keyword in execution_result.lower() for keyword in ['threat intelligence', 'mcp server', 'virustotal', 'abuseip', 'shodan', 'otx']):
            logger.info("🔧 MCP SERVERS: Detected threat intelligence requirements, calling MCP servers")
            mcp_results = self._gather_threat_intelligence(alert_data)
            api_results.extend(mcp_results)
        
        # Check if Splunk search is needed
        if any(keyword in execution_result.lower() for keyword in ['splunk', 'search', 'logs', 'index']):
            src_ip = alert_data.get('src_ip', alert_data.get('source_ip', ''))
            if src_ip:
                splunk_result = self._make_splunk_search(
                    f"search index=* src_ip=\"{src_ip}\" earliest=-1h | head 100"
                )
                api_results.append(splunk_result)
        
        # Additional API calls based on alert data
        if 'src_ip' in alert_data or 'source_ip' in alert_data:
            src_ip = alert_data.get('src_ip', alert_data.get('source_ip', ''))
            if src_ip and src_ip != 'N/A':
                # Network analysis
                network_result = self._make_splunk_search(
                    f"search index=network src_ip=\"{src_ip}\" earliest=-24h | stats count by dest_ip, dest_port | sort -count"
                )
                api_results.append(network_result)
        
        logger.info(f"🔧 API CALLS: Completed {len(api_results)} API calls")
        return api_results
    
    def _make_splunk_search(self, spl_query: str) -> Dict[str, Any]:
        """
        Execute a Splunk search using the API tool.
        
        Args:
            spl_query: SPL query to execute
            
        Returns:
            Dictionary with search results
        """
        try:
            # Create search job
            search_url = f"{self.api_base_url}/services/search/jobs"
            search_data = {
                'search': spl_query,
                'output_mode': 'json'
            }
            
            # Use API tool to make the request
            result_json = self.api_tool._run(
                method="POST",
                url=search_url,
                data=search_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            result = json.loads(result_json)
            
            if result.get('success'):
                return {
                    'type': 'splunk_search',
                    'query': spl_query,
                    'status': 'success',
                    'results': result.get('data', {})
                }
            else:
                return {
                    'type': 'splunk_search',
                    'query': spl_query,
                    'status': 'failed',
                    'error': result.get('error', 'Unknown error')
                }
                
        except Exception as e:
            return {
                'type': 'splunk_search',
                'query': spl_query,
                'status': 'error',
                'error': str(e)
            }
    
    def _call_mcp_server(self, server_name: str, endpoint: str, method: str = "GET", 
                        data: Optional[Dict] = None, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Call MCP server for threat intelligence gathering.
        
        Args:
            server_name: Name of the MCP server (virustotal, abuseip, etc.)
            endpoint: API endpoint to call
            method: HTTP method to use
            data: Optional request data
            headers: Optional request headers
            
        Returns:
            Dictionary with MCP server response
        """
        try:
            logger.info(f"🔧 MCP SERVER: Calling {server_name} at {endpoint}")
            
            # Prepare headers with API keys
            api_headers = headers or {}
            
            # Add API keys based on server
            if server_name.lower() == 'virustotal':
                api_key = os.getenv('VIRUSTOTAL_API_KEY')
                if api_key:
                    api_headers['x-apikey'] = api_key
            elif server_name.lower() == 'abuseip':
                api_key = os.getenv('ABUSEIP_API_KEY')
                if api_key:
                    api_headers['Key'] = api_key
            elif server_name.lower() == 'shodan':
                api_key = os.getenv('SHODAN_API_KEY')
                if api_key:
                    api_headers['X-API-Key'] = api_key
            elif server_name.lower() == 'otx':
                api_key = os.getenv('OTX_API_KEY')
                if api_key:
                    api_headers['X-OTX-API-KEY'] = api_key
            
            # Use API tool to make the request
            result_json = self.api_tool._run(
                method=method,
                url=endpoint,
                data=data,
                headers=api_headers
            )
            
            result = json.loads(result_json)
            
            if result.get('success'):
                return {
                    'type': f'mcp_{server_name}',
                    'server': server_name,
                    'endpoint': endpoint,
                    'status': 'success',
                    'data': result.get('data', {}),
                    'response_code': result.get('status_code', 200)
                }
            else:
                return {
                    'type': f'mcp_{server_name}',
                    'server': server_name,
                    'endpoint': endpoint,
                    'status': 'failed',
                    'error': result.get('error', 'Unknown error'),
                    'response_code': result.get('status_code', 500)
                }
                
        except Exception as e:
            return {
                'type': f'mcp_{server_name}',
                'server': server_name,
                'endpoint': endpoint,
                'status': 'error',
                'error': str(e)
            }
    
    def _gather_threat_intelligence(self, alert_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Gather threat intelligence from multiple MCP servers.
        
        Args:
            alert_data: Alert information for threat intelligence gathering
            
        Returns:
            List of MCP server results
        """
        mcp_results = []
        src_ip = alert_data.get('src_ip', '')
        dest_ip = alert_data.get('dest_ip', '')
        
        # VirusTotal IP analysis
        if src_ip and src_ip != 'N/A':
            try:
                vt_result = self._call_mcp_server(
                    'virustotal',
                    f'https://www.virustotal.com/api/v3/ip_addresses/{src_ip}',
                    'GET'
                )
                mcp_results.append(vt_result)
            except Exception as e:
                logger.warning(f"VirusTotal API call failed: {e}")
        
        # AbuseIPDB IP reputation
        if src_ip and src_ip != 'N/A':
            try:
                abuseip_result = self._call_mcp_server(
                    'abuseip',
                    'https://api.abuseipdb.com/api/v2/check',
                    'GET',
                    params={'ipAddress': src_ip, 'maxAgeInDays': 90, 'verbose': ''}
                )
                mcp_results.append(abuseip_result)
            except Exception as e:
                logger.warning(f"AbuseIPDB API call failed: {e}")
        
        # Shodan IP information
        if src_ip and src_ip != 'N/A':
            try:
                shodan_result = self._call_mcp_server(
                    'shodan',
                    f'https://api.shodan.io/shodan/host/{src_ip}',
                    'GET'
                )
                mcp_results.append(shodan_result)
            except Exception as e:
                logger.warning(f"Shodan API call failed: {e}")
        
        # AlienVault OTX IP analysis
        if src_ip and src_ip != 'N/A':
            try:
                otx_result = self._call_mcp_server(
                    'otx',
                    f'https://otx.alienvault.com/api/v1/indicators/IPv4/{src_ip}/general',
                    'GET'
                )
                mcp_results.append(otx_result)
            except Exception as e:
                logger.warning(f"OTX API call failed: {e}")
        
        logger.info(f"🔧 MCP SERVERS: Completed {len(mcp_results)} threat intelligence calls")
        return mcp_results
    
    def _extract_findings(self, execution_result: str) -> str:
        """Extract key findings from execution result."""
        import re
        
        logger.debug(f"📋 PLAYBOOK RUNNER AGENT: Extracting findings from {len(execution_result)} characters")
        
        # Look for findings sections or patterns
        findings_patterns = [
            r'##?\s*Findings?\s*\n(.*?)(?=\n##|\n\*\*|\n\n|$)',
            r'\*\*Findings?\*\*\s*\n(.*?)(?=\n\*\*|\n##|\n\n|$)',
            r'Key Findings?\s*:\s*(.*?)(?=\n\n|\n\*\*|\n##|$)',
            r'Discovered\s*:\s*(.*?)(?=\n\n|\n\*\*|\n##|$)',
            r'Identified\s*:\s*(.*?)(?=\n\n|\n\*\*|\n##|$)'
        ]
        
        for pattern in findings_patterns:
            matches = re.findall(pattern, execution_result, re.IGNORECASE | re.DOTALL)
            if matches:
                # Return the first substantial finding
                for match in matches:
                    cleaned = match.strip()
                    if len(cleaned) > 10:  # Only return substantial findings
                        logger.debug(f"📋 PLAYBOOK RUNNER AGENT: Found findings using pattern: {len(cleaned)} characters")
                        return cleaned
        
        # Fallback: extract lines containing finding keywords
        findings = []
        lines = execution_result.split('\n')
        
        for line in lines:
            line_lower = line.lower().strip()
            if any(keyword in line_lower for keyword in ['found', 'detected', 'discovered', 'identified', 'analysis shows']):
                if len(line.strip()) > 10:
                    findings.append(line.strip())
        
        result = '\n'.join(findings) if findings else 'No specific findings extracted from execution results.'
        logger.debug(f"📋 PLAYBOOK RUNNER AGENT: Findings extraction result: {len(result)} characters")
        return result
    
    def _extract_recommendations(self, execution_result: str) -> str:
        """Extract recommendations from execution result."""
        import re
        
        logger.debug(f"📋 PLAYBOOK RUNNER AGENT: Extracting recommendations from {len(execution_result)} characters")
        
        # Look for recommendations sections or patterns
        recommendation_patterns = [
            r'##?\s*Recommendations?\s*\n(.*?)(?=\n##|\n\*\*|\n\n|$)',
            r'\*\*Recommendations?\*\*\s*\n(.*?)(?=\n\*\*|\n##|\n\n|$)',
            r'Next Steps?\s*:\s*(.*?)(?=\n\n|\n\*\*|\n##|$)',
            r'Recommended Actions?\s*:\s*(.*?)(?=\n\n|\n\*\*|\n##|$)',
            r'Should\s+.*?(?=\n\n|\n\*\*|\n##|$)'
        ]
        
        for pattern in recommendation_patterns:
            matches = re.findall(pattern, execution_result, re.IGNORECASE | re.DOTALL)
            if matches:
                # Return the first substantial recommendation
                for match in matches:
                    cleaned = match.strip()
                    if len(cleaned) > 10:  # Only return substantial recommendations
                        logger.debug(f"📋 PLAYBOOK RUNNER AGENT: Found recommendations using pattern: {len(cleaned)} characters")
                        return cleaned
        
        # Fallback: extract lines containing recommendation keywords
        recommendations = []
        lines = execution_result.split('\n')
        
        for line in lines:
            line_lower = line.lower().strip()
            if any(keyword in line_lower for keyword in ['recommend', 'suggest', 'should', 'next step', 'consider']):
                if len(line.strip()) > 10:
                    recommendations.append(line.strip())
        
        result = '\n'.join(recommendations) if recommendations else 'No specific recommendations extracted from execution results.'
        logger.debug(f"📋 PLAYBOOK RUNNER AGENT: Recommendations extraction result: {len(result)} characters")
        return result
    
    def _extract_evidence(self, execution_result: str) -> str:
        """Extract evidence items from execution result."""
        import re
        
        logger.debug(f"📋 PLAYBOOK RUNNER AGENT: Extracting evidence from {len(execution_result)} characters")
        
        # Look for evidence sections or patterns
        evidence_patterns = [
            r'##?\s*Evidence\s*\n(.*?)(?=\n##|\n\*\*|\n\n|$)',
            r'\*\*Evidence\*\*\s*\n(.*?)(?=\n\*\*|\n##|\n\n|$)',
            r'Artifacts?\s*:\s*(.*?)(?=\n\n|\n\*\*|\n##|$)',
            r'Indicators?\s*:\s*(.*?)(?=\n\n|\n\*\*|\n##|$)',
            r'IOCs?\s*:\s*(.*?)(?=\n\n|\n\*\*|\n##|$)'
        ]
        
        for pattern in evidence_patterns:
            matches = re.findall(pattern, execution_result, re.IGNORECASE | re.DOTALL)
            if matches:
                # Return the first substantial evidence
                for match in matches:
                    cleaned = match.strip()
                    if len(cleaned) > 10:  # Only return substantial evidence
                        logger.debug(f"📋 PLAYBOOK RUNNER AGENT: Found evidence using pattern: {len(cleaned)} characters")
                        return cleaned
        
        # Fallback: extract lines containing evidence keywords
        evidence = []
        lines = execution_result.split('\n')
        
        for line in lines:
            line_lower = line.lower().strip()
            if any(keyword in line_lower for keyword in ['evidence', 'artifact', 'indicator', 'ioc', 'log entry', 'network traffic']):
                if len(line.strip()) > 10:
                    evidence.append(line.strip())
        
        result = '\n'.join(evidence) if evidence else 'No specific evidence extracted from execution results.'
        logger.debug(f"📋 PLAYBOOK RUNNER AGENT: Evidence extraction result: {len(result)} characters")
        return result
    
    def execute_playbook(self, playbook_name: str, alert_data: Optional[Dict] = None, 
                        spl_queries: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute complete investigation playbook from start to finish.
        
        Args:
            playbook_name: Name of the playbook to execute
            alert_data: Optional alert context
            spl_queries: Optional pre-generated SPL queries
            
        Returns:
            Dictionary with complete playbook execution results
        """
        logger.info(f"📋 PLAYBOOK RUNNER AGENT: Starting execution of playbook '{playbook_name}'")
        
        # Load playbook steps
        steps = self.load_playbook(playbook_name)
        if not steps:
            return {
                'status': 'failed',
                'error': f'Could not load playbook: {playbook_name}',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        # Execute each step
        step_results = []
        overall_status = 'success'
        
        for step in steps:
            try:
                result = self.execute_step(step, alert_data, spl_queries)
                step_results.append(result)
                
                if result.get('status') == 'failed':
                    overall_status = 'partial'
                    
            except Exception as e:
                logger.error(f"Failed to execute step {step['step_number']}: {e}")
                step_results.append({
                    'step_number': step['step_number'],
                    'status': 'failed',
                    'error': str(e)
                })
                overall_status = 'partial'
        
        # Compile final results
        execution_summary = {
            'playbook': playbook_name,
            'status': overall_status,
            'total_steps': len(steps),
            'completed_steps': len([r for r in step_results if r.get('status') == 'completed']),
            'failed_steps': len([r for r in step_results if r.get('status') == 'failed']),
            'step_results': step_results,
            'alert_context': alert_data,
            'execution_time': datetime.now(timezone.utc).isoformat(),
            'summary': self._generate_execution_summary(step_results)
        }
        
        logger.info(f"📋 PLAYBOOK RUNNER AGENT: Playbook execution completed - Status: {overall_status}")
        return execution_summary
    
    def _generate_execution_summary(self, step_results: List[Dict]) -> str:
        """
        Generate a summary of playbook execution results.
        
        Args:
            step_results: List of step execution results
            
        Returns:
            Summary string
        """
        total_steps = len(step_results)
        completed_steps = len([r for r in step_results if r.get('status') == 'completed'])
        failed_steps = len([r for r in step_results if r.get('status') == 'failed'])
        
        summary = f"Playbook execution completed: {completed_steps}/{total_steps} steps successful"
        
        if failed_steps > 0:
            summary += f", {failed_steps} steps failed"
        
        # Extract key findings
        all_findings = []
        for result in step_results:
            if result.get('findings'):
                all_findings.extend(result['findings'])
        
        if all_findings:
            summary += f"\\n\\nKey Findings:\\n" + "\\n".join(f"- {finding}" for finding in all_findings[:5])
        
        return summary

# Example usage and testing
if __name__ == "__main__":
    # Initialize playbook runner
    runner = PlaybookRunnerAgent()
    
    # Example 1: Load and execute a playbook
    print("\\n" + "="*60)
    print("Example 1: Playbook Execution")
    print("="*60)
    
    alert_data = {
        "id": "ALT-2025-001",
        "title": "Network Intrusion Detected",
        "severity": "High",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.50"
    }
    
    result = runner.execute_playbook(
        "network_intrusion_investigation",
        alert_data
    )
    print(json.dumps(result, indent=2))
    
    # Example 2: Individual step execution
    print("\\n" + "="*60)
    print("Example 2: Individual Step Execution")
    print("="*60)
    
    test_step = {
        'step_number': 1,
        'phase': 'Initial Analysis',
        'phase_description': 'Analyze the source IP and gather initial context',
        'detail_actions': 'Query network logs for source IP activity and check threat intelligence databases',
        'requires_api': True,
        'requires_spl': True
    }
    
    step_result = runner.execute_step(test_step, alert_data)
    print(json.dumps(step_result, indent=2))