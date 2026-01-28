"""
SOC AI Assistant v2 - SPL Generator Agent
=========================================

The SPL Generator Agent is a specialized agent focused solely on generating Splunk SPL 
(Search Processing Language) queries for threat hunting, log analysis, and security investigations.

Key Responsibilities:
1. Generate SPL queries based on user requests and security contexts
2. Utilize Splunk knowledge base including indexes, use cases, and documentation
3. Provide optimized and efficient SPL queries for various security scenarios
4. Support different types of searches: threat hunting, incident investigation, compliance checks

Architecture:
- No RAG system (uses system prompts with embedded knowledge)
- Specialized in SPL query generation only
- Accesses knowledge base files for Splunk configurations and use cases
- Integrates with Splunk documentation URLs for advanced queries
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

# Import RAG utilities
try:
    from agents.rag_utils import get_rag_manager
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    
# load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SPLGeneratorAgent:
    """
    Specialized agent for generating Splunk SPL queries for security operations.
    
    This agent focuses exclusively on creating effective SPL queries for various
    security use cases, from threat hunting to compliance monitoring.
    """
    
    def __init__(self):
        """
        Initialize the SPL Generator Agent with OpenAI model and knowledge base.
        """
        # Optimized LLM for faster SPL generation
        self.llm = ChatOllama(
            model="qwen2.5:3b", 
            temperature=0.1,
            num_ctx=2048,  # Reduced context for faster processing
            timeout=10   # Add timeout
        )

        # Initialize RAG Manager
        self.rag_manager = None
        self.rag_enabled = False
        if RAG_AVAILABLE:
            try:
                self.rag_manager = get_rag_manager()
                self.rag_enabled = self.rag_manager.enabled
                if self.rag_enabled:
                    logger.info("🔍 RAG system enabled for SPL Generator")
            except Exception as e:
                logger.warning(f"RAG initialization failed: {e}")

        # Load SPL knowledge base
        self.splunk_indexes = self._load_splunk_indexes()
        self.sources = self._load_sources()
        self.sourcetypes = self._load_sourcetypes()
        self.use_cases = self._load_use_cases()
        self.field_mappings = self._load_field_mappings()
        self.data_models = self._load_data_models()
    def _load_sources(self) -> List[str]:
        """
        Load Splunk sources from knowledge/sources.txt
        """
        sources_path = "knowledge/sources.txt"
        sources = []
        try:
            if os.path.exists(sources_path):
                with open(sources_path, 'r') as f:
                    sources = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.warning(f"Could not load sources: {e}")
        return sources

    def _load_sourcetypes(self) -> List[str]:
        """
        Load Splunk sourcetypes from knowledge/sourcetypes.txt
        """
        sourcetypes_path = "knowledge/sourcetypes.txt"
        sourcetypes = []
        try:
            if os.path.exists(sourcetypes_path):
                with open(sourcetypes_path, 'r') as f:
                    sourcetypes = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.warning(f"Could not load sourcetypes: {e}")
        return sourcetypes
        
        logger.info("🔍 SPL Generator Agent initialized successfully")
    
    def _load_splunk_indexes(self) -> List[str]:
        """
        Load Splunk indexes configuration from knowledge base.
        
        Returns:
            List of available Splunk indexes
        """
        try:
            indexes_path = "knowledge/splunk_indexes.json"
            if os.path.exists(indexes_path):
                with open(indexes_path, 'r') as f:
                    data = json.load(f)
                return data.get("indexes", [])
        except Exception as e:
            logger.warning(f"Could not load Splunk indexes: {e}")
        
        # Default indexes if file doesn't exist
        return [
            "*"
        ]
    
    def _load_use_cases(self) -> List[Dict[str, str]]:
        """
        Load SPL use cases from knowledge base.
        
        Returns:
            List of use case dictionaries with descriptions and example queries
        """
        try:
            use_cases_path = "knowledge/splunk_use_cases.json"
            if os.path.exists(use_cases_path):
                with open(use_cases_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load use cases: {e}")
        
        # Default use cases
        return [
            {
                "name": "Sample Data - Network Intrusion Detection",
                "description": "Detect suspicious network connections and potential intrusions",
                "example_spl": "index=net* earliest=-1h | where src_ip!=dest_ip | stats count by src_ip, dest_ip, protocol | sort -count"
            },
            {
                "name": "Sample Data - Failed Login Analysis",
                "description": "Analyze failed authentication attempts for brute force attacks",
                "example_spl": "index=win* EventCode=4625 earliest=-1h | stats count by user, src_ip | where count > 10"
            },
            {
                "name": "Sample Data - Malware Detection",
                "description": "Hunt for malware indicators in endpoint logs",
                "example_spl": "index=win* (process_name=*.exe OR file_name=*.dll) earliest=-24h | search NOT process_path=C:\\\\Windows\\\\System32\\\\*"
            },
            {
                "name": "Sample Data - Data Exfiltration Hunt",
                "description": "Look for large data transfers indicating potential exfiltration",
                "example_spl": "index=net* earliest=-1h | eval bytes_mb=bytes/1024/1024 | where bytes_mb > 100 | stats sum(bytes_mb) by src_ip, dest_ip"
            }
        ]
    
    def _load_field_mappings(self) -> Dict[str, str]:
        """
        Load field mappings and log parsing configurations.
        
        Returns:
            Dictionary mapping common fields to their log format equivalents
        """
        try:
            fields_path = "knowledge/field_mappings.json"
            if os.path.exists(fields_path):
                with open(fields_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load field mappings: {e}")
        
        # Default field mappings
        return {
            "source_ip": "src_ip, client_ip, source_address",
            "destination_ip": "dest_ip, server_ip, destination_address, dest",
            "user": "username, user, account, login",
            "process": "process_name, proc_name, process",
            "file": "file_name, filename, file_path",
            "timestamp": "_time, time, timestamp, event_time",
            "event_id": "EventCode, event_id, eventid, log_id"
        }
    
    def _load_data_models(self) -> Dict[str, Any]:
        """
        Load Splunk data model definitions for enhanced field awareness.
        
        Returns:
            Dictionary containing processed data model information
        """
        data_models = {}
        data_model_dir = "knowledge/data_model"

        try:
            if os.path.exists(data_model_dir):
                for filename in os.listdir(data_model_dir):
                    if not filename.endswith('.json'):
                        continue

                    model_path = os.path.join(data_model_dir, filename)
                    try:
                        with open(model_path, 'r', encoding='utf-8') as f:
                            model_data = json.load(f)
                    except Exception as e:
                        logger.warning(f"Skipping invalid JSON file {filename}: {e}")
                        continue

                    # Ensure we have a dict at the top-level
                    if not isinstance(model_data, dict):
                        logger.warning(f"Skipping {filename}: expected JSON object, got {type(model_data).__name__}")
                        continue

                    # Process the data model to extract useful information
                    model_name = model_data.get('modelName') or filename.replace('.json', '')
                    processed_model = {
                        'displayName': model_data.get('displayName', model_name),
                        'description': model_data.get('description', ''),
                        'fields': {},
                        'objects': []
                    }

                    objects = model_data.get('objects') or []
                    if not isinstance(objects, list):
                        logger.debug(f"Data model {model_name} objects field is not a list, skipping objects")
                        objects = []

                    # Extract field information from all objects
                    for obj in objects:
                        if not isinstance(obj, dict):
                            continue

                        object_info = {
                            'name': obj.get('objectName', '') or '',
                            'displayName': obj.get('displayName', '') or '',
                            'fields': []
                        }

                        fields = obj.get('fields') or []
                        if not isinstance(fields, list):
                            fields = []

                        # Extract field details
                        for field in fields:
                            if not isinstance(field, dict):
                                continue

                            field_name = field.get('fieldName') or ''

                            # Normalize comment which can be dict or string
                            comment = field.get('comment') or {}
                            if not isinstance(comment, dict):
                                comment = {
                                    'description': str(comment) if comment is not None else '',
                                    'expected_values': [],
                                    'recommended': False
                                }

                            field_info = {
                                'name': field_name,
                                'type': field.get('type', 'string'),
                                'description': comment.get('description', ''),
                                'expected_values': comment.get('expected_values', []),
                                'recommended': comment.get('recommended', False)
                            }

                            object_info['fields'].append(field_info)
                            if field_name:
                                processed_model['fields'][field_name] = field_info

                        processed_model['objects'].append(object_info)

                    data_models[model_name] = processed_model

                logger.info(f"📊 Loaded {len(data_models)} Splunk data models for enhanced SPL generation")

        except Exception as e:
            logger.warning(f"Could not load data models: {e}")

        return data_models
    
    def _get_system_prompt(self, request) -> str:
            """
            Generate the system prompt for the SPL Generator Agent with RAG context.
            """
            # CORRECT: Define all info strings once at the beginning of the method.
            indexes_info = json.dumps(self.splunk_indexes, indent=2)
            sources_info = json.dumps(self.sources, indent=2)
            sourcetypes_info = json.dumps(self.sourcetypes, indent=2)
            use_cases_info = json.dumps(self.use_cases, indent=2)
            field_mappings_info = json.dumps(self.field_mappings, indent=2)
            
            # Get RAG context if available
            rag_sections: List[str] = []
            if self.rag_enabled and self.rag_manager:
                try:
                    spl_results = self.rag_manager.search(
                        query=request,
                        collection_name="spl_knowledge",
                        k=3
                    )
                    if spl_results:
                        spl_context = "**Relevant Examples and Best Practices from Knowledge Base:**\n\n"
                        for i, result in enumerate(spl_results, 1):
                            filename = result['metadata'].get('filename', 'unknown')
                            content = result['content'][:500]
                            spl_context += f"**Example {i}** (from {filename}):\n{content}\n\n"
                        rag_sections.append(spl_context.strip())

                    alert_results = self.rag_manager.search(
                        query=request,
                        collection_name="alert_research",
                        k=2
                    )
                    if alert_results:
                        alert_context = "**Alert Research Descriptions (Splunk research-style):**\n\n"
                        for i, result in enumerate(alert_results, 1):
                            filename = result['metadata'].get('filename', 'unknown')
                            content = result['content'][:500]
                            alert_context += f"**Alert {i}** (from {filename}):\n{content}\n\n"
                        rag_sections.append(alert_context.strip())

                    if rag_sections:
                        rag_context = "\n\n".join(rag_sections)
                    else:
                        rag_context = "No specific examples found in knowledge base."
                except Exception as e:
                    logger.warning(f"RAG search failed: {e}")
                    rag_context = "RAG search unavailable."
            else:
                rag_context = "RAG system not available."

            # Create a summary of all available field names from data models
            all_field_names = set()
            for model_data in self.data_models.values():
                for obj in model_data.get('objects', []):
                    for field in obj.get('fields', []):
                        if field.get('fieldName'):
                            all_field_names.add(field['fieldName'])
            all_field_names_list = sorted(list(all_field_names))

            # Create a condensed summary of data models. The loop is now only for this purpose.
            data_models_summary = {}
            for model_name, model_data in self.data_models.items():
                important_fields = []
                # This logic to extract fields was missing in the previous version, re-adding it
                for obj in model_data.get('objects', []):
                    for field in obj.get('fields', []):
                        field_name = field.get('fieldName')
                        if not field_name:
                            continue
                        
                        comment = field.get('comment', {})
                        if isinstance(comment, str): # Normalize comment field
                            comment = {'description': comment}

                        if comment.get('recommended') or comment.get('expected_values'):
                            field_summary = {
                                'name': field_name,
                                'type': field.get('type', 'string'),
                                'description': comment.get('description', '')[:100]
                            }
                            if comment.get('expected_values'):
                                field_summary['values'] = comment['expected_values'][:5]
                            important_fields.append(field_summary)
                
                data_models_summary[model_name] = {
                    'displayName': model_data.get('displayName', model_name),
                    'description': model_data.get('description', ''),
                    'key_fields': important_fields[:10]
                }
            data_models_info = json.dumps(data_models_summary, indent=2)

            # The final return statement can now safely access all the info variables.
            return f"""
    You are the SPL Generator Agent, a specialized Splunk expert focused on creating efficient and effective SPL (Search Processing Language) queries for security operations.

    **Your Core Mission:** Translate natural language instructions into a valid JSON array of SPL query objects.

    **Your Expertise:**
    - Advanced Splunk SPL query construction for incident investigation and analysis
    - Threat hunting query patterns and IOC detection
    - Performance optimization for large datasets

    **Available Splunk Indexes:**
    {indexes_info}

    **Available Splunk Sources:**
    {sources_info}

    **Available Splunk Sourcetypes:**
    {sourcetypes_info}

    **All Data Model Field Names (use only these):**
    {json.dumps(all_field_names_list, indent=2)}

    **Splunk Data Models and Field Specifications (Summary):**
    {data_models_info}

    **Common Use Cases and Patterns:**
    {use_cases_info}

    **Field Mappings (how logs are parsed):**
    {field_mappings_info}
    
    **Relevant Knowledge Base Context:**
    {rag_context}

    **SPL Generation Guidelines:**
    1.  **Mandatory Index, Source, and Sourcetype:** ALL queries MUST start with `index=`. Use wildcards (*) at the end of names only when appropriate (e.g., `index=net*`).
    2.  **Field Names:** Use only field names from the provided `All Data Model Field Names` list. Do not invent new field names.
    3.  **Time Ranges:** Always include a time range (e.g., `earliest=-1h`).
    4.  **Performance:** Start queries with `index=` and time range, then filter on specific fields early.
    5.  **Restricted Commands:** NEVER use `| tstats` or `search` as the first command.
    6.  **Query Structure:**
        ```
        index=<index> earliest=<time_range> source=<source> sourcetype=<sourcetype> <search_terms>
        | <filtering_commands>
        | <aggregation_or_analysis>
        | <output_formatting>
        ```

    **Response Format:**
    ALWAYS respond with ONLY a valid JSON array containing one or more query objects. Do NOT include any introductory text, comments, or markdown formatting outside of the JSON.
    Example format:
    [
    {{
        "title": "Brief descriptive title",
        "query": "index=pan* earliest=-15m latest=+15m user=\\"ABC_nhungnguyen\\" OR src_ip=\\"171.253.232.107\\" | table _time, user, src_ip, dest_ip, action",
        "description": "Finds all activity for the specified user and source IP within a 30-minute window around the event.",
        "expected_results": "A table of events showing the user and IP's activity over time."
    }}
    ]

    Generate efficient, security-focused SPL queries that provide actionable intelligence for SOC analysts.
    """
    
    def _extract_spl_queries(self, content: str) -> List[Dict[str, str]]:
        """
        Extract SPL queries from LLM response content.
        
        Args:
            content: LLM response content containing SPL queries
            
        Returns:
            List of dictionaries with query metadata (title, query, description)
        """
        try:
            # Try to parse as JSON first (expected format)
            import re
            
            # Remove markdown code blocks if present
            content = re.sub(r'```json\s*', '', content)
            content = re.sub(r'```\s*', '', content)
            content = content.strip()
            
            # Try to find JSON array in the content
            json_match = re.search(r'\[[\s\S]*\]', content)
            if json_match:
                json_str = json_match.group(0)
                queries_data = json.loads(json_str)
                
                # Normalize the format to match frontend expectations
                normalized_queries = []
                for q in queries_data:
                    normalized_queries.append({
                        "title": q.get("title", "SPL Query"),
                        "query": q.get("query", q.get("spl", "")),
                        "description": q.get("description", "No description"),
                        "expected_results": q.get("expected_results", "Query results")
                    })
                
                logger.info(f"Successfully parsed {len(normalized_queries)} queries from JSON")
                return normalized_queries
                
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse failed: {e}, falling back to text parsing")
        except Exception as e:
            logger.warning(f"Error in JSON extraction: {e}, falling back to text parsing")
        
        # Fallback: Parse as text format
        queries = []
        lines = content.split('\n')
        current_query = None
        current_title = ""
        current_description = ""
        
        for line in lines:
            line = line.strip()
            
            # Look for title
            if line.lower().startswith('title:'):
                if current_query:
                    queries.append({
                        "title": current_title.strip() or "SPL Query",
                        "query": current_query.strip(),
                        "description": current_description.strip() or "No description"
                    })
                current_title = line[6:].strip()
                current_query = None
                current_description = ""
            
            # Look for query
            elif line.lower().startswith('query:'):
                current_query = line[6:].strip()
            
            # Look for description
            elif line.lower().startswith('description:'):
                current_description = line[12:].strip()
            
            # Look for SPL query markers if no title format found
            elif ('index=' in line or 'search ' in line) and not line.startswith('#'):
                if current_query:
                    queries.append({
                        "title": current_title.strip() or "SPL Query",
                        "query": current_query.strip(),
                        "description": current_description.strip() or "No description"
                    })
                current_query = line
                current_title = ""
                current_description = ""
            elif current_query and (line.startswith('|') or line.startswith(' |')):
                current_query += "\n" + line
        
        # Add the last query if exists
        if current_query:
            queries.append({
                "title": current_title.strip() or "SPL Query",
                "query": current_query.strip(),
                "description": current_description.strip() or "No description"
            })
        
        # If no queries found, return a fallback
        if not queries:
            logger.warning("No queries extracted, returning fallback")
            queries = [{
                "title": "Basic Search Query",
                "query": "index=* | head 100",
                "description": "Fallback query - please check the response format"
            }]
        
        return queries
    
    def _classify_query_type(self, spl: str) -> str:
        """
        Classify the type of SPL query based on its content.
        
        Args:
            spl: SPL query string
            
        Returns:
            Query type classification
        """
        spl_lower = spl.lower()
        
        if 'stats count' in spl_lower or 'stats sum' in spl_lower:
            return "aggregation"
        elif 'where' in spl_lower or 'search' in spl_lower:
            return "filtering"
        elif 'eval' in spl_lower:
            return "calculation"
        elif 'lookup' in spl_lower:
            return "enrichment"
        elif 'rex' in spl_lower:
            return "extraction"
        else:
            return "general"
    
    def generate_spl(self, request: str, alert_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate SPL queries for a given request and optional alert context.
        
        Args:
            request: Natural language request for SPL query generation
            alert_data: Optional alert context dictionary
            
        Returns:
            Dictionary with status, queries list, and metadata
        """
        logger.info(f"🔍 SPL GENERATOR AGENT: Creating Splunk query for: {request[:100]}...")
        
        # Build context with request and alert data
        context = f"""
**User Request:** {request}

**Alert Context:** {json.dumps(alert_data, indent=2) if alert_data else "No specific alert context provided"}

Generate appropriate SPL queries for this security request. Return ONLY a valid JSON array.
"""
        
        try:
            messages = [
                SystemMessage(content=self._get_system_prompt(request)),
                HumanMessage(content=context)
            ]
            
            logger.info("Invoking LLM for SPL generation...")
            response = self.llm.invoke(messages)
            spl_content = response.content
            
            logger.info(f"LLM response received: {spl_content[:200]}...")
            
            # Extract queries from response
            queries = self._extract_spl_queries(spl_content)
            
            logger.info(f"Successfully generated {len(queries)} SPL queries")
            
            return {
                "status": "success",
                "request": request,
                "queries": queries,
                "full_response": spl_content,
                "alert_context": alert_data,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating SPL queries: {e}", exc_info=True)
            
            # Return fallback queries
            fallback_queries = self._generate_fallback_queries(alert_data) if alert_data else []
            
            return {
                "status": "error",
                "message": str(e),
                "request": request,
                "queries": fallback_queries,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
    
    def _generate_fallback_queries(self, alert_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate fallback queries when LLM fails"""
        src_ip = alert_data.get('src_ip', '0.0.0.0')
        dest_ip = alert_data.get('dest_ip', '0.0.0.0')
        
        return [
            {
                "title": "Source IP Activity",
                "query": f'index=* src_ip="{src_ip}" | stats count by dest_ip, action',
                "description": f"All activity from source IP {src_ip}"
            },
            {
                "title": "Destination IP Activity", 
                "query": f'index=* dest_ip="{dest_ip}" | stats count by src_ip, action',
                "description": f"All activity to destination IP {dest_ip}"
            },
            {
                "title": "Related Events Timeline",
                "query": f'index=* (src_ip="{src_ip}" OR dest_ip="{dest_ip}") | timechart count by action',
                "description": "Timeline of related events"
            }
        ]
    
    
    def generate_investigation_queries(self, alert_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Generate comprehensive investigation SPL queries for a specific alert.
        
        Args:
            alert_data: Alert information dictionary
            
        Returns:
            List of dictionaries with 'title' and 'query' keys
        """
        logger.info(f"🔍 SPL GENERATOR AGENT: Generating investigation queries for alert: {alert_data.get('title', 'Unknown')}")
        
        investigation_prompt = f"""
        Generate 5-6 comprehensive SPL investigation queries for this security alert:
        
        **Alert Details:**
        - Title: {alert_data.get('title', 'Unknown')}
        - Severity: {alert_data.get('severity', 'Unknown')}
        - Source IP: {alert_data.get('src_ip', 'N/A')}
        - Destination IP: {alert_data.get('dest_ip', 'N/A')}
        - Description: {alert_data.get('description', 'No description')}
        
        Generate investigation queries that cover:
        1. Source IP activity analysis
        2. Destination/target analysis
        3. Timeline and pattern analysis
        4. Similar threat detection
        5. Impact assessment
        6. Related events correlation
        
        For each query, provide:
        - A descriptive title
        - The complete SPL query
        - Focus on actionable security intelligence
        
        Return ONLY a JSON array of objects like:
        [
            {{"title": "Source IP Activity Analysis", "query": "index=* src_ip=\\"x.x.x.x\\" | ..."}},
            {{"title": "Timeline Analysis", "query": "index=* ... | timechart ..."}},
            ...
        ]
        
        Do NOT include any additional text outside the JSON array.
        """
        
        try:
            if self.llm:
                messages = [
                    SystemMessage(content="You are a Splunk expert generating investigation SPL queries. Respond with only a JSON array."),
                    HumanMessage(content=investigation_prompt)
                ]
                
                response = self.llm.invoke(messages)
                queries_json = response.content.strip()
                
                # Parse the JSON response
                investigation_queries = json.loads(queries_json)
                
                if isinstance(investigation_queries, list):
                    logger.info(f"🔍 SPL GENERATOR AGENT: Generated {len(investigation_queries)} investigation queries")
                    return investigation_queries
                else:
                    raise ValueError("Response is not a list")
            else:
                logger.warning("⚠️ LLM not available, using fallback investigation queries")
                return self._generate_fallback_investigation_queries(alert_data)
                
        except Exception as e:
            logger.error(f"Error generating investigation queries: {e}")
            return self._generate_fallback_investigation_queries(alert_data)
    
    def _generate_fallback_investigation_queries(self, alert_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate fallback investigation queries when AI is not available."""
        src_ip = alert_data.get('src_ip', '0.0.0.0')
        dest_ip = alert_data.get('dest_ip', '0.0.0.0')
        
        return [
            {
                "title": "Source IP Activity Analysis",
                "query": f'index=network src_ip="{src_ip}" | stats count by dest_ip, dest_port, action | sort -count | head 20'
            },
            {
                "title": "Destination Analysis", 
                "query": f'index=network dest_ip="{dest_ip}" | stats count by src_ip, action | sort -count | head 20'
            },
            {
                "title": "Traffic Timeline",
                "query": f'index=network (src_ip="{src_ip}" OR dest_ip="{dest_ip}") | timechart span=1h count by action'
            },
            {
                "title": "Port Scanning Detection",
                "query": f'index=network src_ip="{src_ip}" | stats dc(dest_port) as unique_ports, count by dest_ip | where unique_ports > 5'
            },
            {
                "title": "Related Security Events",
                "query": f'index=security (src_ip="{src_ip}" OR dest_ip="{dest_ip}") | stats count by signature, action | sort -count'
            }
        ]

# Example usage and testing
if __name__ == "__main__":
    # Initialize SPL generator
    spl_generator = SPLGeneratorAgent()
    
    # Example 1: Basic threat hunting request
    '''
    print("\\n" + "="*60)
    print("Example 1: Network Threat Hunting")
    print("="*60)
    
    result1 = spl_generator.generate_spl(
        "Generate SPL queries to list all source IP that have blocked more than 10 connections in the last hour",
    )
    print(json.dumps(result1, indent=2))
    '''

    # Example 2: Alert-specific SPL generation
    print("\\n" + "="*60)
    print("Example 2: Alert-Specific Analysis")
    print("="*60)
    
    alert_data = {
        "title": "Suspicious Process Execution",
        "severity": "High",
        "first_event_time": "2025-09-15 14:14:15",
        "user": "ABC_nhungnguyen",
        "src_ip": "171.253.232.107",
        "num_failed_logins": 3,
        "num_successful_logins": 0,
        "total_risk_score": 3.0
    }
    
    result2 = spl_generator.generate_spl(
        "Create SPL queries to find all activities related to this user and source IP before and after the first event time 15 mins",
        alert_data
    )
    print(json.dumps(result2, indent=2))
    
    