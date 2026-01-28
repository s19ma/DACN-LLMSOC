"""
SOC AI Assistant v2 - Ollama LLM Supervisor Agent (invoke version)
==================================================================

Dùng Ollama SDK trực tiếp (invoke) thay vì gọi API thủ công qua requests.
"""

import os
import logging
from typing import Dict, List, Any, Optional
from langchain_ollama import ChatOllama

# Import RAG utilities
try:
    from agents.rag_utils import get_rag_manager
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class OllamaClient:
    """Client Ollama dùng invoke thay vì REST API"""

    def __init__(self, model="qwen3:8b", base_url="http://localhost:11434"):
        try:
            # Optimize for faster responses
            self.model = ChatOllama(
                model=model, 
                base_url=base_url, 
                timeout=60,  # Increase timeout for stability
                num_ctx=1024,  # Reduce context window for speed (default 4096)
                temperature=0.1  # Lower temp for more focused responses
            )
            self.available = True
            logger.info(f"Ollama client initialized with model: {model}")
        except Exception as e:
            self.available = False
            logger.error(f"Cannot initialize Ollama model: {e}")

    def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Sinh phản hồi bằng Ollama.invoke()"""
        if not self.available:
            return "Error: Ollama not available."

        try:
            full_prompt = (
                f"{system_prompt}\n\nUser Prompt:\n{prompt}"
                if system_prompt
                else prompt
            )
            response = self.model.invoke(full_prompt)
            print(f"{response = }")
            
            # ChatOllama.invoke() returns an AIMessage object with .content attribute
            if hasattr(response, 'content'):
                return str(response.content).strip()
            elif isinstance(response, dict) and "message" in response:
                return response["message"]["content"].strip()
            elif isinstance(response, str):
                return response.strip()
            else:
                return str(response).strip()
        except Exception as e:
            logger.error(f"Ollama invoke error: {e}")
            return f"Error invoking Ollama: {e}"

    def is_available(self) -> bool:
        """Kiểm tra sẵn sàng"""
        return self.available


class SupervisorAgent:
    """AI SOC Supervisor Agent (phiên bản invoke)"""

    def __init__(self):
        logger.info("Initializing SupervisorAgent with invoke-based Ollama...")
        self.ollama = OllamaClient()
        self.ai_enabled = self.ollama.is_available()
        self.response_cache = {}

        # Initialize RAG manager (optional)
        self.rag_manager = None
        self.rag_enabled = False
        if RAG_AVAILABLE:
            try:
                self.rag_manager = get_rag_manager()
                self.rag_enabled = getattr(self.rag_manager, 'enabled', False)
                if self.rag_enabled:
                    logger.info("📚 RAG system enabled for SupervisorAgent")
            except Exception as e:
                logger.warning(f"RAG initialization failed: {e}")
        # System prompts - optimized for speed and conciseness
        self.system_prompts = {
            "alert_analysis": """You are a cybersecurity SOC analyst. Provide concise threat assessment and actionable recommendations. Be direct and practical.""",
            "qa_response": """You are a cybersecurity SOC analyst. Answer questions concisely with technical accuracy and clear recommendations. Keep responses focused and actionable.""",
            "quick_questions": """Generate 4-5 short investigative questions. Be concise. One question per line.""",
        }

    def _build_rag_context(self, query: str, k: int = 2) -> str:
        """Aggregate context from supervisor and alert research knowledge bases."""
        if not (self.rag_enabled and self.rag_manager):
            return ""

        contexts = []
        for collection in ("alert_research", "supervisor_knowledge"):
            try:
                ctx = self.rag_manager.get_relevant_context(query, collection_name=collection, k=k)
                if ctx and "No relevant context" not in ctx:
                    contexts.append(f"{collection.upper()}\n{ctx}")
            except Exception as e:
                logger.warning(f"RAG search failed for {collection}: {e}")
        return "\n\n".join(contexts)


    def explain_alert_status(self, alert_data: Dict[str, Any]) -> str:
        logger.info("Analyzing alert with Ollama (invoke)...")

        title = alert_data.get('title', 'Unknown Alert')
        severity = alert_data.get('severity', 'Unknown')
        src_ip = alert_data.get('src_ip', 'Unknown')
        dest_ip = alert_data.get('dest_ip', 'Unknown')
        description = alert_data.get('description', 'No description available')

        if not self.ai_enabled:
            return f"""
            <div class="alert alert-warning">
                <h5><i class="fas fa-exclamation-triangle me-2"></i>Alert Analysis (Ollama not available)</h5>
                <p>Title: {title}</p>
                <p>Severity: {severity}</p>
                <p>Source IP: {src_ip}</p>
                <p>Description: {description}</p>
            </div>
            """

        # Retrieve optional RAG context for this alert
        rag_context = ""
        if self.rag_enabled and self.rag_manager:
            try:
                query = f"Alert: {title}. Description: {description}. Severity: {severity}. Source: {src_ip}. Destination: {dest_ip}"
                rag_context = self._build_rag_context(query, k=2)
            except Exception as e:
                logger.warning(f"RAG search failed: {e}")
        rag_part = ""
        if rag_context:
            rag_part = "RAG CONTEXT:\n" + rag_context + "\n\n"

        context_parts = [
            f"- Title: {title}",
            f"- Severity: {severity}",
            f"- Source IP: {src_ip}",
            f"- Destination IP: {dest_ip}",
            f"- Description: {description}",
        ]
        context_str = "\n".join(context_parts)

        prompt = f"""
        {rag_part}
        Alert Context:
        {context_str}

        Provide concise:
        1. Technical explanation and likely cause
        2. Key remediation recommendations
        3. Risk assessment
        Format in clean HTML (use <p>, <ul>, <strong>).
        """.strip()



        ai_response = self.ollama.generate_response(prompt, self.system_prompts["alert_analysis"])
        return f"""
        <div class="alert alert-info">
            <h5><i class="fas fa-robot me-2"></i>AI Security Analysis</h5>
            <div><b>Alert:</b> {title} | <b>Severity:</b> {severity}</div>
            <div class="ai-response">{ai_response}</div>
        </div>
        """
    def answer_alert_question(self, question: str, alert_data: Dict[str, Any]) -> str:
        """Answer a question about the specific alert context, returning HTML string."""
        logger.info("Answering question via invoke...")

        cache_key = f"qa::{alert_data.get('id', '')}::{question.strip()}"
        if cache_key in self.response_cache:
            logger.info("Returning cached response")
            return self.response_cache[cache_key]

        if not self.ai_enabled:
            logger.warning("AI not enabled, returning warning message")
            return (
                "<div class='alert alert-warning'>"
                "<strong>AI Q&A unavailable.</strong> Please ensure Ollama is running."
                "</div>"
            )

        try:
            # Extract only essential info to reduce context size and speed up response
            import json
            alert_summary = {
                "id": alert_data.get('id', 'Unknown'),
                "title": alert_data.get('title', 'Unknown'),
                "severity": alert_data.get('severity', 'Unknown'),
                "status": alert_data.get('status', 'Unknown'),
                "timestamp": alert_data.get('timestamp', 'Unknown'),
                "description": alert_data.get('description', 'No description'),
                "playbook": alert_data.get('playbook', 'N/A')
            }
            
            # Parse result JSON if present - flexible extraction for any alert type
            result_str = alert_data.get('result', '')
            if result_str:
                try:
                    result_data = json.loads(result_str) if isinstance(result_str, str) else result_str
                    logs = result_data.get('logs', [])
                    
                    if logs and len(logs) > 0:
                        first_log = logs[0]
                        
                        # Dynamically extract all available fields from first log
                        # Common fields across different alert types
                        field_mappings = {
                            'src_ip': ['src_ip', 'source_ip', 'source_address'],
                            'src_country': ['src_country', 'source_country'],
                            'dest_ip': ['dest_ip', 'destination_ip', 'dest_address'],
                            'dest_country': ['dest_country', 'destination_country'],
                            'user': ['user', 'username', 'account', 'user_name'],
                            'host': ['host', 'hostname', 'computer', 'device'],
                            'action': ['action', 'event_action', 'activity'],
                            'total_traffic': ['total_traffic', 'traffic_count', 'event_count'],
                            'blocked_traffic': ['total_blocked_traffic', 'blocked_count', 'denied_count'],
                            'num_dest_ports': ['num_dest_port', 'port_count', 'targeted_ports'],
                            'num_dest_ips': ['num_dest_ip', 'ip_count', 'targeted_ips'],
                            'process': ['process', 'process_name', 'program'],
                            'file': ['file', 'file_name', 'filename'],
                            'risk_score': ['risk_score', 'score', 'severity_score']
                        }
                        
                        # Extract fields dynamically
                        for key, possible_names in field_mappings.items():
                            for name in possible_names:
                                if name in first_log:
                                    alert_summary[key] = first_log[name]
                                    break
                        
                        # Add summary stats if multiple logs
                        if len(logs) > 1:
                            alert_summary['total_log_entries'] = len(logs)
                            
                except Exception as e:
                    logger.warning(f"Failed to parse result JSON: {e}")
            
            # Build context string with only available fields
            context_parts = [
                f"- ID: {alert_summary.get('id')}",
                f"- Title: {alert_summary.get('title')}",
                f"- Severity: {alert_summary.get('severity')}",
                f"- Status: {alert_summary.get('status')}",
                f"- Time: {alert_summary.get('timestamp')}",
                f"- Description: {alert_summary.get('description')}",
            ]
            
            # Add optional fields only if present
            optional_fields = {
                'source_ip': 'Source IP',
                'src_ip': 'Source IP',
                'src_country': 'Source Country',
                'dest_ip': 'Destination IP',
                'dest_country': 'Destination Country',
                'user': 'User',
                'host': 'Host',
                'action': 'Action',
                'total_traffic': 'Total Traffic',
                'blocked_traffic': 'Blocked Traffic',
                'num_dest_ports': 'Targeted Ports',
                'num_dest_ips': 'Targeted IPs',
                'process': 'Process',
                'file': 'File',
                'risk_score': 'Risk Score',
                'total_log_entries': 'Log Entries',
                'playbook': 'Playbook'
            }
            
            for field_key, field_label in optional_fields.items():
                if field_key in alert_summary and alert_summary[field_key] not in ['N/A', 'Unknown', None]:
                    context_parts.append(f"- {field_label}: {alert_summary[field_key]}")
            
            context_str = "\n            ".join(context_parts)
            
            # Retrieve optional RAG context relevant to the question
            rag_context = ""
            if self.rag_enabled and self.rag_manager:
                try:
                    q = f"Question: {question}. Alert title: {alert_summary.get('title')}. Description: {alert_summary.get('description')}"
                    rag_context = self._build_rag_context(q, k=2)
                except Exception as e:
                    logger.warning(f"RAG search failed: {e}")

            rag_part = ""
            if rag_context:
                rag_part = "RAG CONTEXT:\n" + rag_context + "\n\n"

            prompt = f"""
            {rag_part}
            Question: {question}

            Alert Context:
            {context_str}

            Provide concise:
            1. Technical answer
            2. Key recommendations
            3. Risk assessment
            Format in clean HTML (use <p>, <ul>, <strong>).
            """.strip()

            logger.info(f"Generating response for question: {question[:50]}...")
            ai_response = self.ollama.generate_response(
                prompt, self.system_prompts["qa_response"]
            )
            logger.info(f"AI response generated successfully (length: {len(ai_response)})")
            
            answer = f"""
            <div class="alert alert-success">
                <h6><i class="fas fa-robot me-2"></i>AI Response</h6>
                <b>Question:</b> {question}<hr>
                <div class="ai-response">{ai_response}</div>
            </div>
            """

            self.response_cache[cache_key] = answer
            return answer
            
        except Exception as e:
            logger.error(f"Error in answer_alert_question: {e}")
            import traceback
            traceback.print_exc()
            return f"""
            <div class="alert alert-danger">
                <h6><i class="fas fa-exclamation-triangle me-2"></i>Error</h6>
                <p>Failed to generate AI response: {str(e)}</p>
            </div>
            """
    
    def generate_quick_questions(self, alert_data: Dict[str, Any]) -> List[str]:
        """Generate 4-5 quick investigation questions for the alert (fast version)."""
        logger.info("Generating quick questions via invoke...")
        
        # Use cache key based on alert type
        cache_key = f"quick_q::{alert_data.get('type', alert_data.get('title', 'unknown'))}"
        if cache_key in self.response_cache:
            return self.response_cache[cache_key]

        if not self.ai_enabled:
            title = alert_data.get('title', 'Unknown Alert')
            src_ip = alert_data.get('src_ip', 'Unknown')
            severity = alert_data.get('severity', 'Unknown')
            return [
                f"1. What is the threat level of this {severity} severity alert?",
                f"2. How should we investigate source IP {src_ip}?",
                f"3. What is the potential business impact of '{title}'?",
                f"4. What immediate actions should we take?",
                f"5. Should this alert be escalated?",
            ]

        # Simplified and concise prompt for faster response
        prompt = f"""Generate 4-5 quick investigation questions for this alert:
            Title: {alert_data.get('title')}
            Severity: {alert_data.get('severity')}
            Source IP: {alert_data.get('src_ip')}
            Dest IP: {alert_data.get('dest_ip')}
            Return plain text (one per line)."""

        ai_response = self.ollama.generate_response(
            prompt, self.system_prompts["quick_questions"]
        )
        # Split by lines, strip bullets/numbers
        lines = [q.strip(" -\t").lstrip("1234567890. ").strip() for q in ai_response.split('\n')]
        questions = [q for q in lines if q][:5]  # Limit to 5 questions
        # Add numbering (1, 2, 3, 4...) to each question
        result = [f"{i}. {q}" for i, q in enumerate(questions, 1)]
        self.response_cache[cache_key] = result  # Cache result
        return result

    # # -------------------------------------------------------------------------
    # # 5️⃣ Sinh nhiều SPL query gợi ý
    # # -------------------------------------------------------------------------
    def generate_investigation_spl_queries(self, alert_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate 4-6 SPL queries (title/query/description) for investigation.

        Returns a list of dicts with keys: title, query, description. Always strings.
        """
        logger.info("Generating multiple SPL queries via invoke...")

        def _sanitize_queries(qs: List[Dict[str, str]]) -> List[Dict[str, str]]:
            cleaned = []
            for q in qs:
                cleaned.append({
                    "title": str(q.get("title", "Investigation Query")).strip(),
                    "query": str(q.get("query", "index=* | head 50")).strip(),
                    "description": str(q.get("description", "Suggested investigation search")).strip(),
                })
            return cleaned

        if not self.ai_enabled:
            return _sanitize_queries([
                {"title": "Basic IP Activity", "query": f"index=* (src_ip=\"{alert_data.get('src_ip','')}\" OR dest_ip=\"{alert_data.get('src_ip','')}\") | stats count by sourcetype, host | sort -count", "description": "Activity involving the source IP across indexes"},
                {"title": "Dest IP Activity", "query": f"index=* (src_ip=\"{alert_data.get('dest_ip','')}\" OR dest_ip=\"{alert_data.get('dest_ip','')}\") | stats count by sourcetype, host | sort -count", "description": "Activity involving the destination IP across indexes"},
            ])

        prompt = f"""
        Generate 4-6 Splunk SPL queries to investigate this alert:

        - Title: {alert_data.get('title')}
        - Severity: {alert_data.get('severity')}
        - Source IP: {alert_data.get('src_ip')}
        - Destination IP: {alert_data.get('dest_ip')}
        - Description: {alert_data.get('description')}

        Format strictly as:
        Title: <short descriptive title>
        Query: <single-line SPL>
        Description: <what this query checks>

        Separate each query block with a blank line. Output only these lines.
        """

        # Optionally add RAG context for SPL generation
        full_prompt = prompt
        if self.rag_enabled and self.rag_manager:
            try:
                q = f"Generate SPL queries for alert: {alert_data.get('title')} - {alert_data.get('description')}"
                rag_context = self._build_rag_context(q, k=2)
                if rag_context:
                    full_prompt = f"RAG CONTEXT:\n{rag_context}\n\n" + prompt
            except Exception as e:
                logger.warning(f"RAG search failed: {e}")

        ai_response = self.ollama.generate_response(full_prompt, self.system_prompts.get("spl_queries", ""))

        queries: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        for raw_line in ai_response.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            key = None
            if line.lower().startswith("title:"):
                key = "title"
                value = line.split(":", 1)[1].strip()
                if current:
                    # close previous block if it already has a query
                    if "query" in current or "description" in current:
                        queries.append(current)
                        current = {}
                current["title"] = value
            elif line.lower().startswith("query:"):
                key = "query"
                value = line.split(":", 1)[1].strip()
                current["query"] = value
            elif line.lower().startswith("description:"):
                key = "description"
                value = line.split(":", 1)[1].strip()
                current["description"] = value
            else:
                # try to accumulate into description if present
                if "description" in current:
                    current["description"] += " " + line
                elif "query" in current:
                    current["query"] += " " + line
                elif "title" in current:
                    current["title"] += " " + line
                continue

        if current:
            queries.append(current)

        if not queries:
            # Fallback single query if parsing failed
            queries = [{
                "title": "General Related Activity",
                "query": f"index=* (src_ip=\"{alert_data.get('src_ip','')}\" OR dest_ip=\"{alert_data.get('dest_ip','')}\") | stats count by sourcetype, host | sort -count",
                "description": "Generic related activity around involved IPs"
            }]

        return _sanitize_queries(queries)

    def get_agent_stats(self) -> Dict[str, Any]:
        """Basic stats for health and UI."""
        return {
            "ai_enabled": self.ai_enabled,
            "model": getattr(self.ollama, "model", None).__dict__.get("model", "mistral:7b") if hasattr(self.ollama, "model") else "unknown",
            "cache_size": len(self.response_cache),
        }
