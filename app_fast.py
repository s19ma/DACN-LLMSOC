import os
import sys
import json
import logging
import uuid
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Disable SSL warnings for demo purposes (only for development)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Global variables for application state
supervisor = None
alert_supervisor = None
alert_manager = None

# Configuration
INVESTIGATION_DATA_DIR = 'investigation_data'
CACHE_DATA_DIR = 'cache_data'

class AlertManager:
    """Manages alert data and persistence"""
    
    def __init__(self, excel_file='alerts_database.xlsx'):
        self.excel_file = excel_file
        self.alerts = self.load_alerts_from_excel()
    
    def load_alerts_from_excel(self):
        """Load alerts from Excel file or set error state if failed"""
        import pandas as pd
        try:
            if os.path.exists(self.excel_file):
                df = pd.read_excel(self.excel_file)
                alerts = []
                for _, row in df.iterrows():
                    alert = {}
                    for col in df.columns:
                        alert[col] = str(row[col]) if pd.notna(row[col]) else ''
                    # Ensure backwards compatibility with additional fields
                    if 'alert_id' not in alert or not str(alert.get('alert_id')).strip():
                        alert['alert_id'] = alert.get('id', '') or str(uuid.uuid4())
                    if 'alert_time' not in alert:
                        alert['alert_time'] = alert.get('timestamp', '')
                    if 'source_ip' not in alert:
                        alert['source_ip'] = alert.get('src_ip', '')
                    if 'destination_ip' not in alert:
                        alert['destination_ip'] = alert.get('dest_ip', '')
                    alerts.append(alert)
                print(f"Loaded {len(alerts)} alerts from Excel file: {self.excel_file}")
                return alerts
            else:
                print(f"Excel file {self.excel_file} not found.")
                self.load_error = 'Cannot load the database error'
                return []
        except Exception as e:
            print(f"Error loading Excel file: {e}.")
            self.load_error = 'Cannot load the database error'
            return []
    
    def load_all_alerts(self):
        """Load all alerts"""
        return self.alerts
    
    def get_alert_by_id(self, alert_id):
        """Get specific alert by ID"""
        return next((a for a in self.alerts if a['id'] == alert_id), None)
    
    def update_alert_status(self, alert_id, new_status):
        """Update alert status"""
        alert = self.get_alert_by_id(alert_id)
        if alert:
            alert['status'] = new_status
            return True
        return False

def ensure_investigation_data_dir():
    """Ensure investigation data directory exists"""
    if not os.path.exists(INVESTIGATION_DATA_DIR):
        os.makedirs(INVESTIGATION_DATA_DIR)

def ensure_cache_data_dir():
    """Ensure cache data directory exists"""
    if not os.path.exists(CACHE_DATA_DIR):
        os.makedirs(CACHE_DATA_DIR)

# Lazy loading functions for AI agents
def get_supervisor():
    """Get supervisor agent with lazy loading"""
    global supervisor
    if supervisor is None:
        print("Initializing Supervisor Agent...")
        try:
            from agents.supervisor_ollama import SupervisorAgent
            supervisor = SupervisorAgent()
            print("Supervisor Agent initialized with Ollama LLM")
        except ImportError as e:
            print(f"Error importing supervisor: {e}")
            # Fallback to basic functionality
            supervisor = None
    return supervisor

def get_spl_generator():
    """Get SPL query generator agent with lazy loading"""
    global supervisor
    if supervisor is None:
        print("Initializing SPL Query Generator Agent...")
        try:
            from agents.spl_generator_ollama import SPLQueryGeneratorAgent
            spl_generator = SPLQueryGeneratorAgent()
            print("SPL Query Generator Agent initialized with Ollama LLM")
        except ImportError as e:
            print(f"Error importing SPL generator: {e}")
            # Fallback to basic functionality
            spl_generator = None
    return spl_generator

# Initialize only essential components
print("Starting SOC AI Assistant (Fast Mode)")
print("=" * 50)

# Initialize alert manager
alert_manager = AlertManager()
print("Alert Manager initialized successfully")

# Ensure directories exist
ensure_investigation_data_dir()
ensure_cache_data_dir()
print("Directories created")

print("AI Agents will be initialized on first use")
print("Server starting...")
supervisor = get_supervisor()

# Flask Routes
@app.route('/')
def dashboard():
    """Main dashboard showing all alerts"""
    if alert_manager is None:
        return "Alert Manager not initialized", 500
    alerts = alert_manager.load_all_alerts()
    load_error = getattr(alert_manager, 'load_error', None)
    return render_template('alert_dashboard.html', alerts=alerts, load_error=load_error)

@app.route('/alert/<alert_id>')
def alert_detail(alert_id):
    """Alert detail page"""
    if alert_manager is None:
        return "Alert Manager not initialized", 500
    
    alert = alert_manager.get_alert_by_id(alert_id)
    if not alert:
        return "Alert not found", 404

    return render_template('alert_detail.html', alert=alert)

@app.route('/api/explain-status', methods=['POST'])
def explain_status():
    """API endpoint to explain alert status using AI."""
    data = request.json
    alert_id = data.get('alert_id')

    if alert_manager is None:
        return jsonify({'error': 'Alert Manager not initialized'}), 500

    alerts = alert_manager.load_all_alerts()
    alert = next((a for a in alerts if a['id'] == alert_id), None)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404


    if supervisor:
        response = supervisor.explain_alert_status(alert)
        print(f"{response = }")
    else:
        # Fallback explanation
        response = f"""
        <div class="alert alert-warning">
            <h5>Alert Analysis (Fallback Mode)</h5>
            <p><strong>Alert:</strong> {alert.get('title', 'Unknown Alert')}</p>
            <p><strong>Severity:</strong> <span class="badge bg-warning">{alert.get('severity', 'Medium')}</span></p>
            <p><strong>Source IP:</strong> <code>{alert.get('src_ip', 'Unknown')}</code></p>
            <p><strong>Destination IP:</strong> <code>{alert.get('dest_ip', 'Unknown')}</code></p>
            <p><strong>Description:</strong> {alert.get('description', 'No description available')}</p>
            <hr>
            <p><strong>Analysis:</strong> This is a {alert.get('severity', 'Medium').lower()} severity security alert requiring investigation.</p>
            <small class="text-muted">Note: AI features are not available. Using basic analysis.</small>
        </div>
        """

    return jsonify({
        'status': 'success',
        'explanation': response,
        'alert_id': alert_id
    })

@app.route('/api/qa-assistant', methods=['POST'])
def qa_assistant():
    """API endpoint for Q&A interaction with AI assistant."""
    try:
        data = request.json
        alert_id = data.get('alert_id')
        question = data.get('question')
        
        if not question:
            return jsonify({'error': 'Question is required'}), 400
        
        if alert_manager is None:
            return jsonify({'error': 'Alert Manager not initialized'}), 500
            
        alerts = alert_manager.load_all_alerts()
        alert = next((a for a in alerts if a['id'] == alert_id), None)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        logger.info(f"Q&A request for alert {alert_id}: {question}")
        
        # Get supervisor (lazy loading)
        supervisor_agent = get_supervisor()
        
        if supervisor_agent and supervisor_agent.ai_enabled:
            logger.info("Using AI supervisor for Q&A")
            response = supervisor_agent.answer_alert_question(question, alert)
        else:
            # Fallback Q&A
            logger.warning("AI not available, using fallback response")
            response = f"""
            <div class="alert alert-info">
                <h6>Q&A Response (Fallback Mode)</h6>
                <p><strong>Question:</strong> {question}</p>
                <p><strong>Alert Context:</strong> {alert.get('title', 'Unknown Alert')}</p>
                <hr>
                <p><strong>Answer:</strong> Based on the alert information, this is a {alert.get('severity', 'Unknown').lower()} severity security alert that requires investigation.</p>
                <ul>
                    <li><strong>Alert ID:</strong> {alert.get('id', 'Unknown')}</li>
                    <li><strong>Source IP:</strong> {alert.get('src_ip', 'Unknown')}</li>
                    <li><strong>Destination IP:</strong> {alert.get('dest_ip', 'Unknown')}</li>
                    <li><strong>Description:</strong> {alert.get('description', 'No description')}</li>
                </ul>
                <p><strong>Recommendation:</strong> Review the alert details and follow standard investigation procedures.</p>
                <small class="text-muted">Note: AI features are not available. Using basic analysis.</small>
            </div>
            """
        
        return jsonify({
            'status': 'success',
            'answer': response,
            'question': question,
            'alert_id': alert_id,
            'cached': False
        })
        
    except Exception as e:
        logger.error(f'Question processing error: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Question processing error: {str(e)}'}), 500

@app.route('/api/generate_spl', methods=['POST'])
def api_generate_spl():
    """API endpoint for SPL query generation to find IOCs related to an alert."""
    try:
        data = request.get_json()
        alert_id = data.get('alert_id')
        
        if not alert_id:
            return jsonify({'error': 'Alert ID is required'}), 400
        
        if alert_manager is None:
            return jsonify({'error': 'Alert Manager not initialized'}), 500
        
        # Get alert data
        alert = alert_manager.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Initialize SPL Generator
        from agents.spl_generator_ollama import SPLGeneratorAgent
        spl_generator = SPLGeneratorAgent()
        
        # Generate investigation queries to find IOCs
        logger.info(f"Generating SPL queries to find IOCs for alert: {alert_id}")
        print(f"{alert = }")
        # Create request string for SPL generation
        request_text = f"""
            Please generate SPL queries to:
            1. Find all activity from the source IP
            2. Identify related events and patterns
            3. Search for similar threats
            4. Analyze timeline and connections
            5. Detect IOCs and suspicious indicators
            """
        print(f"{request_text = }")
                # Call generate_spl with proper parameters
        result = spl_generator.generate_spl(request_text, alert)
        
        if result.get('status') == 'success':
            return jsonify({
                'status': 'success',
                'alert_id': alert_id,
                'queries': result.get('queries', []),
                'total_queries': len(result.get('queries', []))
            })
        else:
            return jsonify({
                'status': 'error',
                'error': result.get('message', 'Unknown error'),
                'alert_id': alert_id
            }), 500
        
    except Exception as e:
        logger.error(f"Error generating SPL queries: {e}")
        return jsonify({'error': f'Error generating SPL queries: {str(e)}'}), 500

@app.route('/api/quick-questions', methods=['POST'])
def get_quick_questions():
    """Generate AI-powered quick questions for an alert."""
    try:
        data = request.json
        alert_id = data.get('alert_id')
        
        if not alert_id:
            return jsonify({"error": "Alert ID is required"}), 400
            
        alert = alert_manager.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        
        supervisor = get_supervisor()
        if supervisor:
            logger.info(f"AI generating quick questions for alert {alert_id}")
            questions = supervisor.generate_quick_questions(alert)
        else:
            # AI-powered fallback questions based on alert data
            title = alert.get('title', 'Unknown Alert')
            src_ip = alert.get('src_ip', 'Unknown')
            severity = alert.get('severity', 'Unknown')
            
            questions = [
                f"AI Analysis: What is the threat level of this {severity} severity alert?",
                f"AI Investigation: How should I investigate source IP {src_ip}?",
                f"AI Impact: What is the potential business impact of '{title}'?",
                f"AI Response: What immediate actions should I take for this alert?",
                f"AI Correlation: Are there similar attacks from {src_ip} in our logs?",
                f"AI Escalation: Should this {severity} alert be escalated to management?",
                f"AI Security: What security controls should be implemented?"
            ]
        
        return jsonify({
            "status": "success",
            "alert_id": alert_id,
            "questions": questions
        })
        
    except Exception as e:
        logger.error(f"Error in get_quick_questions: {e}")
        return jsonify({"error": str(e)}), 500

# @app.route('/api/investigation-queries', methods=['POST'])
# def get_investigation_queries():
#     """Generate AI-powered SPL queries for alert investigation."""
#     try:
#         data = request.json
#         alert_id = data.get('alert_id')
        
#         if not alert_id:
#             return jsonify({"error": "Alert ID is required"}), 400
            
#         alert = alert_manager.get_alert_by_id(alert_id)
#         if not alert:
#             return jsonify({"error": "Alert not found"}), 404
        
#         supervisor = get_supervisor()
#         if supervisor:
#             logger.info(f"AI generating investigation queries for alert {alert_id}")
#             queries = supervisor.generate_investigation_spl_queries(alert)
#         else:
#             # AI-powered fallback SPL queries
#             src_ip = alert.get('src_ip', '0.0.0.0')
#             dest_ip = alert.get('dest_ip', '0.0.0.0')
#             title = alert.get('title', 'Unknown Alert')
#             severity = alert.get('severity', 'Unknown')
            
#             queries = [
#                 {
#                     "title": f"AI Analysis: Source IP {src_ip} Threat Intelligence",
#                     "query": f'index=* src_ip="{src_ip}" | stats count by dest_ip, action, sourcetype | sort -count | head 20',
#                     "description": f"AI-powered analysis of all activity from source IP {src_ip} to identify attack patterns"
#                 },
#                 {
#                     "title": f"AI Investigation: Destination IP {dest_ip} Impact Assessment", 
#                     "query": f'index=* dest_ip="{dest_ip}" | stats count by src_ip, action, sourcetype | sort -count | head 20',
#                     "description": f"AI analysis of all activity targeting destination IP {dest_ip} to assess potential compromise"
#                 },
#                 {
#                     "title": f"AI Correlation: {severity} Severity Alert Pattern Analysis",
#                     "query": f'index=* "{title}" OR src_ip="{src_ip}" OR dest_ip="{dest_ip}" | stats count by src_ip, dest_ip, action | sort -count',
#                     "description": f"AI correlation analysis to find related security events and attack patterns"
#                 },
#                 {
#                     "title": f"AI Timeline: Attack Progression Analysis",
#                     "query": f'index=* (src_ip="{src_ip}" OR dest_ip="{dest_ip}") | eval time=strftime(_time, "%Y-%m-%d %H:%M:%S") | sort _time | head 100',
#                     "description": f"AI timeline analysis to understand attack progression and identify lateral movement"
#                 }
#             ]
        
#         return jsonify({
#             "status": "success",
#             "alert_id": alert_id,
#             "queries": queries
#         })
        
#     except Exception as e:
#         logger.error(f"Error in get_investigation_queries: {e}")
#         return jsonify({"error": str(e)}), 500

@app.route('/api/stats')
def api_stats():
    """API endpoint to get agent statistics."""
    try:
        supervisor = get_supervisor()
        stats = supervisor.get_agent_stats()
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/smart-investigation', methods=['POST'])
def smart_investigation():
    """API endpoint for smart IOC investigation with threat intel."""
    try:
        data = request.json
        alert_id = data.get('alert_id')
        
        if not alert_id:
            return jsonify({'error': 'Alert ID is required'}), 400
            
        alert = alert_manager.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        logger.info(f"🔍 Starting smart investigation for alert: {alert_id}")
        
        # Initialize playbook runner with threat intel
        from agents.playbook_runner import PlaybookRunnerAgent
        playbook_runner = PlaybookRunnerAgent()
        
        if not playbook_runner.threat_intel:
            return jsonify({
                'status': 'error',
                'message': 'Threat Intel MCP not configured. Please add API keys to .env file.',
                'help': 'Add VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY to your .env file'
            }), 503
        
        # Run smart investigation
        print(f"{alert = }")
        results = playbook_runner.smart_investigation(alert)
        
        return jsonify({
            'status': 'success',
            'alert_id': alert_id,
            'investigation': results,
            'iocs_analyzed': len(results.get('iocs_found', [])),
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in smart investigation: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "alert_manager": "initialized" if alert_manager else "not_initialized",
        "supervisor": "initialized" if supervisor else "lazy_loading",
        "alert_supervisor": "initialized" if alert_supervisor else "lazy_loading",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True, host='0.0.0.0', port=5000)
