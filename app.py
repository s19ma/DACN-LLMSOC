import os
import json
import logging
import uuid
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
from agents.supervisor_ollama import SupervisorAgent
from agents.alert_supervisor import AlertSupervisorAgent

# Disable SSL warnings for demo purposes (only for development)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
project_root = os.path.dirname(os.path.abspath(__file__))
# dotenv_path = os.path.join(project_root, '.env')
# load_dotenv(dotenv_path=dotenv_path, override=True)

app = Flask(__name__)

# Global variables for application state
supervisor = None
alert_supervisor = None
alert_manager = None
investigations = {}  # In-memory storage for investigations
investigation_steps = {}  # In-memory storage for investigation steps
cached_questions = {}  # Cache for AI-generated quick questions by alert type
cached_investigation_queries = {}  # Cache for AI-generated investigation queries by alert type
chat_history = {}  # Storage for chat conversations by alert_id

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
                print(f"✅ Loaded {len(alerts)} alerts from Excel file: {self.excel_file}")
                return alerts
            else:
                print(f"⚠️ Excel file {self.excel_file} not found.")
                self.load_error = 'Cannot load the database error'
                return []
        except Exception as e:
            print(f"❌ Error loading Excel file: {e}.")
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

def init_application():
    """Initialize application components"""
    global supervisor, alert_supervisor, alert_manager
    
    try:
        # Initialize alert manager first (fast)
        alert_manager = AlertManager()
        print("✅ Alert Manager initialized successfully")
        
        # Ensure investigation data directory exists
        ensure_investigation_data_dir()
        
        # Initialize AI agents lazily (only when needed)
        print("⚠️ AI Agents will be initialized on first use to improve startup time")
        
        return True
    except Exception as e:
        print(f"❌ Failed to initialize application: {e}")
        return False

def ensure_investigation_data_dir():
    """Ensure investigation data directory exists"""
    if not os.path.exists(INVESTIGATION_DATA_DIR):
        os.makedirs(INVESTIGATION_DATA_DIR)

def ensure_cache_data_dir():
    """Ensure cache data directory exists"""
    if not os.path.exists(CACHE_DATA_DIR):
        os.makedirs(CACHE_DATA_DIR)

# Audit trail functionality
def add_audit_entry(investigation_id, action, details, user='system'):
    """Add an audit entry to investigation history"""
    try:
        audit_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'user': user,
            'action': action,
            'details': details,
            'investigation_id': investigation_id
        }
        
        # Add to investigation if it exists
        if investigation_id in investigations:
            if 'audit_trail' not in investigations[investigation_id]:
                investigations[investigation_id]['audit_trail'] = []
            investigations[investigation_id]['audit_trail'].append(audit_entry)
            
            # Save the updated investigation
            save_investigation_state(investigation_id)
            
        logger.info(f"Audit trail entry added for {investigation_id}: {action}")
        return audit_entry
        
    except Exception as e:
        logger.error(f"Failed to add audit entry: {str(e)}")
        return None

def save_investigation_state(investigation_id):
    """Save investigation state to persistent storage"""
    try:
        ensure_investigation_data_dir()
        
        investigation_data = {
            'investigation': investigations.get(investigation_id),
            'steps': investigation_steps.get(investigation_id, [])
        }
        
        file_path = os.path.join(INVESTIGATION_DATA_DIR, f'investigation_{investigation_id}.json')
        with open(file_path, 'w') as f:
            json.dump(investigation_data, f, indent=2, default=str)
            
    except Exception as e:
        print(f"Error saving investigation state: {e}")

def load_investigation_state(investigation_id):
    """Load investigation state from persistent storage"""
    try:
        file_path = os.path.join(INVESTIGATION_DATA_DIR, f'investigation_{investigation_id}.json')
        
        if not os.path.exists(file_path):
            return False
            
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        investigations[investigation_id] = data.get('investigation')
        investigation_steps[investigation_id] = data.get('steps', [])
        
        return True
        
    except Exception as e:
        print(f"Error loading investigation state: {e}")
        return False

# Initialize application
init_application()

# Ensure application components are initialized at startup
if not init_application():
    print("❌ Application failed to initialize. Exiting...")
    exit(1)
else:
    print("✅ Application initialized successfully")

# Lazy loading functions for AI agents
def get_supervisor():
    """Get supervisor agent with lazy loading"""
    global supervisor
    if supervisor is None:
        print("🔄 Initializing Supervisor Agent...")
        supervisor = SupervisorAgent()
        print("✅ Supervisor Agent initialized")
    return supervisor

def get_alert_supervisor():
    """Get alert supervisor agent with lazy loading"""
    global alert_supervisor
    if alert_supervisor is None:
        print("🔄 Initializing Alert Supervisor Agent...")
        alert_supervisor = AlertSupervisorAgent()
        print("✅ Alert Supervisor Agent initialized")
    return alert_supervisor

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

    # Check for existing investigation
    existing_investigation_id = None
    for inv_id, investigation in investigations.items():
        if investigation and investigation.get('alert_id') == alert_id:
            existing_investigation_id = inv_id
            break

    return render_template('alert_detail.html', 
                         alert=alert, 
                         existing_investigation_id=existing_investigation_id)

@app.route('/api/process-alert', methods=['POST'])
def process_alert():
    """Process a security alert using the Alert Supervisor Agent."""
    try:
        data = request.json
        alert_id = data.get('alert_id')
        
        if not alert_id:
            return jsonify({"error": "Alert ID is required"}), 400
        
        if alert_manager is None:
            return jsonify({"error": "Alert Manager not initialized"}), 500
        
        # Get alert data
        alert = alert_manager.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        
        logger.info(f"🚨 Processing alert {alert_id} through Alert Supervisor")
        
        # Get alert supervisor with lazy loading
        alert_supervisor = get_alert_supervisor()
        
        # Process alert through Alert Supervisor
        result = alert_supervisor.process_alert(alert)
        
        # Add audit trail entry
        add_audit_entry(alert_id, 'alert_processed', {
            'alert_id': alert_id,
            'processing_status': result.get('processing_status', 'unknown'),
            'spl_queries_generated': len(result.get('spl_queries', [])),
            'mcp_calls_made': len(result.get('mcp_results', [])),
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        return jsonify({
            "status": "success",
            "alert_id": alert_id,
            "result": result,
            "message": "Alert processed successfully through Alert Supervisor"
        })
        
    except Exception as e:
        logger.error(f"Error processing alert: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e),
            "alert_id": alert_id if 'alert_id' in locals() else "unknown"
        }), 500

@app.route('/api/explain-status', methods=['POST'])
def explain_status():
    """API endpoint to explain alert status using AI, with caching and reanalyze support."""
    data = request.json
    alert_id = data.get('alert_id')
    reanalyze = data.get('reanalyze', False)

    if alert_manager is None:
        return jsonify({'error': 'Alert Manager not initialized'}), 500

    alerts = alert_manager.load_all_alerts()
    alert = next((a for a in alerts if a['id'] == alert_id), None)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404

    try:
        supervisor = get_supervisor()
        response = supervisor.explain_alert_status(alert)

        return jsonify({
            'status': 'success',
            'explanation': response,
            'alert_id': alert_id,
            'cached': False
        })

    except Exception as e:
        return jsonify({'error': f'Analysis error: {str(e)}'}), 500

@app.route('/api/qa-assistant', methods=['POST'])
def qa_assistant():
    """API endpoint for Q&A interaction with AI assistant with chat history."""
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
    
    try:
        supervisor = get_supervisor()
        response = supervisor.answer_alert_question(question, alert)
        
        return jsonify({
            'status': 'success',
            'answer': response,
            'question': question,
            'alert_id': alert_id
        })
        
    except Exception as e:
        error_msg = f'Question processing error: {str(e)}'
        return jsonify({'error': error_msg}), 500

@app.route('/api/generate_spl', methods=['POST'])
def api_generate_spl():
    """API endpoint for SPL query generation."""
    try:
        supervisor = get_supervisor()
        data = request.get_json()
        
        description = data.get('description')
        if not description:
            return jsonify({"error": "Query description is required"}), 400
        
        index = data.get('index', '')
        time_range = data.get('time_range', '-24h')
        
        result = supervisor.generate_spl_query(description, index, time_range)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/quick-questions', methods=['POST'])
def get_quick_questions():
    """Generate AI-powered quick questions for an alert with caching."""
    try:
        data = request.json
        alert_id = data.get('alert_id')
        
        if not alert_id:
            return jsonify({"error": "Alert ID is required"}), 400
            
        alert = alert_manager.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        
        supervisor = get_supervisor()
        questions = supervisor.generate_quick_questions(alert)
        
        return jsonify({
            "status": "success",
            "alert_id": alert_id,
            "questions": questions,
            "cached": False
        })
        
    except Exception as e:
        logger.error(f"Error in get_quick_questions: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/investigation-queries', methods=['POST'])
def get_investigation_queries():
    """Generate AI-powered SPL queries for alert investigation with caching."""
    try:
        data = request.json
        alert_id = data.get('alert_id')
        force_regenerate = data.get('force_regenerate', False)
        
        if not alert_id:
            return jsonify({"error": "Alert ID is required"}), 400
            
        alert = alert_manager.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        
        supervisor = get_supervisor()
        queries = supervisor.generate_investigation_spl_queries(alert)
        
        return jsonify({
            "status": "success",
            "alert_id": alert_id,
            "queries": queries,
            "cached": False
        })
        
    except Exception as e:
        logger.error(f"Error in get_investigation_queries: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats')
def api_stats():
    """API endpoint to get agent statistics."""
    try:
        supervisor = get_supervisor()
        stats = supervisor.get_agent_stats()
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)