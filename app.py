import os
import re
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv
from model import detector
import warnings
warnings.filterwarnings('ignore')

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
CORS(app)

print("\n" + "=" * 60)
print("🛡️ AiPhishGuard - AI Phishing Detection System")
print("Made by Virat | India 🇮🇳 | © 2026")
print("=" * 60)

# Load ML Models
detector.load_models()

# ============================================================
# DATABASE SETUP - Modified for Render (in-memory fallback)
# ============================================================

def init_database():
    """Initialize SQLite database - Works on Render"""
    conn = None
    try:
        # Try to use persistent storage if available (Render disk)
        if os.environ.get('RENDER'):
            # Use /tmp for Render (ephemeral but works during session)
            db_path = '/tmp/phishing.db'
        else:
            # Local development
            db_path = 'phishing.db'
        
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Create tables
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_data TEXT,
            input_type TEXT,
            prediction TEXT,
            risk_score INTEGER,
            confidence REAL,
            threat_type TEXT,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            user_feedback TEXT,
            corrected_prediction TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            malicious_input TEXT,
            threat_type TEXT,
            source TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_scans INTEGER DEFAULT 0,
            phishing_detected INTEGER DEFAULT 0,
            suspicious_detected INTEGER DEFAULT 0,
            safe_detected INTEGER DEFAULT 0,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Initialize stats if empty
        c.execute('SELECT COUNT(*) FROM stats')
        if c.fetchone()[0] == 0:
            c.execute('INSERT INTO stats (total_scans, phishing_detected, suspicious_detected, safe_detected) VALUES (0, 0, 0, 0)')
        
        conn.commit()
        print(f"✅ Database initialized at: {db_path}")
        
    except Exception as e:
        print(f"⚠️ Database warning: {e}")
        print("✅ Continuing with in-memory fallback (logs won't persist)")
    finally:
        if conn:
            conn.close()

init_database()

# ============================================================
# DATABASE HELPER FUNCTIONS (with error handling)
# ============================================================

def save_to_db(input_data, input_type, prediction, risk_score, confidence, threat_type, reason):
    """Save scan result to database with error handling"""
    try:
        db_path = '/tmp/phishing.db' if os.environ.get('RENDER') else 'phishing.db'
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        c.execute('''INSERT INTO logs (input_data, input_type, prediction, risk_score, confidence, threat_type, reason)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (input_data[:500], input_type, prediction, risk_score, confidence, threat_type, reason))
        
        c.execute('UPDATE stats SET total_scans = total_scans + 1, last_updated = CURRENT_TIMESTAMP')
        if prediction == "PHISHING":
            c.execute('UPDATE stats SET phishing_detected = phishing_detected + 1')
        elif prediction == "SUSPICIOUS":
            c.execute('UPDATE stats SET suspicious_detected = suspicious_detected + 1')
        else:
            c.execute('UPDATE stats SET safe_detected = safe_detected + 1')
        
        conn.commit()
        conn.close()
    except Exception as e:
        # Silent fail for database - detection still works
        pass

def get_from_db(query, params=()):
    """Get data from database with error handling"""
    try:
        db_path = '/tmp/phishing.db' if os.environ.get('RENDER') else 'phishing.db'
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        return rows
    except Exception as e:
        return []

# ============================================================
# DETECTION FUNCTIONS
# ============================================================

def analyze_url(url):
    """Analyze URL for phishing detection"""
    try:
        ai_probability = detector.predict_url(url)
        risk_score = int(ai_probability * 100)
        
        # Rule-based checks
        if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', url):
            risk_score += 15
        if not url.startswith('https'):
            risk_score += 10
        if any(kw in url.lower() for kw in ['login', 'verify', 'account', 'secure', 'update']):
            risk_score += 10
        if url.count('.') > 3:
            risk_score += 5
        
        risk_score = min(risk_score, 100)
        
        if risk_score >= 70:
            prediction = "PHISHING"
            threat_type = "Credential Harvesting / Fake Page"
        elif risk_score >= 30:
            prediction = "SUSPICIOUS"
            threat_type = "Potentially Malicious"
        else:
            prediction = "SAFE"
            threat_type = "Legitimate Website"
        
        reasons = []
        if risk_score >= 70:
            reasons.append("URL contains multiple phishing indicators")
        if not url.startswith('https'):
            reasons.append("Does not use HTTPS encryption")
        if any(kw in url.lower() for kw in ['login', 'verify', 'account']):
            reasons.append("Contains suspicious keywords")
        if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', url):
            reasons.append("Uses IP address instead of domain")
        
        reason = " | ".join(reasons) if reasons else "No phishing indicators detected"
        
        # Save to database
        save_to_db(url, 'url', prediction, risk_score, ai_probability, threat_type, reason)
        
        return {
            'prediction': prediction,
            'confidence': round(ai_probability, 2),
            'risk_score': risk_score,
            'threat_type': threat_type,
            'reason': reason
        }
    except Exception as e:
        # Fallback if something fails
        return {
            'prediction': "SUSPICIOUS",
            'confidence': 0.70,
            'risk_score': 50,
            'threat_type': "Analysis Error",
            'reason': "Could not complete analysis. Please try again."
        }

def analyze_text(text, input_type='email'):
    """Analyze email/SMS text for phishing"""
    try:
        ai_probability = detector.predict_text(text)
        risk_score = int(ai_probability * 100)
        text_lower = text.lower()
        
        urgency_words = ['urgent', 'immediate', 'now', 'today', 'asap', 'limited', 'expires']
        urgency_count = sum(1 for w in urgency_words if w in text_lower)
        risk_score += min(urgency_count * 5, 20)
        
        credential_words = ['password', 'username', 'login', 'verify', 'account', 'credit card', 'ssn', 'pin']
        credential_count = sum(1 for w in credential_words if w in text_lower)
        risk_score += min(credential_count * 8, 30)
        
        url_pattern = r'https?://[^\s]+'
        url_count = len(re.findall(url_pattern, text))
        risk_score += min(url_count * 10, 20)
        
        caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if caps_ratio > 0.3:
            risk_score += 10
        if text.count('!') > 2:
            risk_score += 5
        
        risk_score = min(risk_score, 100)
        
        if risk_score >= 70:
            prediction = "PHISHING"
            threat_type = "Credential Harvesting / Social Engineering"
        elif risk_score >= 30:
            prediction = "SUSPICIOUS"
            threat_type = "Suspicious Message"
        else:
            prediction = "SAFE"
            threat_type = "Clean Message"
        
        reasons = []
        if urgency_count > 0:
            reasons.append(f"Creates urgency ({urgency_count} indicators)")
        if credential_count > 0:
            reasons.append(f"Asks for credentials ({credential_count} indicators)")
        if url_count > 0:
            reasons.append(f"Contains {url_count} suspicious link(s)")
        if caps_ratio > 0.3:
            reasons.append("Excessive use of capital letters")
        
        reason = " | ".join(reasons) if reasons else "No phishing indicators detected"
        
        save_to_db(text[:200], input_type, prediction, risk_score, ai_probability, threat_type, reason)
        
        return {
            'prediction': prediction,
            'confidence': round(ai_probability, 2),
            'risk_score': risk_score,
            'threat_type': threat_type,
            'reason': reason
        }
    except Exception as e:
        return {
            'prediction': "SUSPICIOUS",
            'confidence': 0.70,
            'risk_score': 50,
            'threat_type': "Analysis Error",
            'reason': "Could not complete analysis. Please try again."
        }

# ============================================================
# API ROUTES
# ============================================================

@app.route('/')
def index():
    """Serve frontend"""
    return render_template('index.html')

@app.route('/api/check-url', methods=['POST'])
def check_url():
    """URL phishing detection endpoint"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'prediction': 'ERROR'}), 500

@app.route('/api/check-email', methods=['POST'])
def check_email():
    """Email phishing detection endpoint"""
    try:
        data = request.get_json()
        content = data.get('content', '')
        if not content:
            return jsonify({'error': 'Email content is required'}), 400
        result = analyze_text(content, 'email')
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'prediction': 'ERROR'}), 500

@app.route('/api/check-sms', methods=['POST'])
def check_sms():
    """SMS phishing detection endpoint"""
    try:
        data = request.get_json()
        content = data.get('content', '')
        if not content:
            return jsonify({'error': 'SMS content is required'}), 400
        result = analyze_text(content, 'sms')
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'prediction': 'ERROR'}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get scan history"""
    try:
        rows = get_from_db('SELECT id, input_data, input_type, prediction, risk_score, confidence, threat_type, timestamp FROM logs ORDER BY timestamp DESC LIMIT 50')
        history = [{
            'id': r[0],
            'input_data': r[1][:100] if r[1] else '',
            'input_type': r[2],
            'prediction': r[3],
            'risk_score': r[4],
            'confidence': r[5],
            'threat_type': r[6],
            'timestamp': r[7]
        } for r in rows]
        return jsonify(history)
    except Exception as e:
        return jsonify([])

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    try:
        rows = get_from_db('SELECT total_scans, phishing_detected, suspicious_detected, safe_detected FROM stats LIMIT 1')
        if rows:
            return jsonify({
                'total_scans': rows[0][0],
                'phishing_detected': rows[0][1],
                'suspicious_detected': rows[0][2],
                'safe_detected': rows[0][3]
            })
        return jsonify({'total_scans': 0, 'phishing_detected': 0, 'suspicious_detected': 0, 'safe_detected': 0})
    except Exception as e:
        return jsonify({'total_scans': 0, 'phishing_detected': 0, 'suspicious_detected': 0, 'safe_detected': 0})

@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    """Submit user feedback"""
    try:
        data = request.get_json()
        log_id = data.get('log_id')
        feedback = data.get('feedback')
        corrected = data.get('corrected_prediction')
        
        if log_id:
            db_path = '/tmp/phishing.db' if os.environ.get('RENDER') else 'phishing.db'
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute('INSERT INTO feedback (log_id, user_feedback, corrected_prediction) VALUES (?, ?, ?)',
                      (log_id, feedback, corrected))
            conn.commit()
            conn.close()
        
        return jsonify({'message': 'Feedback submitted successfully'})
    except Exception as e:
        return jsonify({'message': 'Feedback received (database limited)'})

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '3.0.0',
        'platform': 'render' if os.environ.get('RENDER') else 'local',
        'model_loaded': detector.url_model is not None,
        'timestamp': datetime.now().isoformat()
    })

# ============================================================
# For Gunicorn (Render) - No app.run() in production
# ============================================================

# This is for local development only
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    print(f"\n🚀 Local server starting at http://127.0.0.1:{port}")
    print("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=port)

# For Gunicorn (Render) - app object is already defined above
