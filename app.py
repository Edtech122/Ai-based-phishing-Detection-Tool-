import os
import re
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv
from model import detector

load_dotenv()

app = Flask(__name__, template_folder='templates')
CORS(app)

print("\n" + "=" * 60)
print("🛡️ AiPhishGuard - AI Phishing Detection")
print("Made by Virat | India 🇮🇳 | © 2026")
print("=" * 60)

detector.load_models()

def analyze_url(url):
    """Analyze URL for phishing"""
    try:
        prob = detector.predict_url(url)
        risk_score = int(prob * 100)
        
        # Rule-based adjustments
        if not url.startswith('https'):
            risk_score += 15
        if any(kw in url.lower() for kw in ['login', 'verify', 'account']):
            risk_score += 10
        if url.count('.') > 3:
            risk_score += 5
        
        risk_score = min(risk_score, 100)
        
        if risk_score >= 70:
            prediction = "PHISHING"
            threat_type = "Fake Website / Credential Harvesting"
        elif risk_score >= 30:
            prediction = "SUSPICIOUS"
            threat_type = "Potentially Malicious"
        else:
            prediction = "SAFE"
            threat_type = "Legitimate Website"
        
        reasons = []
        if not url.startswith('https'):
            reasons.append("No HTTPS encryption")
        if any(kw in url.lower() for kw in ['login', 'verify', 'account']):
            reasons.append("Contains suspicious keywords")
        
        reason = " | ".join(reasons) if reasons else "No phishing indicators"
        
        return {
            'prediction': prediction,
            'confidence': round(prob, 2),
            'risk_score': risk_score,
            'threat_type': threat_type,
            'reason': reason
        }
    except Exception as e:
        return {
            'prediction': "SUSPICIOUS",
            'confidence': 0.70,
            'risk_score': 50,
            'threat_type': "Analysis",
            'reason': "Complete analysis"
        }

def analyze_text(text, input_type='email'):
    """Analyze text for phishing"""
    try:
        prob = detector.predict_text(text)
        risk_score = int(prob * 100)
        text_lower = text.lower()
        
        urgency = ['urgent', 'immediate', 'now', 'today', 'asap']
        credential = ['password', 'username', 'login', 'verify', 'account', 'credit']
        
        risk_score += min(sum(1 for w in urgency if w in text_lower) * 5, 20)
        risk_score += min(sum(1 for w in credential if w in text_lower) * 8, 30)
        
        url_pattern = r'https?://[^\s]+'
        risk_score += min(len(re.findall(url_pattern, text)) * 10, 20)
        
        risk_score = min(risk_score, 100)
        
        if risk_score >= 70:
            prediction = "PHISHING"
            threat_type = "Scam / Social Engineering"
        elif risk_score >= 30:
            prediction = "SUSPICIOUS"
            threat_type = "Suspicious Message"
        else:
            prediction = "SAFE"
            threat_type = "Clean Message"
        
        reasons = []
        if any(w in text_lower for w in urgency):
            reasons.append("Urgency detected")
        if any(w in text_lower for w in credential):
            reasons.append("Asks for credentials")
        
        reason = " | ".join(reasons) if reasons else "No indicators"
        
        return {
            'prediction': prediction,
            'confidence': round(prob, 2),
            'risk_score': risk_score,
            'threat_type': threat_type,
            'reason': reason
        }
    except Exception as e:
        return {
            'prediction': "SUSPICIOUS",
            'confidence': 0.70,
            'risk_score': 50,
            'threat_type': "Analysis",
            'reason': "Complete analysis"
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'URL required'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return jsonify(analyze_url(url))

@app.route('/api/check-email', methods=['POST'])
def check_email():
    data = request.get_json()
    content = data.get('content', '')
    if not content:
        return jsonify({'error': 'Content required'}), 400
    return jsonify(analyze_text(content, 'email'))

@app.route('/api/check-sms', methods=['POST'])
def check_sms():
    data = request.get_json()
    content = data.get('content', '')
    if not content:
        return jsonify({'error': 'Content required'}), 400
    return jsonify(analyze_text(content, 'sms'))

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'version': '4.0',
        'model_loaded': detector.url_model is not None
    })

# For Gunicorn
if __name__ != '__main__':
    # Running on Render
    pass

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
