import re
import joblib
from urllib.parse import urlparse
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

class PhishingDetector:
    """AI Model for Phishing Detection - Lightweight for Render"""
    
    def __init__(self):
        self.url_model = None
        self.text_model = None
        self.vectorizer = None
        self.feature_names = [
            'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_question_marks',
            'num_equal_signs', 'num_at_symbols', 'has_https', 'has_ip', 
            'suspicious_keyword_count', 'digit_count'
        ]
    
    def extract_url_features(self, url):
        """Extract features from URL (no numpy/pandas)"""
        features = {}
        
        features['url_length'] = min(len(url), 500)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_symbols'] = url.count('@')
        features['has_https'] = 1 if url.startswith('https') else 0
        
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
        
        suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm']
        features['suspicious_keyword_count'] = sum(1 for kw in suspicious_keywords if kw in url.lower())
        
        features['digit_count'] = sum(c.isdigit() for c in url)
        
        return features
    
    def extract_text_features_dict(self, text):
        """Extract features from text"""
        text_lower = text.lower()
        features = []
        
        urgency_words = ['urgent', 'immediate', 'now', 'today', 'asap', 'limited']
        features.append(sum(1 for w in urgency_words if w in text_lower))
        
        fear_words = ['suspended', 'closed', 'blocked', 'locked', 'compromised', 'warning']
        features.append(sum(1 for w in fear_words if w in text_lower))
        
        credential_words = ['password', 'username', 'login', 'verify', 'account', 'credit card', 'ssn']
        features.append(sum(1 for w in credential_words if w in text_lower))
        
        url_pattern = r'https?://[^\s]+'
        features.append(len(re.findall(url_pattern, text)))
        
        features.append(text.count('!'))
        
        caps = sum(1 for c in text if c.isupper())
        features.append(caps / max(len(text), 1))
        
        return features
    
    def train_url_model(self, urls, labels):
        """Train URL model"""
        print("📊 Training URL model...")
        
        features_list = []
        for i, url in enumerate(urls):
            f = self.extract_url_features(url)
            features_list.append([f[n] for n in self.feature_names])
            if (i + 1) % 20 == 0:
                print(f"   Processed {i + 1}/{len(urls)} URLs")
        
        X_train, X_test, y_train, y_test = train_test_split(features_list, labels, test_size=0.2, random_state=42)
        
        self.url_model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.url_model.fit(X_train, y_train)
        
        accuracy = self.url_model.score(X_test, y_test)
        print(f"✅ URL Model Accuracy: {accuracy * 100:.2f}%")
        return self.url_model
    
    def train_text_model(self, texts, labels):
        """Train text model"""
        print("📝 Training text model...")
        
        self.vectorizer = TfidfVectorizer(max_features=200, stop_words='english')
        X = self.vectorizer.fit_transform(texts)
        
        X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)
        
        self.text_model = RandomForestClassifier(n_estimators=30, random_state=42)
        self.text_model.fit(X_train, y_train)
        
        accuracy = self.text_model.score(X_test, y_test)
        print(f"✅ Text Model Accuracy: {accuracy * 100:.2f}%")
        return self.text_model
    
    def predict_url(self, url):
        """Predict if URL is phishing"""
        if self.url_model is None:
            return 0.5
        
        features = self.extract_url_features(url)
        X = [[features[n] for n in self.feature_names]]
        proba = self.url_model.predict_proba(X)[0]
        return float(proba[1])
    
    def predict_text(self, text):
        """Predict if text is phishing"""
        if self.text_model is None or self.vectorizer is None:
            return 0.5
        
        X = self.vectorizer.transform([text])
        proba = self.text_model.predict_proba(X)[0]
        return float(proba[1])
    
    def save_models(self):
        """Save models to disk"""
        if self.url_model:
            joblib.dump(self.url_model, 'phishing_model.pkl')
        if self.text_model:
            joblib.dump(self.text_model, 'text_model.pkl')
        if self.vectorizer:
            joblib.dump(self.vectorizer, 'vectorizer.pkl')
        print("✅ Models saved")
    
    def load_models(self):
        """Load models from disk"""
        try:
            self.url_model = joblib.load('phishing_model.pkl')
            print("✅ URL Model loaded")
        except:
            print("⚠️ URL Model not found")
        
        try:
            self.text_model = joblib.load('text_model.pkl')
            print("✅ Text Model loaded")
        except:
            print("⚠️ Text Model not found")
        
        try:
            self.vectorizer = joblib.load('vectorizer.pkl')
            print("✅ Vectorizer loaded")
        except:
            print("⚠️ Vectorizer not found")

detector = PhishingDetector()
