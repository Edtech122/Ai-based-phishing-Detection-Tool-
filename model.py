import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import joblib
import warnings
warnings.filterwarnings('ignore')

class PhishingDetector:
    """Advanced AI Model for Phishing Detection"""
    
    def __init__(self):
        self.url_model = None
        self.text_model = None
        self.vectorizer = None
        self.feature_names = [
            'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_question_marks',
            'num_equal_signs', 'num_at_symbols', 'has_https', 'has_ip', 
            'suspicious_keyword_count', 'subdomain_count', 'digit_count', 'letter_count',
            'special_char_ratio', 'entropy'
        ]
    
    def extract_url_features(self, url):
        """Extract all features from URL"""
        features = {}
        
        features['url_length'] = min(len(url), 1000)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_symbols'] = url.count('@')
        features['has_https'] = 1 if url.startswith('https') else 0
        
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
        
        suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 
                              'confirm', 'banking', 'paypal', 'apple', 'microsoft', 'amazon']
        features['suspicious_keyword_count'] = sum(1 for kw in suspicious_keywords if kw in url.lower())
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            parts = hostname.split('.')
            features['subdomain_count'] = max(0, len(parts) - 2)
        except:
            features['subdomain_count'] = 0
        
        features['digit_count'] = sum(c.isdigit() for c in url)
        features['letter_count'] = sum(c.isalpha() for c in url)
        
        special_chars = sum(c in '!@#$%^&*()_+-=[]{}|;:\'",.<>/?`~' for c in url)
        features['special_char_ratio'] = special_chars / max(len(url), 1)
        
        if url:
            freq = Counter(url)
            probs = [freq[c]/len(url) for c in freq]
            features['entropy'] = -sum(p * np.log2(p) for p in probs)
        else:
            features['entropy'] = 0
        
        return features
    
    def extract_text_features(self, text):
        """Extract features from email/SMS text"""
        text_lower = text.lower()
        features = {}
        
        features['length'] = min(len(text), 1000)
        features['word_count'] = len(text.split())
        
        urgency_words = ['urgent', 'immediate', 'now', 'today', 'asap', 'limited', 'expires']
        features['urgency_score'] = sum(1 for w in urgency_words if w in text_lower)
        
        fear_words = ['suspended', 'closed', 'blocked', 'locked', 'compromised', 'warning']
        features['fear_score'] = sum(1 for w in fear_words if w in text_lower)
        
        scam_words = ['click here', 'verify your account', 'confirm your', 'update your', 'win', 'prize']
        features['scam_score'] = sum(1 for s in scam_words if s in text_lower)
        
        credential_words = ['password', 'username', 'login', 'verify', 'account', 'credit card', 'ssn']
        features['credential_score'] = sum(1 for c in credential_words if c in text_lower)
        
        url_pattern = r'https?://[^\s]+'
        features['url_count'] = len(re.findall(url_pattern, text))
        
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        
        caps = sum(1 for c in text if c.isupper())
        features['caps_ratio'] = caps / max(len(text), 1)
        
        return features
    
    def train_url_model(self, urls, labels):
        """Train URL classification model"""
        print("📊 Training URL classification model...")
        
        features_list = []
        for i, url in enumerate(urls):
            features_list.append(self.extract_url_features(url))
            if (i + 1) % 10 == 0:
                print(f"   Processed {i + 1}/{len(urls)} URLs")
        
        X = pd.DataFrame(features_list)
        y = np.array(labels)
        
        for col in self.feature_names:
            if col not in X.columns:
                X[col] = 0
        
        X = X[self.feature_names]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.url_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.url_model.fit(X_train, y_train)
        
        accuracy = self.url_model.score(X_test, y_test)
        print(f"✅ URL Model Accuracy: {accuracy * 100:.2f}%")
        return self.url_model
    
    def train_text_model(self, texts, labels):
        """Train text classification model"""
        print("📝 Training text classification model...")
        
        self.vectorizer = TfidfVectorizer(max_features=500, stop_words='english')
        X = self.vectorizer.fit_transform(texts)
        y = np.array(labels)
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.text_model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.text_model.fit(X_train, y_train)
        
        accuracy = self.text_model.score(X_test, y_test)
        print(f"✅ Text Model Accuracy: {accuracy * 100:.2f}%")
        return self.text_model
    
    def predict_url(self, url):
        """Predict if URL is phishing"""
        if self.url_model is None:
            return 0.5
        
        features = self.extract_url_features(url)
        X = pd.DataFrame([features])
        
        for col in self.feature_names:
            if col not in X.columns:
                X[col] = 0
        
        X = X[self.feature_names]
        proba = self.url_model.predict_proba(X)[0]
        return proba[1]
    
    def predict_text(self, text):
        """Predict if text is phishing"""
        if self.text_model is None or self.vectorizer is None:
            return 0.5
        
        X = self.vectorizer.transform([text])
        proba = self.text_model.predict_proba(X)[0]
        return proba[1]
    
    def save_models(self):
        """Save models to disk"""
        if self.url_model:
            joblib.dump(self.url_model, 'phishing_model.pkl')
        if self.text_model:
            joblib.dump(self.text_model, 'text_model.pkl')
        if self.vectorizer:
            joblib.dump(self.vectorizer, 'vectorizer.pkl')
        print("✅ Models saved successfully")
    
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