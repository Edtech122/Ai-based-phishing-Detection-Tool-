import pandas as pd
import numpy as np
from model import detector
import warnings
warnings.filterwarnings('ignore')

def load_training_data():
    """Load training data"""
    
    urls = [
        "https://www.google.com", "https://www.facebook.com", "https://www.amazon.com",
        "https://www.youtube.com", "https://www.wikipedia.org", "https://www.reddit.com",
        "https://www.linkedin.com", "https://www.twitter.com", "https://www.instagram.com",
        "https://www.netflix.com", "https://www.microsoft.com", "https://www.apple.com",
        "https://www.paypal.com", "https://github.com", "https://stackoverflow.com",
        "https://www.spotify.com", "https://www.dropbox.com", "https://www.zoom.us",
        "https://www.adobe.com", "https://salesforce.com", "https://www.ibm.com",
        "https://www.cisco.com", "https://www.oracle.com", "https://www.intel.com",
        "https://www.nvidia.com", "https://www.amd.com", "https://www.dell.com",
        "https://www.hp.com", "https://www.lenovo.com", "https://www.asus.com",
        "http://paypal-verify-account.xyz", "http://secure-login-apple.com",
        "https://amazon-account-update.tk", "http://facebook-security-verify.ml",
        "https://netflix-account-suspended.ga", "http://apple-id-verify.cf",
        "https://bankofamerica-login.gq", "http://chase-secure-message.xyz",
        "https://paypal-verification.tk", "http://microsoft-account-alert.ml",
        "https://google-security-alert.ga", "http://instagram-verify-account.cf",
        "https://wellsfargo-online-banking.gq", "http://capitalone-secure.xyz",
        "https://update-account-now.ru", "http://secure-banking-login.net",
        "https://verify-identity.com", "http://account-security-alert.org",
        "https://confirm-payment.info", "http://login-secure-verify.xyz",
        "https://appleid-verify.com", "http://paypal-center.net",
        "https://amazon-verification.ru", "http://facebook-login-verify.xyz",
        "https://netflix-verify-account.tk", "http://microsoft-update.ml",
        "https://google-verification.ga", "http://instagram-security.cf",
        "https://bank-verification.gq", "http://secure-paypal.xyz"
    ]
    
    url_labels = [0] * 30 + [1] * 30
    
    texts = [
        "Your order has been confirmed", "Thank you for your purchase",
        "Welcome to our service", "Your account has been created",
        "Password reset request received", "Your subscription is active",
        "Payment processed successfully", "Your invoice is ready",
        "New login from recognized device", "Your profile has been updated",
        "Weekly report is available", "Your feedback is important",
        "Account verification completed", "Security update installed",
        "Your request has been approved",
        "URGENT: Your account will be suspended! Verify now",
        "Your PayPal account has been limited. Click to resolve",
        "Immediate action required: Update your billing info",
        "Security alert: Unusual login detected",
        "Your Netflix subscription has expired. Renew now",
        "Bank account verification needed. Click the link",
        "Your Apple ID has been compromised. Secure your account",
        "You've won $1000! Claim your prize today",
        "Your package cannot be delivered. Update address",
        "Wire transfer request pending approval",
        "Your credit card has been charged $500",
        "Microsoft account security alert. Verify now",
        "Your social security number has been suspended",
        "IRS: You have a pending tax refund",
        "Lottery winner! Click here to claim your prize"
    ]
    
    text_labels = [0] * 15 + [1] * 15
    
    return urls, url_labels, texts, text_labels

def main():
    print("=" * 60)
    print("🛡️ AiPhishGuard - AI Model Training")
    print("Made by Virat | India 🇮🇳 | © 2026")
    print("=" * 60)
    
    urls, url_labels, texts, text_labels = load_training_data()
    
    print(f"\n📂 URL Dataset: {len(urls)} samples")
    print(f"   Legitimate: {url_labels.count(0)}, Phishing: {url_labels.count(1)}")
    print(f"📝 Text Dataset: {len(texts)} samples")
    print(f"   Legitimate: {text_labels.count(0)}, Phishing: {text_labels.count(1)}")
    
    print("\n" + "=" * 40)
    detector.train_url_model(urls, url_labels)
    
    print("\n" + "=" * 40)
    detector.train_text_model(texts, text_labels)
    
    print("\n" + "=" * 40)
    detector.save_models()
    
    print("\n" + "=" * 40)
    print("🧪 Testing Model Predictions")
    print("=" * 40)
    
    test_cases = [
        ("https://www.google.com", "Legitimate", "url"),
        ("http://paypal-verify.xyz", "Phishing", "url"),
        ("Your order is confirmed", "Legitimate", "text"),
        ("URGENT: Verify your account now!", "Phishing", "text"),
    ]
    
    for test_input, expected, input_type in test_cases:
        if input_type == "url":
            prob = detector.predict_url(test_input)
        else:
            prob = detector.predict_text(test_input)
        
        prediction = "PHISHING" if prob > 0.5 else "SAFE"
        confidence = prob * 100 if prob > 0.5 else (1 - prob) * 100
        status = "✅" if (prediction == "PHISHING" and expected == "Phishing") or (prediction == "SAFE" and expected == "Legitimate") else "⚠️"
        
        print(f"\n{status} Input: {test_input[:50]}")
        print(f"   Expected: {expected} | Predicted: {prediction}")
        print(f"   Confidence: {confidence:.1f}%")
    
    print("\n" + "=" * 60)
    print("🎉 Training Complete! Run 'python app.py' to start the server")
    print("=" * 60)

if __name__ == "__main__":
    main()