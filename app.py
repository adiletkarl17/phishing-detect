from flask import Flask, request, render_template
import joblib
import pandas as pd
import re

# Load model
try:
    model = joblib.load("phishing_model.pkl")
except:
    model = None

# --- Extract more URL features ---
def extract_features_from_url(url):
    return pd.DataFrame([{
        "URL_Length": len(url),
        "having_At_Symbol": 1 if "@" in url else -1,
        "Prefix_Suffix": 1 if "-" in url else -1,
        "HTTPS_token": 1 if "https" not in url else -1,
        "Domain_Length": len(url.split('.')[0]),
        "Digit_Count": sum(c.isdigit() for c in url),
        "Suspicious_Words": sum(1 for word in ["login", "verify", "update", "bank", "secure"] if word in url.lower())
    }])

# --- Simple Email phishing detection heuristic ---
def simple_email_detector(email_text):
    phishing_keywords = [
        "login", "verify", "bank account", "click here", "update your information",
        "suspend", "unauthorized", "confirm", "limited access", "security alert"
    ]
    suspicious = sum(1 for word in phishing_keywords if word in email_text.lower())
    return 1 if suspicious >= 2 else 0

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    url = request.form.get('url')
    email_text = request.form.get('email')

    url_status = email_status = ""

    # Check URL
    if url:
        # Simple heuristic for safe sites
        safe_sites = ["google.com", "wikipedia.org", "facebook.com"]
        if any(site in url for site in safe_sites):
            url_status = 'Safe ✅'
        else:
            if model:
                features = extract_features_from_url(url)
                result = model.predict(features)[0]
            else:
                result = 1 if "login" in url.lower() else 0  # simple fallback
            url_status = 'Phishing ⚠️' if result == 1 else 'Safe ✅'

    # Check email
    if email_text:
        result = simple_email_detector(email_text)
        email_status = 'Phishing ⚠️' if result == 1 else 'Safe ✅'

    return render_template('index.html', url=url, url_status=url_status,
                           email_text=email_text, email_status=email_status)

if __name__ == '__main__':
    app.run(debug=True)
