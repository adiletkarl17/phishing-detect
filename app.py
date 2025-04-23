from flask import Flask, request, render_template
import joblib
import pandas as pd

# Load the trained model and feature columns
try:
    model, feature_columns = joblib.load("phishing_model.pkl")
except Exception as e:
    print(f"Model loading error: {e}")
    model = None
    feature_columns = []

# Function to extract features from a URL
# Function to extract features from a URL
def extract_url_features(url):
    features = {
        "URL_Length": len(url),
        "having_At_Symbol": 1 if "@" in url else -1,
        "Prefix_Suffix": 1 if "-" in url else -1,
        "HTTPS_token": 1 if "https" in url else -1,  # Уже считается фишинговым, если HTTPS нет
        "Domain_Length": len(url.split('.')[0]) if '.' in url else 0,
        "Digit_Count": sum(c.isdigit() for c in url),
        "Suspicious_Words": sum(1 for word in ["login", "verify", "update", "bank", "secure", "account", "login", "confirm", "suspend", "unauthorized", "clickhere", "security"] if word in url.lower()),
        "Shortining_Service": 1 if "bit.ly" in url or "goo.gl" in url else -1,  # Пример для URL-менеджеров
        "double_slash_redirecting": 1 if url.count("//") > 1 else -1,  # Проверка на лишние слэши в URL
        "having_Sub_Domain": 1 if len(url.split(".")) > 2 else -1,  # Проверка на поддомен
        "SSLfinal_State": 1 if "https" in url else -1,  # Протокол SSL (https) отсутствует, считается фишингом
        "Domain_registeration_length": 10,  # Статический пример
        "Favicon": 1 if "favicon.ico" in url else -1,  # Проверка на favicon
        "port": 1 if ":" in url else -1,  # Проверка на указание порта в URL
        "Request_URL": 1 if "request" in url else -1,  # Пример признака
        "URL_of_Anchor": 1 if "anchor" in url else -1,  # Похожая проверка
        "Links_in_tags": 1 if "<a href=" in url else -1,  # Проверка на наличие тегов <a> в URL
        "SFH": 1 if "action" in url else -1,  # Другой пример признака
        "Submitting_to_email": 1 if "email" in url else -1,  # Проверка на отправку на email
        "Abnormal_URL": 1 if len(url.split(".")) > 3 else -1,  # Аномальные URL, обычно имеют более 3 частей
        "Redirect": 1 if "redirect" in url else -1,  # Проверка на редирект
        "on_mouseover": 1 if "mouseover" in url else -1,  # Проверка на событие mouseover
        "RightClick": 1 if "rightclick" in url else -1,  # Проверка на правый клик
        "popUpWidnow": 1 if "popup" in url else -1,  # Проверка на всплывающее окно
        "Iframe": 1 if "iframe" in url else -1,  # Проверка на iframe
        "age_of_domain": 5,  # Статическая информация, может быть динамической
        "DNSRecord": 1 if "dns" in url else -1,  # Проверка на DNS-записи
        "web_traffic": 1000,  # Пример статического признака, основанного на трафике
        "Page_Rank": 10,  # Статическое значение
        "Google_Index": 1 if "google" in url else -1,  # Проверка на индексацию в Google
        "Links_pointing_to_page": 5,  # Статическое значение
        "Statistical_report": 1 if "stats" in url else -1  # Статический признак
    }

    if "http://" in url and "https://" not in url:
        features["HTTPS_token"] = -1  # Marking it as phishing

    print(f"Extracted features: {features}")  # Logging the extracted features for debugging
    return pd.DataFrame([features])




# Simple email phishing detection using keyword matching
def detect_phishing_email(email_text):
    phishing_keywords = [
        "login", "verify", "bank account", "click here", "update your information",
        "suspend", "unauthorized", "confirm", "limited access", "security alert", 
        "urgent", "important", "payment", "invoice", "account suspension", 
        "password reset", "you won a prize", "confirm your account", "reward claim"
    ]
    suspicious_count = sum(1 for word in phishing_keywords if word in email_text.lower())
    return 1 if suspicious_count >= 2 else 0

# Initialize Flask app
app = Flask(__name__)

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# URL and email phishing detection route
@app.route('/check', methods=['POST'])
def check_url():
    url = request.form.get('url')
    email_text = request.form.get('email')

    url_status = email_status = ""

    # URL analysis
    if url:
        safe_domains = ["google.com", "wikipedia.org", "facebook.com"]
        if any(domain in url for domain in safe_domains):
            url_status = 'Safe ✅'
        else:
            if model:
                try:
                    # Extract features from URL and ensure correct order
                    features = extract_url_features(url)
                    features = features[feature_columns]  # Ensure correct feature order
                    print(f"Features for prediction: {features}")  # Log features before prediction
                    prediction = model.predict(features)[0]
                    url_status = 'Phishing ⚠️' if prediction == 1 else 'Safe ✅'
                except Exception as e:
                    print(f"Prediction error: {e}")
                    url_status = f'Error: {e}'  # Show detailed error message instead of default to phishing
            else:
                url_status = 'Model not loaded or error'  # In case the model is not loaded

    # Email analysis
    if email_text:
        prediction = detect_phishing_email(email_text)
        email_status = 'Phishing ⚠️' if prediction == 1 else 'Safe ✅'

    return render_template('index.html',
                           url=url, url_status=url_status,
                           email_text=email_text, email_status=email_status)

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
