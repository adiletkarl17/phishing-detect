import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Загружаем данные
df = pd.read_csv("phishing.csv")

# Преобразуем существующие столбцы в новые признаки
df["Domain_Length"] = df["URL_Length"]
df["Digit_Count"] = df["URL_Length"].apply(lambda x: sum(c.isdigit() for c in str(x)))
df["Suspicious_Words"] = df["URL_of_Anchor"].apply(lambda x: sum(1 for word in ["login", "verify", "update", "bank", "secure", "account", "confirm"] if word in str(x).lower()))

# Указываем признаки для обучения
feature_columns = [
    "URL_Length", "Shortining_Service", "having_At_Symbol", "double_slash_redirecting",
    "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State", "Domain_registeration_length",
    "Favicon", "port", "HTTPS_token", "Request_URL", "URL_of_Anchor", "Links_in_tags",
    "SFH", "Submitting_to_email", "Abnormal_URL", "Redirect", "on_mouseover", "RightClick",
    "popUpWidnow", "Iframe", "age_of_domain", "DNSRecord", "web_traffic", "Page_Rank",
    "Google_Index", "Links_pointing_to_page", "Statistical_report"
]

# Определяем признаки и результат
X = df[feature_columns]
y = df["Result"]

# Разделяем данные на обучающую и тестовую выборки
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Создаем и обучаем модель
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Оцениваем модель
print(f"Accuracy: {model.score(X_test, y_test)}")

# Сохраняем модель и список признаков
joblib.dump((model, feature_columns), "phishing_model.pkl")

