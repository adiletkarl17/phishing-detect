import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Загрузка датасета
df = pd.read_csv("phishing.csv")

# ⚠️ Используем только эти признаки:
features = ["URL_Length", "having_At_Symbol", "Prefix_Suffix", "HTTPS_token"]

# Выделим признаки и цель
X = df[features]
y = df["Result"]

# Разделим на обучение и тест
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Обучим модель
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Сохраним модель
joblib.dump(model, "phishing_model.pkl")

print("✅ Модель переобучена и сохранена как phishing_model.pkl")
