import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# Veriyi oku
data = pd.read_csv("phishing.csv")

FEATURE_COLS = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "DNSRecord",
    "age_of_domain",
    "Domain_registeration_length",
]


missing = [c for c in FEATURE_COLS if c not in data.columns]
if missing:
    raise ValueError(f"Eksik feature kolonlari: {missing}")

X = data[FEATURE_COLS].copy()
y = data["Result"]

# Eğitim ve test setine ayır
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Modeli oluştur ve eğit
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)


y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"Model egitildi. Basari orani: %{acc*100:.2f}")


joblib.dump({"model": model, "feature_cols": FEATURE_COLS}, "model.pkl")
print("model.pkl basariyla kaydedildi.")