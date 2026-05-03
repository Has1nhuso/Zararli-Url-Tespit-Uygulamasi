from scipy.io import arff
import pandas as pd

# ARFF dosyasını yükle
data = arff.loadarff("Training Dataset.arff")
df = pd.DataFrame(data[0])

# Byte formatındaki verileri (b'-1' gibi) temizle ve sayıya çevir
for col in df.columns:
    if df[col].dtype == object:
        df[col] = df[col].apply(lambda v: v.decode("utf-8", errors="ignore") if isinstance(v, (bytes, bytearray)) else v)
    df[col] = pd.to_numeric(df[col], errors="coerce")

# Eğer bazı hücreler sayıya çevrilemediyse, CSV'yi bozmasın diye 0 ile doldur
df = df.fillna(0)

df.to_csv("phishing.csv", index=False)
print("phishing.csv basariyla olusturuldu ve temizlendi.")