# URL Phishing Tespit (Python)

Bu proje, `phishing.csv` veri seti ile bir `RandomForestClassifier` modeli eğitir (`model.pkl`) ve basit bir Tkinter arayüzü ile URL analizi yapar.

## Gereksinimler

Makinenizde **Python 3.10+** kurulu olmalı.

Kurulum:

```bash
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -U pip
pip install -r requirements.txt
```

## Çalıştırma

- Tek komut (önerilen):

```powershell
.\run.ps1
```

- Model eğitimi (model.pkl üretir):

```bash
py main.py
```

- Arayüz:

```bash
py gui.py
```

## Notlar

- `convert.py`, `Training Dataset.arff` dosyasını `phishing.csv`’ye dönüştürmek içindir.
- `model.pkl` yoksa `gui.py` artık hata verip çökmek yerine kullanıcıya uyarı gösterir.
- GUI analizleri `reports/history.csv` dosyasına kaydedilir.
- `Temkinli / Dengeli / Rahat` modları karar eşiğini değiştirir.

## Lokal test (zararsiz)

Modelin "güvensiz" diyebildigini gormek icin zararsiz test sayfalari vardir:

```powershell
.\.venv\Scripts\python.exe .\test_server.py
```

Sonra GUI'de su URL'leri dene:
- `http://127.0.0.1:8000/safe.html`
- `http://127.0.0.1:8000/phishy.html`

## Dataset ile URL-text model egitimi (API gerektirmez)

Bu proje opsiyonel olarak `urls.csv` (url,label) dosyasindan URL metninden ogrenebilen bir model egitebilir.

### 1) Dataset indir

- UCI PhiUSIIL (CC BY 4.0): `https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset`

### 2) urls.csv formatina cevir

```powershell
.\.venv\Scripts\python.exe .\prepare_phiusiil.py --input .\PhiUSIIL_Phishing_URL_Dataset.csv --output .\urls.csv
```

Eger egittikten sonra `google.com` gibi bilinen sitelere bile "zararli" diyorsa, label'lar ters gelmis olabilir. Bu durumda:

```powershell
.\.venv\Scripts\python.exe .\prepare_phiusiil.py --input .\PhiUSIIL_Phishing_URL_Dataset.csv --output .\urls.csv --invert-labels
```

### 3) URL-text modeli egit

```powershell
.\.venv\Scripts\python.exe .\train_url_text_model.py --data .\urls.csv --out .\url_text_model.pkl
```

`url_text_model.pkl` dosyasi varsa GUI otomatik kullanir (daha iyi genelleme).

## CLI ile tarama

GUI olmadan terminalden de tarayabilirsin:

```powershell
.\.venv\Scripts\python.exe .\scan.py --url "https://google.com" --mode Dengeli
```

JSON çıktısını dosyaya yazmak için:

```powershell
.\.venv\Scripts\python.exe .\scan.py --url "https://google.com" --mode Dengeli --out .\reports\last_scan.json
```
