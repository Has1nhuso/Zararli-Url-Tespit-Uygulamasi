import tkinter as tk
from tkinter import messagebox, ttk
from datetime import datetime
from pathlib import Path
import threading
import joblib

from features import build_features_for_url, explain_risks, heuristic_url_risk

try:
    text_bundle = joblib.load("url_text_model.pkl")
    url_text_model = text_bundle.get("model") if isinstance(text_bundle, dict) else None
except Exception:
    url_text_model = None

def _text_model_p_bad(m, url: str):
    proba_t = m.predict_proba([url])[0]
    cls_t = list(getattr(m, "classes_", []))
    if -1 in cls_t:
        return float(proba_t[cls_t.index(-1)])
    return None

def _validate_text_model(m) -> bool:
    
    try:
        pb_google = _text_model_p_bad(m, "https://google.com")
        pb_github = _text_model_p_bad(m, "https://github.com")
        if pb_google is None or pb_github is None:
            return False
        # Iki bilinen benign URL icin bile cok yuksek risk veriyorsa pp ters etiket.
        return not (pb_google > 0.85 and pb_github > 0.85)
    except Exception:
        return False

if url_text_model is not None and not _validate_text_model(url_text_model):
    url_text_model = None


try:
    bundle = joblib.load("model.pkl")
    if isinstance(bundle, dict) and "model" in bundle:
        model = bundle["model"]
        feature_cols = bundle.get("feature_cols")
    else:
        
        model = bundle
        feature_cols = None
except Exception as e:
    model = None
    feature_cols = None
    print(f"Hata: model.pkl yüklenemedi! Önce main.py çalıştırılmalı. Detay: {e}")

def extract_features(url):
    cols = feature_cols if feature_cols else []
    X, _meta, _feats = build_features_for_url(url, cols, fetch_timeout_s=8.0)
    return X


def _set_busy(is_busy: bool):
    try:
        btn.config(state=("disabled" if is_busy else "normal"))
        entry.config(state=("disabled" if is_busy else "normal"))
        mode_menu.config(state=("disabled" if is_busy else "readonly"))
    except Exception:
        pass
    if is_busy:
        sonuc_label.config(text="Analiz ediliyor...", fg="#34495e")
        detay_label.config(text="Lutfen bekleyin. (DNS/WHOIS/HTML sorgulari yapiliyor)")


def _csv(s: str) -> str:
    s = (s or "").replace('"', '""')
    return f"\"{s}\""


def _append_history(
    url: str,
    final_url: str,
    mode: str,
    threshold: float,
    status_code: int | None,
    redirects: int,
    p_bad_feature: float,
    p_bad_text: float | None,
    h_risk: float,
    p_bad_final: float,
    prediction: int,
    reasons: list[str],
):
    ts = datetime.now().isoformat(timespec="seconds")
    out_dir = Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "history.csv"
    header = (
        "timestamp,url,final_url,mode,threshold,status_code,redirects,"
        "p_bad_feature,p_bad_text,h_risk,p_bad_final,prediction,reasons\n"
    )
    line = (
        f"{ts},{_csv(url)},{_csv(final_url)},{_csv(mode)},{threshold:.2f},"
        f"{'' if status_code is None else status_code},{redirects},"
        f"{p_bad_feature:.4f},{'' if p_bad_text is None else f'{p_bad_text:.4f}'},{h_risk:.4f},{p_bad_final:.4f},"
        f"{prediction},{_csv(' | '.join(reasons[:20]))}\n"
    )
    if not path.exists():
        path.write_text(header, encoding="utf-8")
    with path.open("a", encoding="utf-8") as f:
        f.write(line)

def analiz_et():
    if model is None:
        messagebox.showerror("Hata", "Model yüklenemedi. Önce main.py ile model.pkl oluşturun.")
        return

    url = entry.get().strip()
    if not url.startswith("http"):
        messagebox.showwarning("Hata", "Lütfen geçerli bir URL girin (http:// veya https:// ile)")
        return

    cols = feature_cols if feature_cols else None
    if not cols:
        messagebox.showerror("Hata", "Model feature listesi bulunamadi. Lutfen main.py ile modeli yeniden egitin.")
        return

    mode = (threshold_var.get() or "Dengeli").strip()
    threshold = {"Temkinli": 0.40, "Dengeli": 0.50, "Rahat": 0.65}.get(mode, 0.50)

    def _run():
        try:
            root.after(0, lambda: _set_busy(True))

            X, meta, feats = build_features_for_url(url, cols, fetch_timeout_s=8.0)
            # Olasılık hesapla
            proba = model.predict_proba(X)[0]
            classes = list(getattr(model, "classes_", []))
            p_safe = float(proba[classes.index(1)]) if 1 in classes else float(max(proba))
            p_bad = float(proba[classes.index(-1)]) if -1 in classes else float(1 - p_safe)

            # URL-text model (opsiyonel)
            p_bad_text = None
            if url_text_model is not None:
                try:
                    p_bad_text = _text_model_p_bad(url_text_model, url)
                except Exception:
                    p_bad_text = None

            # Heuristic risk
            h_risk, h_reasons = heuristic_url_risk(url, meta)

            p_bad_ml = p_bad
            if p_bad_text is not None:
                p_bad_ml = 0.60 * p_bad_text + 0.40 * p_bad

            p_bad_final = 1.0 - (1.0 - p_bad_ml) * (1.0 - h_risk)
            p_safe_final = 1.0 - p_bad_final
            tahmin_final = -1 if p_bad_final >= threshold else 1
            oran = (p_bad_final if tahmin_final == -1 else p_safe_final) * 100

            reasons = explain_risks(feats)
            net = meta.final_url
            tech = []
            if meta.status_code is not None:
                tech.append(f"HTTP {meta.status_code}")
            if meta.num_redirects:
                tech.append(f"redirect: {meta.num_redirects}")
            if meta.error:
                tech.append("baglanti: basarisiz")
            if meta.html is None and meta.error is None:
                tech.append("html: yok")

            detay = [f"Mod: {mode} (threshold={threshold:.2f})"]
            if tech:
                detay.append(" / ".join(tech) + (f"\nSon URL: {net}" if net and net != url else ""))
            if reasons:
                detay.append("ML risk sinyalleri: " + ", ".join(reasons[:8]) + ("..." if len(reasons) > 8 else ""))
            if h_reasons:
                detay.append("Heuristic sinyaller: " + ", ".join(h_reasons[:6]) + ("..." if len(h_reasons) > 6 else ""))
            if p_bad_text is not None:
                detay.append(
                    f"Skor (feature p_bad): {p_bad:.2f} | (text p_bad): {p_bad_text:.2f} | (final p_bad): {p_bad_final:.2f}"
                )
            else:
                detay.append(f"Skor (model p_bad): {p_bad:.2f} | (final p_bad): {p_bad_final:.2f}")

            _append_history(
                url=url,
                final_url=net,
                mode=mode,
                threshold=threshold,
                status_code=meta.status_code,
                redirects=meta.num_redirects,
                p_bad_feature=p_bad,
                p_bad_text=p_bad_text,
                h_risk=h_risk,
                p_bad_final=p_bad_final,
                prediction=tahmin_final,
                reasons=reasons + h_reasons,
            )

            def _update_ui():
                if tahmin_final == -1:
                    sonuc_label.config(text=f"⚠️ ZARARLI URL! (Güven: %{oran:.1f})", fg="#e74c3c")
                else:
                    sonuc_label.config(text=f"✅ GÜVENLİ URL. (Güven: %{oran:.1f})", fg="#2ecc71")
                detay_label.config(text="\n".join(detay) if detay else "")

            root.after(0, _update_ui)
        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Hata", f"Analiz sirasinda hata: {e}"))
        finally:
            root.after(0, lambda: _set_busy(False))

    threading.Thread(target=_run, daemon=True).start()

if __name__ == "__main__":
    # --- GUI  ---
    root = tk.Tk()
    root.title("Yapay Zeka Destekli URL Analizi")
    root.geometry("500x300")
    root.configure(bg="#f0f2f5")

    tk.Label(root, text="Zararlı URL Tespit Sistemi", font=("Arial", 16, "bold"), bg="#f0f2f5").pack(pady=20)
    entry = tk.Entry(root, width=50, font=("Arial", 12))
    entry.pack(pady=10)
    entry.insert(0, "https://")

    threshold_var = tk.StringVar(value="Dengeli")
    mode_menu = ttk.Combobox(
        root,
        textvariable=threshold_var,
        values=["Temkinli", "Dengeli", "Rahat"],
        state="readonly",
        width=14,
    )
    mode_menu.pack(pady=5)

    btn = tk.Button(root, text="URL'yi Analiz Et", command=analiz_et, bg="#3498db", fg="white", font=("Arial", 10, "bold"), padx=20, pady=10)
    btn.pack(pady=20)

    sonuc_label = tk.Label(root, text="Sonuç burada görünecek", font=("Arial", 12), bg="#f0f2f5")
    sonuc_label.pack()

    detay_label = tk.Label(root, text="", font=("Arial", 10), bg="#f0f2f5", fg="#34495e", justify="left", wraplength=460)
    detay_label.pack(pady=10)

    root.mainloop()