from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


@dataclass(frozen=True)
class TrainConfig:
    test_size: float = 0.2
    random_state: int = 42
    max_features: int = 250_000
    ngram_min: int = 3
    ngram_max: int = 5


def _normalize_label(x) -> int:
    # Accept: -1/1, 0/1, benign/phishing/malware/defacement...
    if isinstance(x, str):
        s = x.strip().lower()
        if s in {"benign", "legitimate", "good", "safe", "0"}:
            return 1
        if s in {"phishing", "malware", "defacement", "bad", "malicious", "1"}:
            return -1
        # fallback
        return -1
    i = int(x)
    if i == 1:
        return 1
    if i == 0:
        return -1
    return 1 if i > 0 else -1


def load_urls_csv(path: Path) -> Tuple[pd.Series, pd.Series]:
    df = pd.read_csv(path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("urls.csv format: columns must be url,label")
    X = df["url"].astype(str)
    y = df["label"].apply(_normalize_label).astype(int)
    return X, y


def train_text_model(X: pd.Series, y: pd.Series, cfg: TrainConfig):
    vec = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(cfg.ngram_min, cfg.ngram_max),
        max_features=cfg.max_features,
        lowercase=True,
    )
    base = LogisticRegression(max_iter=300, class_weight="balanced", n_jobs=None)
    pipe = Pipeline([("vec", vec), ("clf", base)])

    # Calibrate probabilities (more meaningful confidence)
    calibrated = CalibratedClassifierCV(pipe, method="isotonic", cv=3)
    calibrated.fit(X, y)
    return calibrated


def main() -> int:
    p = argparse.ArgumentParser(description="Train URL text model from urls.csv")
    p.add_argument("--data", default="urls.csv", help="CSV with columns url,label")
    p.add_argument("--out", default="url_text_model.pkl", help="Output model file")
    args = p.parse_args()

    data_path = Path(args.data)
    X, y = load_urls_csv(data_path)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    cfg = TrainConfig()
    model = train_text_model(X_train, y_train, cfg)

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, digits=3)
    print(report)

    # Save training report
    out_dir = Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "url_text_report.txt").write_text(report, encoding="utf-8")

    cm = confusion_matrix(y_test, y_pred, labels=[-1, 1])
    cm_df = pd.DataFrame(cm, index=["true_-1", "true_1"], columns=["pred_-1", "pred_1"])
    cm_df.to_csv(out_dir / "url_text_confusion_matrix.csv", index=True)

    bundle: Dict[str, object] = {
        "model": model,
        "label_mapping": {"safe": 1, "bad": -1},
        "type": "url_text_model",
    }
    joblib.dump(bundle, args.out)
    print(f"OK: model kaydedildi -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

