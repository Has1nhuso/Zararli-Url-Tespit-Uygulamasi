from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import joblib

from features import build_features_for_url, explain_risks, heuristic_url_risk


@dataclass
class ScanResult:
    url: str
    final_url: str
    status_code: Optional[int]
    redirects: int
    prediction: int
    p_bad_final: float
    p_bad_feature: float
    p_bad_text: Optional[float]
    h_risk: float
    reasons: list[str]


def _load_feature_model() -> tuple[Any, list[str]]:
    bundle = joblib.load("model.pkl")
    if isinstance(bundle, dict) and "model" in bundle:
        return bundle["model"], bundle.get("feature_cols") or []
    raise ValueError("model.pkl format gecersiz. main.py ile tekrar egitin.")


def _load_text_model() -> Any | None:
    try:
        tb = joblib.load("url_text_model.pkl")
        return tb.get("model") if isinstance(tb, dict) else None
    except Exception:
        return None


def _text_p_bad(m, url: str) -> Optional[float]:
    try:
        proba = m.predict_proba([url])[0]
        cls = list(getattr(m, "classes_", []))
        if -1 in cls:
            return float(proba[cls.index(-1)])
        return None
    except Exception:
        return None


def scan_one(url: str, mode: str = "Dengeli") -> ScanResult:
    fm, cols = _load_feature_model()
    tm = _load_text_model()

    threshold = {"Temkinli": 0.40, "Dengeli": 0.50, "Rahat": 0.65}.get(mode, 0.50)

    X, meta, feats = build_features_for_url(url, cols, fetch_timeout_s=8.0)
    proba = fm.predict_proba(X)[0]
    classes = list(getattr(fm, "classes_", []))
    p_bad = float(proba[classes.index(-1)]) if -1 in classes else 1.0 - float(max(proba))

    p_bad_text = _text_p_bad(tm, url) if tm is not None else None
    p_bad_ml = p_bad if p_bad_text is None else (0.60 * p_bad_text + 0.40 * p_bad)

    h_risk, h_reasons = heuristic_url_risk(url, meta)
    p_bad_final = 1.0 - (1.0 - p_bad_ml) * (1.0 - h_risk)
    pred = -1 if p_bad_final >= threshold else 1

    reasons = explain_risks(feats) + h_reasons

    return ScanResult(
        url=url,
        final_url=meta.final_url,
        status_code=meta.status_code,
        redirects=meta.num_redirects,
        prediction=pred,
        p_bad_final=p_bad_final,
        p_bad_feature=p_bad,
        p_bad_text=p_bad_text,
        h_risk=h_risk,
        reasons=reasons,
    )


def main() -> int:
    p = argparse.ArgumentParser(description="Scan a URL (CLI)")
    p.add_argument("--url", required=True)
    p.add_argument("--mode", default="Dengeli", choices=["Temkinli", "Dengeli", "Rahat"])
    p.add_argument("--out", default="", help="Write JSON output to file")
    args = p.parse_args()

    res = scan_one(args.url, mode=args.mode)
    payload: Dict[str, Any] = asdict(res)

    text = json.dumps(payload, ensure_ascii=False, indent=2)
    print(text)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

