from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def main() -> int:
    p = argparse.ArgumentParser(description="Convert PhiUSIIL CSV -> urls.csv")
    p.add_argument("--input", required=True, help="Path to PhiUSIIL_Phishing_URL_Dataset.csv")
    p.add_argument("--output", default="urls.csv", help="Output CSV (url,label)")
    p.add_argument(
        "--invert-labels",
        action="store_true",
        help="Some CSV variants may have inverted labels; flip if needed.",
    )
    args = p.parse_args()

    inp = Path(args.input)
    out = Path(args.output)

    df = pd.read_csv(inp)
    # UCI says: Label 1 = legitimate, 0 = phishing
    if "URL" not in df.columns or "label" not in df.columns:
        # Some variants use 'Label'
        label_col = "label" if "label" in df.columns else ("Label" if "Label" in df.columns else None)
        if label_col is None or "URL" not in df.columns:
            raise ValueError(f"Beklenen kolonlar yok. Bulunan kolonlar: {list(df.columns)[:30]}")
    else:
        label_col = "label"

    urls = df[["URL", label_col]].copy()
    urls = urls.rename(columns={"URL": "url", label_col: "label"})
    urls["label"] = urls["label"].map(lambda x: 1 if int(x) == 1 else -1)
    if args.invert_labels:
        urls["label"] = urls["label"].map(lambda y: -1 if int(y) == 1 else 1)

    urls = urls.dropna(subset=["url", "label"])
    urls["url"] = urls["url"].astype(str)

    out.parent.mkdir(parents=True, exist_ok=True)
    urls.to_csv(out, index=False)
    print(f"OK: yazildi -> {out} (rows={len(urls)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

