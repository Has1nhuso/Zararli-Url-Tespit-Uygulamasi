from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
import unicodedata
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import re
import socket
import ssl

import pandas as pd
import requests
from bs4 import BeautifulSoup

import tldextract

try:
    import dns.resolver  # type: ignore
except Exception:  # pragma: no cover
    dns = None  # type: ignore

try:
    import whois  # type: ignore
except Exception:  # pragma: no cover
    whois = None  # type: ignore

SHORTENERS = ("bit.ly", "goo.gl", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy")

SUSPICIOUS_TLDS = {
    "info",
    "xyz",
    "top",
    "click",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
    "work",
    "vip",
    "live",
    "rest",
    "support",
    "review",
}

SUSPICIOUS_TOKENS = (
    "login",
    "secure",
    "verify",
    "verification",
    "update",
    "account",
    "signin",
    "payment",
    "bank",
    "paypal",
)

BRAND_DOMAINS = {
    
    "ziraat": {"ziraatbank.com.tr", "ziraatbankasi.com.tr"},
    "isbank": {"isbank.com.tr", "isbankasi.com.tr"},
    "akbank": {"akbank.com", "akbank.com.tr"},
    "garanti": {"garantibbva.com.tr", "garantibbva.com"},
    "yapikredi": {"yapikredi.com.tr"},
    "halkbank": {"halkbank.com.tr"},
    "vakifbank": {"vakifbank.com.tr"},
    "paypal": {"paypal.com"},
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
}


HOMOGLYPH_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
}


@dataclass(frozen=True)
class FetchMeta:
    final_url: str
    status_code: Optional[int]
    num_redirects: int
    html: Optional[str]
    error: Optional[str]


def _safe_int(x: object) -> Optional[int]:
    try:
        return int(x)  # type: ignore[arg-type]
    except Exception:
        return None


@lru_cache(maxsize=512)
def fetch_url(url: str, timeout_s: float = 8.0) -> FetchMeta:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/123.0.0.0 Safari/537.36"
        )
    }
    try:
        r = requests.get(url, headers=headers, timeout=timeout_s, allow_redirects=True)
        ct = (r.headers.get("Content-Type") or "").lower()
        html = r.text if "text/html" in ct or ct == "" else None
        return FetchMeta(
            final_url=str(r.url),
            status_code=_safe_int(r.status_code),
            num_redirects=len(getattr(r, "history", []) or []),
            html=html,
            error=None,
        )
    except Exception as e:
        return FetchMeta(final_url=url, status_code=None, num_redirects=0, html=None, error=str(e))


@lru_cache(maxsize=512)
def fetch_url_chain(url: str, timeout_s: float = 8.0) -> Tuple[str, int, Tuple[str, ...], Optional[int], Optional[str]]:
    """
    Returns: final_url, num_redirects, chain_urls, status_code, error
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/123.0.0.0 Safari/537.36"
        )
    }
    try:
        r = requests.get(url, headers=headers, timeout=timeout_s, allow_redirects=True)
        chain = tuple(str(x.url) for x in (getattr(r, "history", []) or [])) + (str(r.url),)
        return str(r.url), len(getattr(r, "history", []) or []), chain, _safe_int(r.status_code), None
    except Exception as e:
        return url, 0, (url,), None, str(e)


def _registered_domain(host: str) -> str:
    ex = tldextract.extract(host)
    if ex.domain and ex.suffix:
        return f"{ex.domain}.{ex.suffix}".lower()
    return host.lower()


def _host_no_port(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.netloc or "").split("@")[-1]
    return host.split(":")[0].lower()


def _is_official_domain(reg_domain: str, host: str, official: set[str]) -> bool:
    reg_domain = (reg_domain or "").lower()
    host = (host or "").lower()
    for d in official:
        d = d.lower()
        if reg_domain == d or host == d or host.endswith("." + d):
            return True
    return False


def _normalize_host_for_lookalike(host: str) -> str:
    host = (host or "").lower()
    host = unicodedata.normalize("NFKC", host)
    # strip punycode marker but keep the rest for rough matching
    host = host.replace("xn--", "")
    for k, v in HOMOGLYPH_MAP.items():
        host = host.replace(k, v)
    return host


def _levenshtein(a: str, b: str, max_dist: int = 3) -> int:
    # Small bounded Levenshtein for short strings (early exit).
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        min_row = cur[0]
        for j, cb in enumerate(b, 1):
            ins = cur[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            val = min(ins, dele, sub)
            cur.append(val)
            if val < min_row:
                min_row = val
        prev = cur
        if min_row > max_dist:
            return max_dist + 1
    return prev[-1]


def lookalike_brand_risk(host_no_port: str) -> Tuple[float, List[str]]:
    """
    Detects typosquatting/homoglyphs against known brand domains.
    Returns (risk, reasons).
    """
    reasons: List[str] = []
    risk = 0.0
    host_n = _normalize_host_for_lookalike(host_no_port)
    reg = _registered_domain(host_n)

    for brand, official in BRAND_DOMAINS.items():
        for off in official:
            off_n = _normalize_host_for_lookalike(off)
            off_reg = _registered_domain(off_n)
            d = _levenshtein(reg, off_reg, max_dist=2)
            if 0 < d <= 2 and brand not in reg:
                risk = max(risk, 0.25 + 0.05 * (2 - d))
                reasons.append(f"lookalike domain: {reg} ~ {off_reg}")
                return min(0.35, risk), reasons
    return risk, reasons


def heuristic_url_risk(url: str, meta: Optional[FetchMeta] = None) -> Tuple[float, List[str]]:
    """
    ML modelini tamamlayan kural-tabanli risk skoru (0..0.9).
    Bu katman; kisaltilmis link, supheli TLD, asiri subdomain, phishing kelimeleri gibi
    bariz sinyallerde modeli "daha temkinli" yapar.
    """
    parsed = urlparse(url)
    host = (parsed.netloc or "").split("@")[-1]
    host_no_port = host.split(":")[0].lower()

    ex = tldextract.extract(host_no_port)
    suffix = (ex.suffix or "").lower()

    score = 0.0
    reasons: List[str] = []

   
    if any(host_no_port == s or host_no_port.endswith("." + s) for s in SHORTENERS):
        score += 0.30
        reasons.append("kisaltilmis link (shortener)")

   
    if suffix in SUSPICIOUS_TLDS:
        score += 0.25
        reasons.append(f"supheli TLD: .{suffix}")

    dots = host_no_port.count(".")
    if dots >= 4:
        score += 0.20
        reasons.append("asiri subdomain / uzun host")

    if "xn--" in host_no_port:
        score += 0.25
        reasons.append("punycode (xn--)")

  
    hay = (host_no_port + (parsed.path or "") + "?" + (parsed.query or "")).lower()
    token_hits = [t for t in SUSPICIOUS_TOKENS if t in hay]
    if token_hits:
        score += min(0.25, 0.05 * len(set(token_hits)))
        reasons.append("phishing anahtar kelimeleri: " + ", ".join(sorted(set(token_hits))[:6]))

    
    if meta and meta.num_redirects >= 2:
        score += 0.10
        reasons.append(f"redirect sayisi: {meta.num_redirects}")

 
    if meta and meta.error:
        score += 0.10
        reasons.append("baglanti hatasi (temkinli)")

    reg = _registered_domain(host_no_port)
    for brand, official in BRAND_DOMAINS.items():
        if brand in hay:
            if not _is_official_domain(reg, host_no_port, official):
                score += 0.35
                reasons.append(f"marka taklidi: {brand} (resmi domain degil)")
            else:
                
                score -= 0.10
            break


    lk_risk, lk_reasons = lookalike_brand_risk(host_no_port)
    if lk_risk:
        score += lk_risk
        reasons.extend(lk_reasons)


    if meta:
        try:
            final_host = _host_no_port(meta.final_url)
            reg0 = _registered_domain(host_no_port)
            regf = _registered_domain(final_host)
            if reg0 and regf and reg0 != regf:
                score += 0.10
                reasons.append(f"domain degisimi (redirect): {reg0} -> {regf}")
        except Exception:
            pass

    score = max(0.0, min(0.90, score))
    return score, reasons


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _first_date(value: object) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (list, tuple)):
        for v in value:
            d = _first_date(v)
            if d:
                return d
        return None
    return None


def _days_between(a: datetime, b: datetime) -> float:
    return (a - b).total_seconds() / 86400.0


def extract_dns_whois_tls_features(url: str, timeout_s: float = 4.0) -> Dict[str, float]:
    """
    Gercek dunyada ayirt ediciligi yuksek sinyaller.
    API anahtari gerektirmez; DNS/WHOIS/TLS'yi yerel olarak sorgular.
    Hata olursa 0 (bilinmiyor) dondurur.
    """
    host_no_port = _host_no_port(url)
    reg = _registered_domain(host_no_port)

    feats: Dict[str, float] = {}

    feats["DNSRecord"] = _dns_record_feature(host_no_port)

    
    feats["age_of_domain"] = 0
    feats["Domain_registeration_length"] = 0
    age_feat, reglen_feat = _whois_age_features(reg)
    if age_feat is not None:
        feats["age_of_domain"] = age_feat
    if reglen_feat is not None:
        feats["Domain_registeration_length"] = reglen_feat

    # TLS certificate: HTTPS ise sertifika suresi / CN uyumu
    feats["TLS_validity"] = 0
    feats["TLS_mismatch"] = 0
    parsed = urlparse(url)
    if parsed.scheme == "https" and host_no_port:
        feats["TLS_validity"] = _tls_validity_feature(host_no_port, timeout_s=timeout_s)

    return feats


@lru_cache(maxsize=2048)
def _dns_record_feature(host_no_port: str) -> float:
    if not host_no_port:
        return 0.0
    try:
        socket.getaddrinfo(host_no_port, None)
        return 1.0
    except Exception:
        return -1.0


@lru_cache(maxsize=1024)
def _whois_age_features(reg_domain: str) -> Tuple[Optional[float], Optional[float]]:
    if whois is None or not reg_domain:
        return None, None
    try:
        w = whois.whois(reg_domain)  # type: ignore[misc]
        created = _first_date(getattr(w, "creation_date", None))
        expires = _first_date(getattr(w, "expiration_date", None))
        now = _now_utc()
        age_feat = None
        reglen_feat = None
        if created:
            age_days = _days_between(now, created)
            age_feat = 1.0 if age_days >= 180 else -1.0
        if created and expires:
            length_days = _days_between(expires, created)
            reglen_feat = 1.0 if length_days >= 365 else -1.0
        return age_feat, reglen_feat
    except Exception:
        return None, None


@lru_cache(maxsize=1024)
def _tls_validity_feature(host_no_port: str, timeout_s: float = 4.0) -> float:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host_no_port, 443), timeout=timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=host_no_port) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not not_after:
            return 0.0
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = _days_between(exp, _now_utc())
        return 1.0 if days_left >= 30 else -1.0
    except Exception:
        return 0.0


def extract_url_only_features(url: str) -> Dict[str, float]:
    parsed = urlparse(url)
    host = parsed.netloc or ""
    host_no_port = host.split("@")[-1].split(":")[0]
    path = parsed.path or "/"

    feats: Dict[str, float] = {}

    feats["having_IP_Address"] = -1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host_no_port) else 1
    feats["URL_Length"] = 1 if len(url) < 54 else (0 if len(url) <= 75 else -1)
    feats["Shortining_Service"] = -1 if any(s in url for s in SHORTENERS) else 1
    feats["having_At_Symbol"] = -1 if "@" in url else 1
    feats["double_slash_redirecting"] = -1 if url.rfind("//") > 7 else 1
    feats["Prefix_Suffix"] = -1 if "-" in host_no_port else 1

    dots = host_no_port.count(".")
    feats["having_Sub_Domain"] = 1 if dots <= 1 else (0 if dots == 2 else -1)

    feats["SSLfinal_State"] = 1 if parsed.scheme == "https" else -1

    # port
    if ":" in host.split("@")[-1]:
        try:
            p = int(host.split(":")[-1])
            feats["port"] = 1 if p in (80, 443) else -1
        except ValueError:
            feats["port"] = -1
    else:
        feats["port"] = 1

    feats["HTTPS_token"] = -1 if "https" in host_no_port.lower() else 1

   
    feats["SFH"] = 0

    feats["Submitting_to_email"] = 0
    feats["Iframe"] = 0
    feats["on_mouseover"] = 0
    feats["RightClick"] = 0
    feats["popUpWidnow"] = 0
    feats["Redirect"] = 0
    feats["Request_URL"] = 0
    feats["URL_of_Anchor"] = 0
    feats["Links_in_tags"] = 0
    feats["Favicon"] = 0
    feats["Abnormal_URL"] = 0
    feats["DNSRecord"] = 0
    feats["age_of_domain"] = 0
    feats["Domain_registeration_length"] = 0
    feats["TLS_validity"] = 0
    feats["TLS_mismatch"] = 0

    feats["Abnormal_URL"] = -1 if "//" in host_no_port else 1

    _ = path
    return feats


def _domain(host: str) -> str:
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def extract_html_features(base_url: str, final_url: str, html: str, redirects: int) -> Dict[str, float]:
    feats: Dict[str, float] = {}

    base_parsed = urlparse(final_url or base_url)
    host = (base_parsed.netloc or "").split("@")[-1]
    host_no_port = host.split(":")[0]
    dom = _domain(host_no_port.lower())

    soup = BeautifulSoup(html, "lxml")

    feats["Redirect"] = 1 if redirects <= 1 else (-1 if redirects >= 3 else 0)

    # Iframe
    feats["Iframe"] = -1 if soup.find("iframe") is not None else 1

    html_lower = html.lower()
    feats["on_mouseover"] = -1 if "onmouseover" in html_lower else 1
    feats["RightClick"] = -1 if "event.button==2" in html_lower or "contextmenu" in html_lower else 1
    feats["popUpWidnow"] = -1 if "window.open" in html_lower else 1

    feats["Submitting_to_email"] = -1 if ("mailto:" in html_lower or "mail(" in html_lower) else 1

   
    icon = soup.find("link", rel=lambda v: v and "icon" in str(v).lower())
    if icon and icon.get("href"):
        href = str(icon.get("href"))
        abs_href = urljoin(final_url or base_url, href)
        fav_host = (urlparse(abs_href).netloc or "").split("@")[-1].split(":")[0].lower()
        feats["Favicon"] = 1 if _domain(fav_host) == dom else -1
    else:
        feats["Favicon"] = 0

    media = soup.find_all(["img", "video", "audio", "source"])
    ext = 0
    total = 0
    for tag in media:
        src = tag.get("src")
        if not src:
            continue
        total += 1
        abs_src = urljoin(final_url or base_url, str(src))
        h = (urlparse(abs_src).netloc or "").split("@")[-1].split(":")[0].lower()
        if h and _domain(h) != dom:
            ext += 1
    if total == 0:
        feats["Request_URL"] = 0
    else:
        ratio = ext / total
        feats["Request_URL"] = 1 if ratio < 0.22 else (0 if ratio <= 0.61 else -1)

    anchors = soup.find_all("a")
    bad = 0
    a_total = 0
    for a in anchors:
        href = a.get("href")
        if href is None:
            continue
        href_s = str(href).strip()
        if href_s == "":
            continue
        a_total += 1
        low = href_s.lower()
        if low.startswith(("javascript:", "mailto:")) or low in ("#", "#content", "#skip"):
            bad += 1
            continue
        abs_href = urljoin(final_url or base_url, href_s)
        h = (urlparse(abs_href).netloc or "").split("@")[-1].split(":")[0].lower()
        if h and _domain(h) != dom:
            bad += 1
    if a_total == 0:
        feats["URL_of_Anchor"] = 0
    else:
        ratio = bad / a_total
        feats["URL_of_Anchor"] = 1 if ratio < 0.31 else (0 if ratio <= 0.67 else -1)

    tags = soup.find_all(["meta", "script", "link"])
    ext2 = 0
    tot2 = 0
    for t in tags:
        val = t.get("content") or t.get("src") or t.get("href")
        if not val:
            continue
        tot2 += 1
        abs_u = urljoin(final_url or base_url, str(val))
        h = (urlparse(abs_u).netloc or "").split("@")[-1].split(":")[0].lower()
        if h and _domain(h) != dom:
            ext2 += 1
    if tot2 == 0:
        feats["Links_in_tags"] = 0
    else:
        ratio = ext2 / tot2
        feats["Links_in_tags"] = 1 if ratio < 0.17 else (0 if ratio <= 0.81 else -1)

    # SFH: form handler
    forms = soup.find_all("form")
    if not forms:
        feats["SFH"] = 0
    else:
        suspicious = 0
        for f in forms:
            action = (f.get("action") or "").strip()
            if action == "" or action.lower() == "about:blank":
                suspicious += 1
                continue
            abs_action = urljoin(final_url or base_url, action)
            h = (urlparse(abs_action).netloc or "").split("@")[-1].split(":")[0].lower()
            if h and _domain(h) != dom:
                suspicious += 1
        ratio = suspicious / max(1, len(forms))
        feats["SFH"] = 1 if ratio == 0 else (-1 if ratio >= 0.5 else 0)

    feats["_has_password_input"] = 1 if soup.find("input", attrs={"type": "password"}) is not None else 0
    external_post = 0
    total_forms = len(forms)
    if total_forms:
        for f in forms:
            method = (f.get("method") or "").strip().lower()
            action = (f.get("action") or "").strip()
            if method == "post" and action:
                abs_action = urljoin(final_url or base_url, action)
                h = (urlparse(abs_action).netloc or "").split("@")[-1].split(":")[0].lower()
                if h and _domain(h) != dom:
                    external_post += 1
    feats["_external_post_forms"] = external_post

    return feats


def vectorize_features(feature_cols: List[str], feats: Dict[str, float]) -> pd.DataFrame:
    row = {c: float(feats.get(c, 0)) for c in feature_cols}
    return pd.DataFrame([row], columns=feature_cols)


def build_features_for_url(
    url: str,
    feature_cols: List[str],
    fetch_timeout_s: float = 8.0,
) -> Tuple[pd.DataFrame, FetchMeta, Dict[str, float]]:
    base = extract_url_only_features(url)

    meta = fetch_url(url, timeout_s=fetch_timeout_s)
    all_feats = dict(base)

    if meta.html:
        html_feats = extract_html_features(url, meta.final_url, meta.html, meta.num_redirects)
        all_feats.update(html_feats)

    # DNS/WHOIS/TLS
    infra = extract_dns_whois_tls_features(meta.final_url or url)
    all_feats.update(infra)

    X = vectorize_features(feature_cols, all_feats)
    return X, meta, all_feats


def explain_risks(feats: Dict[str, float]) -> List[str]:
    reasons: List[str] = []
    for k, label in [
        ("having_IP_Address", "IP adresi kullanimi"),
        ("Shortining_Service", "URL kisaltici"),
        ("having_At_Symbol", "@ sembolu"),
        ("double_slash_redirecting", "cift slash yonlendirme"),
        ("Prefix_Suffix", "domain icinde tire (-)"),
        ("HTTPS_token", "domain icinde 'https' kelimesi"),
        ("port", "standart disi port"),
        ("Redirect", "coklu redirect"),
        ("Iframe", "iframe bulunmasi"),
        ("on_mouseover", "onmouseover javascript"),
        ("RightClick", "sag tik engelleme"),
        ("popUpWidnow", "popup acma"),
        ("Submitting_to_email", "mailto/email gonderimi"),
        ("SFH", "supheli form action"),
        ("Request_URL", "harici medya yukleme orani"),
        ("URL_of_Anchor", "supheli anchor link orani"),
        ("Links_in_tags", "harici link/script orani"),
        ("Favicon", "harici favicon"),
        ("DNSRecord", "DNS kaydi yok"),
        ("age_of_domain", "domain yeni (yas dusuk)"),
        ("Domain_registeration_length", "domain kayit suresi kisa"),
        ("TLS_validity", "TLS sertifikasi kisa/gecersiz"),
    ]:
        v = feats.get(k, 0)
        if v == -1:
            reasons.append(label)
    return reasons

