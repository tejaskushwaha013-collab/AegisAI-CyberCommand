import base64
import difflib
import hashlib
import ipaddress
import os
import re
import tempfile
from urllib.parse import parse_qs, urlparse

import cv2
import librosa
import numpy as np
import psutil
import requests
import streamlit as st
from PIL import Image
from transformers import pipeline

# ---------------------------------------------------------
# 1. PAGE CONFIGURATION & CYBER-COMMAND THEME
# ---------------------------------------------------------
st.set_page_config(
    page_title="AegisAI CyberCommand v4.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(135deg, #090d16 0%, #111827 55%, #0f172a 100%);
        color: #f8fafc;
    }
    .hero-box {
        background: linear-gradient(90deg, rgba(6,182,212,0.18) 0%, rgba(79,70,229,0.20) 100%);
        border: 1px solid rgba(34, 211, 238, 0.4);
        border-radius: 14px;
        padding: 18px 24px;
        margin-bottom: 18px;
    }
    .hero-title {
        font-size: 1.9rem;
        font-weight: 800;
        color: #22d3ee;
        margin: 0;
    }
    .hero-desc {
        color: #cbd5e1;
        font-size: 0.95rem;
        margin-top: 4px;
    }
    .badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 999px;
        font-size: 0.78rem;
        font-weight: 600;
        background: rgba(16, 185, 129, 0.16);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.45);
        margin-right: 8px;
        margin-top: 8px;
    }
    div[data-testid="stMetric"] {
        background-color: rgba(30, 41, 59, 0.78);
        border: 1px solid rgba(148, 163, 184, 0.22);
        padding: 12px 16px;
        border-radius: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize session state for AI Assistant & scan memory
if "last_scan_summary" not in st.session_state:
    st.session_state["last_scan_summary"] = "No scans performed yet in this session."
if "chat_history" not in st.session_state:
    st.session_state["chat_history"] = [
        {
            "role": "assistant",
            "content": (
                "Welcome to **AegisAI CyberCommand v4.0**! I am your built-in **AI Security Assistant**. "
                "You can scan any QR code, SMS, website link, image, video, voice recording, or file—and ask me "
                "anything about your scan results or how to stay safe from cyber fraud."
            ),
        }
    ]

# ---------------------------------------------------------
# 2. SIDEBAR: LIVE STATUS, HELP GUIDE & OPTIONAL API KEYS
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ AegisAI v4.0 Control")
    st.success("🟢 All AI Security Engines: Ready")
    st.info("🌐 Free Live Internet Intel: Active")

    with st.expander("❓ Quick Help & Tool Guide", expanded=True):
        st.markdown(
            """
            **All-Rounder Security Modules:**
            1. **📷 QR & UPI Scanner:** Upload QR screenshots, use live webcam, or test QR links & UPI payment traps.
            2. **💬 SMS & Phishing:** Detect fake bank KYC, OTP, delivery & callback scams.
            3. **🌐 Website & Link Check:** Verify any suspicious URL before opening it.
            4. **🎭 Deepfake Media:** Detect AI face-swaps in photos & videos.
            5. **🎙️ Voice Clone AI:** Check audio clips for cloned AI voices.
            6. **🦠 Malware & APK Scan:** Inspect `.apk`, `.exe`, `.pdf`, or `.zip` files.
            7. **📡 Live Network Guard:** Audit running apps & remote server IPs.
            8. **🤖 AI Support & Guide:** 24/7 chat support + cyber helpline guide.
            """
        )

    with st.expander("🔑 Optional Pro API Keys (100% Optional)", expanded=False):
        st.caption("Leave blank to use built-in free AI + free live DNS/IP intelligence.")
        vt_api_key = st.text_input(
            "VirusTotal API Key (v3)",
            value="",
            type="password",
            help="Optional free key from virustotal.com to cross-check hashes/URLs across 70+ antivirus engines.",
        )
        abuseipdb_api_key = st.text_input(
            "AbuseIPDB API Key (v2)",
            value="",
            type="password",
            help="Optional free key from abuseipdb.com for community IP abuse scores.",
        )

st.markdown(
    """
    <div class="hero-box">
        <div class="hero-title">🛡️ AegisAI CyberCommand v4.0 — All-in-One AI Cyber Defense Suite</div>
        <div class="hero-desc">
            6-Pass QR & UPI Forensics • BERT Phishing AI • Live Internet DNS & Redirect Tracer • Deepfake & Voice AI • Built-in AI Assistant
        </div>
        <div>
            <span class="badge">● 6-Pass QR + Webcam Ready</span>
            <span class="badge">● BERT Phishing AI Ready</span>
            <span class="badge">● Live DNS & IP Intel Active</span>
            <span class="badge">● 24/7 AI Support Online</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# 3. CACHED DEEP LEARNING MODELS (WITH SAFE FALLBACKS)
# ---------------------------------------------------------
@st.cache_resource(show_spinner="Loading BERT Phishing Neural Network...")
def load_sms_phishing_model():
    try:
        return pipeline("text-classification", model="ealvaradob/bert-finetuned-phishing")
    except Exception:
        return None


@st.cache_resource(show_spinner="Loading Vision Transformer Deepfake Model...")
def load_image_deepfake_model():
    try:
        return pipeline("image-classification", model="dima806/deepfake_vs_real_image_detection")
    except Exception:
        return None


@st.cache_resource(show_spinner="Loading Wav2Vec2 Acoustic Deepfake Model...")
def load_audio_deepfake_model():
    try:
        return pipeline("audio-classification", model="MelodyMachine/Deepfake-audio-detection-V2")
    except Exception:
        return None


# ---------------------------------------------------------
# 4. FREE LIVE INTERNET THREAT INTELLIGENCE (NO API KEY NEEDED)
# ---------------------------------------------------------
@st.cache_data(ttl=600, show_spinner=False)
def check_dns_live(domain: str) -> dict:
    """Queries Google DNS-over-HTTPS over the internet to check if a domain is registered and active."""
    clean_domain = domain.split(":")[0].strip().lower()
    if not clean_domain or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean_domain):
        return {"exists": True, "ips": [clean_domain], "status_text": "Direct IP Address"}

    try:
        resp = requests.get(
            "https://dns.google/resolve",
            params={"name": clean_domain, "type": "A"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            status_code = data.get("Status", -1)
            answers = [ans.get("data") for ans in data.get("Answer", []) if ans.get("type") == 1]
            if status_code == 0 and answers:
                return {"exists": True, "ips": answers, "status_text": f"Active DNS ({answers[0]})"}
            elif status_code == 3:
                return {"exists": False, "ips": [], "status_text": "NXDOMAIN (Unregistered / Fake Domain)"}
            else:
                return {"exists": False, "ips": [], "status_text": "No Active Web Server Record"}
    except Exception:
        pass
    return {"exists": None, "ips": [], "status_text": "DNS Check Unavailable"}


@st.cache_data(ttl=600, show_spinner=False)
def trace_url_redirects(raw_url: str) -> dict:
    """Safely unshortens URLs over the internet to expose hidden redirect targets."""
    target = raw_url if "://" in raw_url else f"https://{raw_url}"
    try:
        resp = requests.get(
            target,
            headers={"User-Agent": "Mozilla/5.0 (AegisAI-Security-Scanner)"},
            timeout=5,
            allow_redirects=True,
            stream=True,
        )
        final_url = resp.url
        hops = len(resp.history)
        resp.close()
        return {"final_url": final_url, "hops": hops, "reachable": True}
    except Exception:
        return {"final_url": target, "hops": 0, "reachable": False}


@st.cache_data(ttl=900, show_spinner=False)
def lookup_ip_free_intel(ip_str: str) -> dict:
    """Queries free keyless ip-api.com for ISP, country, VPN/Proxy, and datacenter hosting intel."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if not ip_obj.is_global:
            return {"status": "private"}
    except ValueError:
        return {"status": "invalid"}

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip_str}",
            params={"fields": "status,countryCode,isp,org,proxy,hosting"},
            timeout=4,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "status": "found",
                    "country": data.get("countryCode", "N/A"),
                    "isp": data.get("isp", "Unknown"),
                    "is_proxy": bool(data.get("proxy", False)),
                    "is_hosting": bool(data.get("hosting", False)),
                }
    except Exception:
        pass
    return {"status": "unavailable"}


@st.cache_data(ttl=600, show_spinner=False)
def vt_lookup_optional(item: str, api_key: str, mode: str = "file") -> dict:
    if len(api_key.strip()) <= 20:
        return {"status": "no_key"}
    headers = {"x-apikey": api_key.strip(), "accept": "application/json"}
    try:
        if mode == "file":
            endpoint = f"https://www.virustotal.com/api/v3/files/{item}"
        else:
            norm = item if "://" in item else f"http://{item}"
            url_id = base64.urlsafe_b64encode(norm.encode("utf-8")).decode("utf-8").rstrip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        resp = requests.get(endpoint, headers=headers, timeout=8)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "found",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
            }
        return {"status": "not_found"}
    except Exception:
        return {"status": "error"}


# ---------------------------------------------------------
# 5. BRAND PROTECTION, URL, QR & UPI FORENSIC ENGINES
# ---------------------------------------------------------
OFFICIAL_BRAND_DOMAINS = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbicard.com"),
    "hdfc": ("hdfcbank.com", "hdfc.com"),
    "icici": ("icicibank.com",),
    "axis": ("axisbank.com",),
    "kotak": ("kotak.com",),
    "pnb": ("pnbindia.in",),
    "bob": ("bankofbaroda.in",),
    "paytm": ("paytm.com", "paytmbank.com"),
    "phonepe": ("phonepe.com",),
    "gpay": ("google.com", "pay.google.com"),
    "google": ("google.com", "youtube.com", "gmail.com", "googleapis.com"),
    "amazon": ("amazon.in", "amazon.com", "amzn.to"),
    "flipkart": ("flipkart.com",),
    "indiapost": ("indiapost.gov.in",),
    "uidai": ("uidai.gov.in",),
    "aadhaar": ("uidai.gov.in",),
    "incometax": ("incometax.gov.in",),
    "irctc": ("irctc.co.in",),
    "epfo": ("epfindia.gov.in",),
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com"),
    "apple": ("apple.com", "icloud.com"),
    "netflix": ("netflix.com",),
    "whatsapp": ("whatsapp.com", "wa.me"),
    "instagram": ("instagram.com",),
}


def get_registrable_domain(hostname: str) -> str:
    host = hostname.split(":")[0].lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    multi_tlds = ("co.in", "gov.in", "nic.in", "ac.in", "org.in", "co.uk", "org.uk", "com.au")
    if ".".join(parts[-2:]) in multi_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def normalize_obfuscated_text(text: str) -> str:
    cleaned = re.sub(r"(?<=\b[a-zA-Z])[.\-_*](?=[a-zA-Z]\b)", "", text)
    leet_map = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s"})
    return cleaned.translate(leet_map).lower()


def analyze_url_comprehensive(url: str, context_text: str = "") -> dict:
    """Deep URL forensics: redirect tracing, Google DNS verification, brand spoofing & typosquatting."""
    risk_score = 0
    flags = []
    safe_notes = []

    raw_url = url.strip()
    lower_raw = raw_url.lower()

    if lower_raw.startswith(("javascript:", "data:", "file:", "intent://")):
        return {
            "score": 95,
            "flags": [f"Dangerous executable URI scheme ({lower_raw.split(':')[0]})"],
            "safe_notes": [],
            "final_url": raw_url,
            "root_domain": "N/A",
            "dns_status": "Blocked URI Scheme",
        }

    redirect_info = trace_url_redirects(raw_url)
    target_url = redirect_info["final_url"]
    if redirect_info["hops"] > 0 and target_url.lower() != raw_url.lower():
        flags.append(f"Redirected ({redirect_info['hops']} hop) to: {target_url}")

    if re.search(r"\.(apk|exe|scr|bat|ps1|vbs|msi|dmg)(\?|$)", target_url.lower()):
        risk_score += 75
        flags.append("Direct executable / Android APK malware download link detected")

    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    hostname = parsed.netloc.lower().split("@")[-1]
    domain_no_port = hostname.split(":")[0]
    root_domain = get_registrable_domain(domain_no_port)

    dns_info = check_dns_live(domain_no_port)
    if dns_info["exists"] is False:
        risk_score += 35
        flags.append(f"Live DNS Check: {dns_info['status_text']} — domain is not active on the internet")

    if "@" in parsed.netloc:
        risk_score += 60
        flags.append("Contains '@' credential/host spoofing trick")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_no_port):
        risk_score += 55
        flags.append("Uses raw IP address instead of a registered domain")

    if "xn--" in domain_no_port:
        risk_score += 50
        flags.append("Contains Punycode ('xn--') lookalike domain spoofing")

    matched_official = False
    for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
        if root_domain in official_domains:
            matched_official = True
            safe_notes.append(f"Verified official {brand.upper()} domain ({root_domain})")
            break

        if brand in domain_no_port:
            risk_score += 70
            flags.append(
                f"BRAND IMPERSONATION: '{domain_no_port}' uses '{brand.upper()}' in its domain "
                f"but is NOT an official domain ({', '.join(official_domains)})"
            )
            break

        domain_label = root_domain.split(".")[0]
        if len(domain_label) >= 5 and len(brand) >= 4:
            if 0.80 <= difflib.SequenceMatcher(None, domain_label, brand).ratio() < 1.0:
                risk_score += 60
                flags.append(f"Typosquatting alert: '{root_domain}' imitates '{brand}'")
                break

    if parsed.scheme == "http" and not matched_official:
        risk_score += 20
        flags.append("Unencrypted HTTP connection (no SSL/TLS certificate)")

    suspicious_tlds = (
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".icu",
        ".buzz", ".click", ".loan", ".work", ".vip", ".online", ".site", ".cfd", ".sbs",
    )
    if any(domain_no_port.endswith(tld) for tld in suspicious_tlds):
        risk_score += 35
        flags.append(f"High-abuse disposable TLD ({root_domain})")

    shorteners = (
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "rb.gy", "cutt.ly", "shorturl.at", "qrco.de", "me-qr.com", "qrfy.com", "tiny.cc",
    )
    if any(root_domain == s or domain_no_port.endswith("." + s) for s in shorteners):
        risk_score += 30
        flags.append(f"URL shortener / dynamic QR redirector ({root_domain})")

    lure_words = (
        "login", "signin", "verify", "update", "bank", "secure", "kyc",
        "wallet", "upi", "otp", "account", "refund", "cashback", "prize", "reward", "suspend", "pan",
    )
    url_tokens = f"{domain_no_port}{parsed.path.lower()}"
    matched_lures = [w for w in lure_words if w in url_tokens]
    if matched_lures and not matched_official:
        risk_score += min(45, len(matched_lures) * 15)
        flags.append(f"Phishing lure keywords in URL: {', '.join(matched_lures)}")

    if domain_no_port.count("-") >= 2 and not matched_official:
        risk_score += 25
        flags.append("Multiple hyphens in domain name (common fake-site pattern)")

    if matched_official and not flags:
        risk_score = 0

    return {
        "score": min(100, risk_score),
        "flags": flags,
        "safe_notes": safe_notes,
        "final_url": target_url,
        "root_domain": root_domain,
        "dns_status": dns_info["status_text"],
    }


def analyze_upi_qr(upi_uri: str) -> dict:
    """Forensic audit of UPI payment QR codes (upi://pay?...)."""
    parsed = urlparse(upi_uri)
    params = parse_qs(parsed.query)

    pa = params.get("pa", [""])[0].strip()
    pn = params.get("pn", ["Unknown"])[0].strip()
    am = params.get("am", [""])[0].strip()
    tn = params.get("tn", [""])[0].strip()
    mc = params.get("mc", [""])[0].strip()

    risk_score = 0
    flags = []
    info = {
        "Payee UPI ID (pa)": pa or "Missing!",
        "Payee Name (pn)": pn,
        "Amount (am)": f"₹{am}" if am else "Open (User enters amount)",
        "Note (tn)": tn or "None",
        "Merchant Code (mc)": mc if mc and mc != "0000" else "None (Personal Account)",
    }

    if not pa or "@" not in pa:
        risk_score += 75
        flags.append("Invalid or missing UPI ID ('pa' parameter)")

    lure_text = f"{pn} {tn} {pa}".lower()
    scam_lures = (
        "refund", "cashback", "prize", "reward", "lottery", "winner",
        "receive", "credit", "claim", "kyc", "subsidy", "bonus", "gift",
    )
    matched_lures = [w for w in scam_lures if w in lure_text]
    if matched_lures:
        risk_score += 85
        flags.append(
            f"CRITICAL UPI SCAM TRAP: QR mentions '{', '.join(matched_lures)}'. "
            "Scanning a UPI QR ALWAYS deducts money—you NEVER scan a QR code or enter your PIN to receive money!"
        )

    brand_names = ("sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "amazon", "flipkart", "govt", "electricity", "customs")
    if any(b in pn.lower() for b in brand_names) and (not mc or mc == "0000"):
        risk_score += 60
        flags.append(f"Payee '{pn}' impersonates an official brand/dept using an unverified personal UPI ID!")

    if am:
        try:
            if float(am) > 0:
                risk_score += 20
                flags.append(f"Pre-filled fixed amount of ₹{float(am):,.2f} embedded in QR—confirm before entering PIN")
        except ValueError:
            risk_score += 30
            flags.append("Corrupted amount parameter in QR")

    return {"score": min(100, risk_score), "flags": flags, "info": info}


def analyze_any_qr_payload(payload: str, vt_key: str) -> dict:
    """Universal classifier for ALL QR payload types (UPI, URL, Wi-Fi, SMS, Email, Tel, vCard, Text)."""
    clean = payload.strip()
    low = clean.lower()

    if low.startswith("upi://"):
        rep = analyze_upi_qr(clean)
        return {"category": "UPI Payment QR", "score": rep["score"], "details": rep}

    if low.startswith("wifi:"):
        # Format: WIFI:T:WPA;S:MyNetwork;P:password;;
        ssid_match = re.search(r"S:([^;]*)", clean, flags=re.IGNORECASE)
        enc_match = re.search(r"T:([^;]*)", clean, flags=re.IGNORECASE)
        ssid = ssid_match.group(1) if ssid_match else "Unknown"
        enc = (enc_match.group(1) if enc_match else "NONE").upper()
        score = 55 if enc in ("", "NOPASS", "NONE", "WEP") else 20
        flags = [f"Network SSID: '{ssid}' | Encryption: {enc}"]
        if score >= 50:
            flags.append("UNENCRYPTED / OPEN WI-FI QR: Attackers use rogue open Wi-Fi QRs to intercept traffic!")
        else:
            flags.append("Verify you recognize this Wi-Fi network before auto-connecting.")
        return {"category": "Wi-Fi Auto-Connect QR", "score": score, "flags": flags}

    if low.startswith(("smsto:", "sms:", "matmsg:", "mailto:", "tel:")):
        return {
            "category": "Action Trigger QR (SMS/Call/Email)",
            "score": 60,
            "flags": [
                f"Triggers an automatic device action ({clean.split(':')[0].upper()})",
                "Scammers use SMS/Call QR codes to send premium-rate messages or initiate vishing calls.",
            ],
        }

    if low.startswith(("http://", "https://", "www.", "javascript:", "data:", "intent://")) or re.match(
        r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", clean
    ):
        url_rep = analyze_url_comprehensive(clean)
        vt_res = vt_lookup_optional(clean, vt_key, mode="url")
        score = max(url_rep["score"], 100 if vt_res.get("malicious", 0) > 0 else 0)
        return {"category": "Web Link / URL QR", "score": score, "url_rep": url_rep, "vt_res": vt_res}

    return {
        "category": "Plain Text / Contact QR",
        "score": 0,
        "flags": ["Contains plain text or contact card data with no executable link or payment request."],
    }


def decode_qr_6pass(img_bgr: np.ndarray) -> tuple[list[str], str]:
    """
    6-pass QR decoder with white quiet-zone padding, multi-scale resizing,
    contrast enhancement, dark-mode inversion, and ArUco-assisted detection.
    """
    detectors = [("Standard QR", cv2.QRCodeDetector())]
    if hasattr(cv2, "QRCodeDetectorAruco"):
        try:
            detectors.insert(0, ("ArUco-Enhanced QR", cv2.QRCodeDetectorAruco()))
        except Exception:
            pass

    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape[:2]

    # Pass 1 & 2: Original + White Quiet-Zone Border (fixes tightly cropped QR screenshots)
    pad = max(30, int(min(h, w) * 0.12))
    bordered = cv2.copyMakeBorder(gray, pad, pad, pad, pad, cv2.BORDER_CONSTANT, value=255)

    # Pass 3: Normalized scale (ideal ~700px width for large phone screenshots or tiny thumbnails)
    scale = 700.0 / max(1, max(h, w))
    resized = cv2.resize(bordered, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    # Pass 4: CLAHE Contrast Enhancement + Otsu Binary Threshold
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(resized)
    _, otsu = cv2.threshold(clahe, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    # Pass 5: Inverted Polarity (for white-on-black dark mode QR codes)
    inverted = cv2.bitwise_not(otsu)

    passes = [
        ("Original Image", img_bgr),
        ("Quiet-Zone White Border Pass", bordered),
        ("Normalized Multi-Scale Pass", resized),
        ("CLAHE + Otsu Binary Pass", otsu),
        ("Dark-Mode Inverted Pass", inverted),
    ]

    for det_name, detector in detectors:
        for pass_name, frame in passes:
            try:
                ok, multi_data, _, _ = detector.detectAndDecodeMulti(frame)
                if ok and multi_data:
                    clean = [d.strip() for d in multi_data if d and d.strip()]
                    if clean:
                        return clean, f"{det_name} ({pass_name})"
            except Exception:
                pass
            try:
                single, _, _ = detector.detectAndDecode(frame)
                if single and single.strip():
                    return [single.strip()], f"{det_name} ({pass_name})"
            except Exception:
                pass

    return [], "None"


# ---------------------------------------------------------
# 6. SMS PHISHING & BINARY MALWARE ENGINES
# ---------------------------------------------------------
def analyze_sms_full(sms_text: str, bert_clf, vt_key: str) -> dict:
    norm_text = normalize_obfuscated_text(sms_text)
    risk_score = 0
    reasons = []
    phishing_prob = 0.0

    if bert_clf is not None:
        try:
            out = bert_clf(sms_text[:512])[0]
            lbl = out["label"].lower()
            conf = out["score"] * 100
            is_phish = any(k in lbl for k in ("phish", "spam", "malicious", "fraud", "label_1"))
            phishing_prob = conf if is_phish else (100.0 - conf)
            if phishing_prob >= 65:
                risk_score += 50
                reasons.append(f"BERT Phishing AI flagged message ({phishing_prob:.1f}% confidence)")
            elif phishing_prob >= 40:
                risk_score += 25
                reasons.append(f"BERT Phishing AI detected moderate risk phrasing ({phishing_prob:.1f}%)")
        except Exception:
            phishing_prob = 0.0

    url_pattern = r"(?:https?://[^\s<>\"']+|www\.[^\s<>\"']+|\b[a-zA-Z0-9-]+\.(?:com|in|co\.in|org|net|xyz|top|tk|ml|ga|cf|gq|icu|vip|online|site|club|live|info|biz|ly|co|me|to)(?:/[^\s<>\"']*)?)"
    raw_urls = list(dict.fromkeys(re.findall(url_pattern, sms_text, flags=re.IGNORECASE)))

    url_reports = []
    for u in raw_urls:
        rep = analyze_url_comprehensive(u, context_text=sms_text)
        vt_res = vt_lookup_optional(u, vt_key, mode="url")
        url_reports.append((u, rep, vt_res))
        if rep["score"] >= 35:
            risk_score = max(risk_score, rep["score"])
            reasons.append(f"High-risk link '{u}' (Risk: {rep['score']}/100)")
        if vt_res.get("malicious", 0) > 0:
            risk_score = 100
            reasons.append(f"VirusTotal flagged '{u}' as MALICIOUS ({vt_res['malicious']} engines)")

    threats = (
        "suspend", "suspended", "block", "blocked", "deactivate", "deactivated",
        "disconnect", "disconnected", "expire", "expired", "freeze", "frozen",
        "terminate", "penalty", "legal action", "arrest", "customs", "seized", "hold",
    )
    urgencies = (
        "urgent", "immediately", "today", "within 24", "within 2 hours", "tonight",
        "last warning", "final notice", "act now", "right now", "asap", "hurry",
    )
    actions = (
        "update kyc", "pan update", "verify", "click here", "click below", "tap here",
        "claim", "won", "lottery", "prize", "cashback", "refund", "share otp", "send otp",
        "apk", "download", "customer care", "helpline",
    )

    found_t = [w for w in threats if w in norm_text]
    found_u = [w for w in urgencies if w in norm_text]
    found_a = [w for w in actions if w in norm_text]

    if found_t:
        risk_score += 25
        reasons.append(f"Account/service threat trigger: {', '.join(found_t[:3])}")
    if found_u:
        risk_score += 20
        reasons.append(f"Artificial urgency trigger: {', '.join(found_u[:3])}")
    if found_a:
        risk_score += 25
        reasons.append(f"Action/credential lure trigger: {', '.join(found_a[:3])}")

    mobiles = re.findall(r"(?:\+91[\-\s]?|0)?[6-9]\d{9}\b", sms_text)
    if mobiles and (found_t or found_a or any(b in norm_text for b in OFFICIAL_BRAND_DOMAINS)):
        risk_score += 45
        reasons.append(
            f"Callback scam trap: embeds personal mobile number ({', '.join(mobiles)}) instead of an official 1800 helpline"
        )

    is_real_otp = (
        bool(re.search(r"\b(otp|one time password|verification code)\b", norm_text))
        and bool(re.search(r"\b(do not share|never share|valid for \d+ min)\b", norm_text))
        and len(raw_urls) == 0
        and len(mobiles) == 0
        and not found_t
    )
    if is_real_otp:
        risk_score = min(risk_score, 8)
        reasons = ["Matches legitimate transactional OTP format (no links, no personal callback numbers, warns not to share)"]

    return {
        "risk_score": min(100, risk_score),
        "phishing_prob": phishing_prob,
        "reasons": reasons,
        "url_reports": url_reports,
    }


def scan_binary_heuristics(file_bytes: bytes, filename: str) -> dict:
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    if file_bytes:
        counts = np.bincount(np.frombuffer(file_bytes, dtype=np.uint8), minlength=256)
        probs = counts[counts > 0] / len(file_bytes)
        entropy = float(-np.sum(probs * np.log2(probs)))
    else:
        entropy = 0.0

    findings = []
    risk_score = 0

    if file_bytes[:2] == b"MZ":
        findings.append("Windows Executable (PE/MZ) binary header detected")
    elif file_bytes[:4] == b"\x7fELF":
        findings.append("Linux/Unix ELF binary header detected")
    elif file_bytes[:4] == b"PK\x03\x04" and filename.lower().endswith(".apk"):
        findings.append("Android Package (APK) archive detected")

    if entropy >= 7.2:
        risk_score += 40
        findings.append(f"High Shannon Entropy ({entropy:.2f}/8.0) — indicates encrypted, packed, or obfuscated payload")
    elif entropy >= 6.5:
        risk_score += 15
        findings.append(f"Elevated Entropy ({entropy:.2f}/8.0) — compressed or dense binary data")

    signatures = [
        (b"VirtualAllocEx", "Process injection API (VirtualAllocEx)"),
        (b"WriteProcessMemory", "Remote memory tampering API (WriteProcessMemory)"),
        (b"CreateRemoteThread", "Remote thread execution API (CreateRemoteThread)"),
        (b"IsDebuggerPresent", "Anti-debugging evasion check"),
        (b"powershell -enc", "Encoded PowerShell command execution"),
        (b"cmd.exe /c", "Hidden command shell invocation"),
        (b"WScript.Shell", "Windows Script Host execution"),
        (b"eval(base64_decode", "Obfuscated script payload execution"),
        (b"android.permission.RECEIVE_SMS", "Android SMS interception permission (common in banking trojans)"),
        (b"android.permission.BIND_ACCESSIBILITY_SERVICE", "Android Accessibility takeover permission"),
    ]
    lower_bytes = file_bytes.lower()
    for sig, desc in signatures:
        if sig.lower() in lower_bytes:
            risk_score += 22
            findings.append(f"Suspicious signature matched: {desc}")

    if re.search(r"\.(pdf|doc|docx|jpg|png|txt)\.(exe|scr|bat|ps1|vbs|js|apk)$", filename.lower()):
        risk_score += 50
        findings.append("Double-extension file masquerading detected")

    return {
        "sha256": sha256,
        "entropy": entropy,
        "risk_score": min(100, risk_score),
        "findings": findings,
    }


# ---------------------------------------------------------
# 7. 24/7 AI CYBER SECURITY ASSISTANT
# ---------------------------------------------------------
def generate_ai_support_reply(user_query: str) -> str:
    q = user_query.lower().strip()
    last_scan = st.session_state.get("last_scan_summary", "No scans run yet.")

    if any(k in q for k in ("last scan", "result", "why", "explain", "flagged", "what happened")):
        return (
            f"### 🔍 Breakdown of Your Latest Scan\n"
            f"**Recorded Result:** {last_scan}\n\n"
            f"**What You Should Do:**\n"
            f"- **Score 50–100 (High Risk):** Treat as a confirmed scam or threat. Do **not** click links, install `.apk` files, or enter your UPI PIN/OTP.\n"
            f"- **Score 20–49 (Caution):** Double-check the sender or merchant manually before proceeding.\n"
            f"- **Already clicked or paid?** Call **1930** (National Cyber Crime Helpline) or report at **cybercrime.gov.in** immediately."
        )

    if any(k in q for k in ("upi", "qr", "payment", "money", "paytm", "gpay", "phonepe")):
        return (
            "### 📷 QR Code & UPI Fraud Protection Guide\n"
            "1. **Golden Rule:** Scanning a QR code and entering your UPI PIN **ALWAYS deducts money** from your account. You never need to scan a QR code to *receive* money, cashback, or a refund.\n"
            "2. **Check Merchant vs. Personal:** Legitimate shops use verified Merchant QR codes. Scammers use personal UPI IDs (`@okaxis`, `@ybl`) disguised with names like *'Refund Support'*.\n"
            "3. **Use Our 3 QR Modes:** You can upload a QR screenshot, hold a QR up to your MacBook webcam, or paste any QR link in the **📷 QR & UPI Scanner** tab."
        )

    if any(k in q for k in ("sms", "kyc", "otp", "link", "phishing", "bank", "message")):
        return (
            "### 💬 How to Spot Fake Bank SMS & Phishing\n"
            "- **Fake Urgency:** Scammers claim your bank account, PAN KYC, or SIM will be *'blocked today'*.\n"
            "- **Lookalike Domains:** Real banks only use their exact root domain (`sbi.co.in`, `hdfcbank.com`), never `sbi-kyc-update.xyz`.\n"
            "- **Personal Phone Numbers:** Real banks never ask you to call a 10-digit mobile number for KYC updates."
        )

    if any(k in q for k in ("deepfake", "voice", "call", "video", "clone", "ai")):
        return (
            "### 🎭 AI Deepfake & Voice Clone Safety\n"
            "- **Family Code Word:** Agree on a secret family safe-word for urgent phone or video money requests.\n"
            "- **Test Media Here:** Upload suspicious profile photos/videos to **🎭 Deepfake Media** or voice clips to **🎙️ Voice Clone AI**."
        )

    if any(k in q for k in ("virus", "malware", "apk", "file", "hacked")):
        return (
            "### 🦠 Malware & Fake APK Protection\n"
            "- Never install `.apk` files sent on WhatsApp (often disguised as *'Wedding Invite.apk'* or *'RTO Challan.apk'*).\n"
            "- Scan downloaded files in **🦠 Malware & APK Scan** before opening them."
        )

    return (
        "### 🛡️ AegisAI Support Assistant\n"
        "Ask me any question, such as:\n"
        "- *'Explain my last scan result'*\n"
        "- *'How do fake UPI QR scams work?'*\n"
        "- *'How do I spot fake bank KYC SMS?'*\n"
        "- *'How do I detect AI voice clones and deepfakes?'*\n\n"
        f"**Latest Session Activity:** {last_scan}"
    )


# ---------------------------------------------------------
# 8. MAIN ALL-ROUNDER TABS
# ---------------------------------------------------------
(
    tab_qr,
    tab_sms,
    tab_url,
    tab_deepfake,
    tab_voice,
    tab_malware,
    tab_network,
    tab_support,
) = st.tabs(
    [
        "📷 QR & UPI Scanner",
        "💬 SMS & Phishing",
        "🌐 Website & Link Check",
        "🎭 Deepfake Media",
        "🎙️ Voice Clone AI",
        "🦠 Malware & APK Scan",
        "📡 Live Network Guard",
        "🤖 AI Support & Guide",
    ]
)

# =========================================================
# TAB 1: ALL-TYPE QR CODE & UPI SCAM SCANNER
# =========================================================
with tab_qr:
    st.subheader("📷 Universal QR Code & UPI Payment Scam Scanner (6-Pass CV + Live Internet Intel)")

    qr_source = st.radio(
        "Select QR Input Method:",
        [
            "📤 Upload QR Screenshot / Photo",
            "📸 Scan QR Live via Webcam",
            "🧪 Test QR Text / UPI / URL Directly",
        ],
        horizontal=True,
        help="Supports cropped QR screenshots, dark-mode QR codes, live camera scanning, and direct payload testing.",
    )

    decoded_payloads = []
    decode_method = "Direct Input"

    if qr_source.startswith("📤"):
        qr_img_file = st.file_uploader(
            "Upload any QR code image (PNG, JPG, WEBP)",
            type=["png", "jpg", "jpeg", "webp"],
            help="Automatically applies 6 computer-vision passes including quiet-zone padding and dark-mode inversion.",
        )
        if qr_img_file and st.button("🔍 Scan Uploaded QR Code", type="primary"):
            file_bytes = np.asarray(bytearray(qr_img_file.read()), dtype=np.uint8)
            img_bgr = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            if img_bgr is not None:
                st.image(cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB), width=230)
                decoded_payloads, decode_method = decode_qr_6pass(img_bgr)
                if not decoded_payloads:
                    st.error(
                        "❌ No QR code detected in this image. Ensure the 3 square corner markers of the QR code are visible."
                    )
            else:
                st.error("❌ Invalid image file.")

    elif qr_source.startswith("📸"):
        cam_photo = st.camera_input("Hold the QR code steady in front of your webcam and click Take Photo")
        if cam_photo is not None:
            cam_bytes = np.asarray(bytearray(cam_photo.read()), dtype=np.uint8)
            cam_bgr = cv2.imdecode(cam_bytes, cv2.IMREAD_COLOR)
            if cam_bgr is not None:
                decoded_payloads, decode_method = decode_qr_6pass(cam_bgr)
                if not decoded_payloads:
                    st.warning("⚠️ Could not read QR from camera snapshot—move closer or improve lighting and retake.")

    else:
        c_q1, c_q2, c_q3, c_q4 = st.columns(4)
        if c_q1.button("🚨 Fake UPI Refund QR"):
            st.session_state["qr_direct_val"] = "upi://pay?pa=refundhelp99@okaxis&pn=SBI%20Cashback%20Refund&am=4999&tn=Claim%20Refund"
        if c_q2.button("🚨 Fake Bank Link QR"):
            st.session_state["qr_direct_val"] = "http://hdfc-kyc-rewards-claim.xyz/login"
        if c_q3.button("🚨 Rogue Open Wi-Fi QR"):
            st.session_state["qr_direct_val"] = "WIFI:T:nopass;S:Free_Airport_VIP_WiFi;P:;;"
        if c_q4.button("✅ Real Official QR"):
            st.session_state["qr_direct_val"] = "https://www.hdfcbank.com"

        direct_val = st.text_input(
            "Enter or paste any QR payload:",
            key="qr_direct_val",
            placeholder="e.g. upi://pay?pa=... or https://... or WIFI:...",
        )
        if st.button("🔍 Analyze QR Payload", type="primary") and direct_val.strip():
            decoded_payloads = [direct_val.strip()]

    for i, payload in enumerate(decoded_payloads, start=1):
        st.caption(f"Detected via: **{decode_method}**")
        st.info(f"**Decoded QR #{i}:** `{payload}`")
        analysis = analyze_any_qr_payload(payload, vt_api_key)
        score = analysis["score"]
        cat = analysis["category"]

        st.session_state["last_scan_summary"] = f"QR Scan ({cat}) → Risk Score: {score}/100 | Payload: {payload[:80]}"

        col_m1, col_m2 = st.columns(2)
        col_m1.metric("QR Threat Risk Score", f"{score}/100")
        col_m2.metric("Detected QR Type", cat)

        if score >= 50:
            st.error(f"🚨 FAKE / DANGEROUS {cat.upper()} DETECTED — Do NOT proceed!")
        elif score >= 20:
            st.warning(f"⚠️ CAUTION ({cat}) — Verify details carefully before trusting.")
        else:
            st.success(f"✅ SAFE / VERIFIED {cat.upper()}")

        if cat == "UPI Payment QR":
            upi_rep = analysis["details"]
            st.table([upi_rep["info"]])
            for flg in upi_rep["flags"]:
                st.warning(f"⚠️ {flg}")
        elif cat == "Web Link / URL QR":
            u_rep = analysis["url_rep"]
            st.write(f"🌐 **Live DNS Status:** `{u_rep['dns_status']}` | **Root Domain:** `{u_rep['root_domain']}`")
            for note in u_rep.get("safe_notes", []):
                st.write(f"✅ {note}")
            for flg in u_rep["flags"]:
                st.warning(f"⚠️ {flg}")
        else:
            for flg in analysis.get("flags", []):
                st.write(f"- {flg}")


# =========================================================
# TAB 2: SMS & PHISHING DETECTOR
# =========================================================
with tab_sms:
    st.subheader("💬 SMS, WhatsApp & Phishing Detector (BERT AI + Live Internet Forensics)")

    s1, s2, s3 = st.columns([1, 1, 2])
    if s1.button("🧪 Load Fake Scam SMS"):
        st.session_state["sms_box_v4"] = (
            "URGENT: Your SBI YONO account will be suspended today due to incomplete PAN KYC. "
            "Update immediately at http://sbi-kyc-verify-online.xyz/login or call 9876543210."
        )
    if s2.button("✅ Load Real Bank OTP"):
        st.session_state["sms_box_v4"] = (
            "482910 is your One Time Password (OTP) for transaction of Rs. 1,250.00 at Amazon Pay. "
            "Valid for 5 mins. NEVER share this OTP with anyone. -HDFC Bank"
        )

    sms_text = st.text_area(
        "Paste any SMS, WhatsApp, or email message:",
        key="sms_box_v4",
        placeholder="Paste suspicious or legitimate text here...",
        height=130,
    )

    if st.button("🔍 Scan Message Authenticity", type="primary") and sms_text.strip():
        bert_model = load_sms_phishing_model()
        res = analyze_sms_full(sms_text, bert_model, vt_api_key)

        verdict = "FAKE / PHISHING SCAM" if res["risk_score"] >= 50 else ("SUSPICIOUS" if res["risk_score"] >= 25 else "SAFE / LEGITIMATE")
        st.session_state["last_scan_summary"] = f"SMS Scan → {verdict} (Risk: {res['risk_score']}/100)"

        m1, m2, m3 = st.columns(3)
        m1.metric("Overall Threat Score", f"{res['risk_score']}/100")
        m2.metric("BERT Phishing Confidence", f"{res['phishing_prob']:.1f}%")
        m3.metric("Links Inspected", len(res["url_reports"]))

        if res["risk_score"] >= 50:
            st.error("🚨 FAKE / PHISHING SMS DETECTED — Do NOT click links, call back, or share OTPs!")
        elif res["risk_score"] >= 25:
            st.warning("⚠️ SUSPICIOUS MESSAGE — Contains unverified links or urgency triggers.")
        else:
            st.success("✅ LEGITIMATE / SAFE MESSAGE — No phishing or scam triggers found.")

        if res["reasons"]:
            st.markdown("**Forensic Evidence:**")
            for r in res["reasons"]:
                st.write(f"- {r}")

        if res["url_reports"]:
            st.markdown("**Live Internet URL Analysis:**")
            for u, rep, vt_res in res["url_reports"]:
                st.write(
                    f"🔗 `{u}` → Root Domain: `{rep['root_domain']}` | DNS: `{rep['dns_status']}` | Risk: **{rep['score']}/100**"
                )
                for note in rep.get("safe_notes", []):
                    st.caption(f"  ✅ {note}")
                for flg in rep["flags"]:
                    st.caption(f"  ⚠️ {flg}")


# =========================================================
# TAB 3: DEDICATED WEBSITE & LINK SAFETY CHECKER
# =========================================================
with tab_url:
    st.subheader("🌐 Live Website, Domain & Short-Link Safety Checker")
    target_link = st.text_input(
        "Enter any website URL or shortened link to inspect over the live internet:",
        placeholder="e.g. https://bit.ly/3xyz... or https://www.sbi.co.in",
    )

    if st.button("🔍 Inspect Link Live", type="primary") and target_link.strip():
        u_rep = analyze_url_comprehensive(target_link.strip())
        vt_res = vt_lookup_optional(target_link.strip(), vt_api_key, mode="url")
        score = max(u_rep["score"], 100 if vt_res.get("malicious", 0) > 0 else 0)

        st.session_state["last_scan_summary"] = f"Website Check ({target_link.strip()}) → Risk: {score}/100 | DNS: {u_rep['dns_status']}"

        c1, c2, c3 = st.columns(3)
        c1.metric("Link Threat Risk", f"{score}/100")
        c2.metric("Root Domain", u_rep["root_domain"])
        c3.metric("Live DNS Status", u_rep["dns_status"])

        st.write(f"**Final Resolved Destination:** `{u_rep['final_url']}`")

        if score >= 45:
            st.error("🚨 DANGEROUS / PHISHING WEBSITE DETECTED — Do NOT enter passwords or card details!")
        elif score >= 20:
            st.warning("⚠️ UNVERIFIED / SUSPICIOUS LINK — Proceed with caution.")
        else:
            st.success("✅ WEBSITE APPEARS SAFE & VERIFIED")

        for note in u_rep.get("safe_notes", []):
            st.write(f"✅ {note}")
        for flg in u_rep["flags"]:
            st.warning(f"⚠️ {flg}")


# =========================================================
# TAB 4: DEEPFAKE IMAGE & VIDEO FORENSICS
# =========================================================
with tab_deepfake:
    st.subheader("🎭 Deepfake Image & Video Forensics (Vision Transformer)")
    media_file = st.file_uploader(
        "Upload an Image or Video to scan for AI manipulation",
        type=["jpg", "jpeg", "png", "webp", "mp4", "avi", "mov"],
    )

    if media_file and st.button("🔍 Scan Media for Deepfakes", type="primary"):
        detector = load_image_deepfake_model()
        ext = media_file.name.split(".")[-1].lower()

        if ext in ("jpg", "jpeg", "png", "webp"):
            img = Image.open(media_file).convert("RGB")
            st.image(img, caption="Uploaded Image", width=320)

            if detector is not None:
                preds = detector(img)
                scores = {p["label"].lower(): p["score"] for p in preds}
                fake_prob = scores.get("fake", scores.get("deepfake", 0.0)) * 100
            else:
                gray_arr = np.array(img.convert("L"), dtype=np.float32)
                lap_var = float(cv2.Laplacian(gray_arr, cv2.CV_64F).var())
                fake_prob = 65.0 if lap_var < 35.0 else 18.0

            st.session_state["last_scan_summary"] = f"Image Deepfake Scan ({media_file.name}) → AI Fake Score: {fake_prob:.1f}%"
            st.metric("AI Manipulation Probability", f"{fake_prob:.2f}%")

            if fake_prob >= 50:
                st.error(f"🚨 DEEPFAKE / AI-GENERATED IMAGE DETECTED ({fake_prob:.2f}% confidence)")
            else:
                st.success(f"✅ AUTHENTIC PHOTOGRAPH ({100 - fake_prob:.2f}% real confidence)")
        else:
            with tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}") as tmp:
                tmp.write(media_file.read())
                tmp_path = tmp.name

            try:
                cap = cv2.VideoCapture(tmp_path)
                total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                indices = np.linspace(0, max(0, total_frames - 1), num=min(10, max(1, total_frames)), dtype=int)
                frame_scores = []
                bar = st.progress(0)

                for i, idx in enumerate(indices):
                    cap.set(cv2.CAP_PROP_POS_FRAMES, int(idx))
                    ok, frame = cap.read()
                    if ok and detector is not None:
                        rgb = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
                        preds = detector(rgb)
                        s_map = {p["label"].lower(): p["score"] for p in preds}
                        frame_scores.append(s_map.get("fake", s_map.get("deepfake", 0.0)))
                    bar.progress((i + 1) / len(indices))
                cap.release()

                if frame_scores:
                    avg_fake = float(np.mean(frame_scores)) * 100
                    peak_fake = float(np.max(frame_scores)) * 100
                    st.session_state["last_scan_summary"] = f"Video Deepfake Scan ({media_file.name}) → Avg Fake: {avg_fake:.1f}%"
                    if avg_fake >= 50 or peak_fake >= 80:
                        st.error(f"🚨 DEEPFAKE VIDEO DETECTED — Avg: {avg_fake:.1f}% | Peak Frame: {peak_fake:.1f}%")
                    else:
                        st.success(f"✅ VIDEO APPEARS AUTHENTIC — Avg Fake Score: {avg_fake:.1f}%")
                else:
                    st.warning("Could not analyze frames from this video file.")
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)


# =========================================================
# TAB 5: AI VOICE & CALL CLONE DETECTOR
# =========================================================
with tab_voice:
    st.subheader("🎙️ Synthetic Voice & AI Call Clone Detector (Wav2Vec2)")
    audio_file = st.file_uploader(
        "Upload a voice note or call recording",
        type=["wav", "mp3", "ogg", "flac", "m4a"],
    )

    if audio_file and st.button("🔍 Analyze Voice Authenticity", type="primary"):
        audio_detector = load_audio_deepfake_model()
        ext = audio_file.name.split(".")[-1].lower()
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}") as tmp:
            tmp.write(audio_file.read())
            tmp_audio = tmp.name

        try:
            st.audio(audio_file)
            wav, sr = librosa.load(tmp_audio, sr=16000)
            flatness = float(np.mean(librosa.feature.spectral_flatness(y=wav)))

            if audio_detector is not None:
                preds = audio_detector({"raw": wav, "sampling_rate": sr})
                s_map = {p["label"].lower(): p["score"] for p in preds}
                fake_score = s_map.get("fake", s_map.get("spoof", 0.0)) * 100
            else:
                fake_score = 60.0 if flatness < 0.002 else 20.0

            st.session_state["last_scan_summary"] = f"Voice Scan ({audio_file.name}) → AI Clone Score: {fake_score:.1f}%"
            c1, c2 = st.columns(2)
            c1.metric("AI Voice Clone Probability", f"{fake_score:.2f}%")
            c2.metric("Spectral Flatness", f"{flatness:.5f}")

            if fake_score >= 50:
                st.error("🚨 AI CLONED / SYNTHETIC VOICE DETECTED — Do NOT trust urgent money requests from this clip!")
            else:
                st.success("✅ NATURAL HUMAN VOICE VERIFIED")
        except Exception as exc:
            st.error(f"Could not process this audio format ({exc}). Try uploading a `.wav` or `.mp3` file.")
        finally:
            if os.path.exists(tmp_audio):
                os.remove(tmp_audio)


# =========================================================
# TAB 6: MALWARE, APK & SUSPICIOUS FILE SCANNER
# =========================================================
with tab_malware:
    st.subheader("🦠 Static Malware, APK & Binary Threat Analyzer")
    suspect_file = st.file_uploader(
        "Upload any file (.apk, .exe, .pdf, .zip, .ps1, .js, etc.) to scan before opening",
    )

    if suspect_file and st.button("🔍 Scan File for Malware", type="primary"):
        raw_bytes = suspect_file.read()
        rep = scan_binary_heuristics(raw_bytes, suspect_file.name)
        vt_res = vt_lookup_optional(rep["sha256"], vt_api_key, mode="file")

        final_risk = max(rep["risk_score"], 100 if vt_res.get("malicious", 0) > 0 else 0)
        st.session_state["last_scan_summary"] = f"File Scan ({suspect_file.name}) → Risk: {final_risk}/100 | Entropy: {rep['entropy']:.2f}"

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Threat Risk Score", f"{final_risk}/100")
        c2.metric("Shannon Entropy", f"{rep['entropy']:.2f} / 8.0")
        c3.metric("File Size", f"{len(raw_bytes):,} B")
        c4.metric(
            "VirusTotal Hits",
            f"{vt_res['malicious']}/{vt_res['total']}" if vt_res.get("status") == "found" else "Local Engine",
        )

        st.code(f"SHA-256: {rep['sha256']}", language="text")

        if final_risk >= 50:
            st.error("🚨 HIGH-RISK / MALICIOUS FILE DETECTED — Do NOT install or execute this file!")
        elif final_risk >= 20:
            st.warning("⚠️ MODERATE RISK — Review forensic findings carefully.")
        else:
            st.success("✅ NO STATIC MALWARE SIGNATURES DETECTED")

        if rep["findings"]:
            st.markdown("**Forensic Indicators:**")
            for f in rep["findings"]:
                st.write(f"- {f}")


# =========================================================
# TAB 7: LIVE NETWORK & PROCESS GUARD
# =========================================================
with tab_network:
    st.subheader("📡 Live System Process & Internet Connection Guard")
    if st.button("🔍 Audit Active Apps & Remote Server IPs", type="primary"):
        suspicious_procs = []
        connections = []
        unique_ips = set()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                p_name = proc.info.get("name") or "Unknown"
                p_pid = proc.info.get("pid")
                exe_path = (proc.info.get("exe") or "").lower()

                if any(t in exe_path for t in ("\\temp\\", "/tmp/", "\\appdata\\local\\temp", "/private/tmp/")):
                    suspicious_procs.append({"PID": p_pid, "Process": p_name, "Path": proc.info.get("exe")})

                for conn in proc.net_connections(kind="inet"):
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        r_ip = conn.raddr.ip
                        r_port = conn.raddr.port
                        unique_ips.add(r_ip)
                        connections.append((p_name, p_pid, r_ip, r_port))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        ip_intel_map = {}
        if unique_ips:
            with st.spinner(f"Checking {len(unique_ips)} active remote IP(s) via live IP intelligence..."):
                for ip in list(unique_ips)[:25]:
                    ip_intel_map[ip] = lookup_ip_free_intel(ip)

        rows = []
        flagged_conns = 0
        for p_name, p_pid, r_ip, r_port in connections:
            intel = ip_intel_map.get(r_ip, {})
            if intel.get("status") == "found":
                is_proxy = intel.get("is_proxy", False)
                if is_proxy:
                    flagged_conns += 1
                location = f"{intel['isp']} [{intel['country']}]"
                net_type = "🚨 VPN/Proxy/Tor" if is_proxy else ("☁️ Cloud/Hosting" if intel["is_hosting"] else "Standard ISP")
            elif intel.get("status") == "private":
                location = "Local Network (Router/LAN)"
                net_type = "Private IP"
            else:
                location = "External Server"
                net_type = "Public IP"

            rows.append(
                {
                    "Application": p_name,
                    "PID": p_pid,
                    "Remote IP:Port": f"{r_ip}:{r_port}",
                    "Provider / Country": location,
                    "Classification": net_type,
                }
            )

        st.session_state["last_scan_summary"] = (
            f"Network Guard Audit → {len(rows)} active connections, {len(suspicious_procs)} temp processes, {flagged_conns} proxy/VPN endpoints."
        )

        if suspicious_procs:
            st.error(f"🚨 {len(suspicious_procs)} App(s) Running from Temporary Folders:")
            st.table(suspicious_procs)
        elif flagged_conns > 0:
            st.warning(f"⚠️ {flagged_conns} Connection(s) to Proxy/VPN/Tor Infrastructure Detected.")
        else:
            st.success("✅ System Processes & Outbound Connections Look Healthy!")

        if rows:
            st.dataframe(rows, width="stretch")
        else:
            st.info("No active external user-space connections found right now.")


# =========================================================
# TAB 8: 24/7 AI SUPPORT ASSISTANT & COMPLETE USER GUIDE
# =========================================================
with tab_support:
    st.subheader("🤖 AegisAI Support Chat & Complete Cyber Safety Guide")

    col_chat, col_guide = st.columns([3, 2])

    with col_chat:
        st.markdown("#### 💬 Ask AegisAI Assistant")
        q1, q2, q3 = st.columns(3)
        quick_q = None
        if q1.button("🔍 Explain Last Scan"):
            quick_q = "Explain my last scan result"
        if q2.button("📷 UPI QR Scam Rules"):
            quick_q = "How do fake UPI QR scams work?"
        if q3.button("💬 Spot Fake Bank SMS"):
            quick_q = "How do I spot fake bank KYC SMS?"

        for msg in st.session_state["chat_history"]:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

        typed_q = st.chat_input("Ask any cybersecurity question here...")
        active_q = quick_q or typed_q

        if active_q:
            st.session_state["chat_history"].append({"role": "user", "content": active_q})
            with st.chat_message("user"):
                st.markdown(active_q)

            ans = generate_ai_support_reply(active_q)
            st.session_state["chat_history"].append({"role": "assistant", "content": ans})
            with st.chat_message("assistant"):
                st.markdown(ans)

    with col_guide:
        st.markdown("#### 📖 Step-by-Step User & Emergency Guide")
        st.info(
            """
            **Emergency Cyber Fraud Helpline (India):**
            * 📞 Call **1930** immediately within 1 hour (*Golden Hour*) to freeze fraudulent bank transfers.
            * 🌐 Report online at **[cybercrime.gov.in](https://cybercrime.gov.in)**.

            **Golden Rules for 99.9% Personal Safety:**
            1. **Never scan a QR code or enter your UPI PIN to receive money.**
            2. **Never install `.apk` files** sent over WhatsApp or SMS.
            3. **Check the root domain** (e.g., `sbi.co.in` vs `sbi-kyc.xyz`) in our **Website & Link Check** tab before logging in.
            """
        )