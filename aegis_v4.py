import os
import io
import re
import math
import json
import time
import base64
import socket
import hashlib
import zipfile
import tempfile
import ipaddress
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote, quote
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import cv2
import requests
import psutil
import streamlit as st
from PIL import Image, ExifTags, ImageOps

# ==============================================================================
# PAGE CONFIGURATION & GOVERNMENT-GRADE PORTAL STYLING
# ==============================================================================
st.set_page_config(
    page_title="Rakshak — Citizen Cyber Defense & AI Forensics Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .main-banner {
        background: linear-gradient(135deg, #0b132b 0%, #1c2541 60%, #0f3460 100%);
        border: 1px solid #2b4c7e;
        border-left: 6px solid #ff9933;
        padding: 18px 22px;
        border-radius: 10px;
        margin-bottom: 14px;
        color: #f8fafc;
    }
    .helpline-strip {
        background: #1e293b;
        border: 1px solid #334155;
        border-left: 5px solid #138808;
        padding: 10px 16px;
        border-radius: 8px;
        font-size: 0.93rem;
        margin-bottom: 16px;
    }
    .verdict-danger {
        background: rgba(220, 38, 38, 0.16);
        border: 1px solid #ef4444;
        border-left: 6px solid #dc2626;
        padding: 14px 18px;
        border-radius: 8px;
        margin: 10px 0;
    }
    .verdict-warn {
        background: rgba(245, 158, 11, 0.16);
        border: 1px solid #f59e0b;
        border-left: 6px solid #d97706;
        padding: 14px 18px;
        border-radius: 8px;
        margin: 10px 0;
    }
    .verdict-safe {
        background: rgba(16, 185, 129, 0.15);
        border: 1px solid #10b981;
        border-left: 6px solid #059669;
        padding: 14px 18px;
        border-radius: 8px;
        margin: 10px 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ==============================================================================
# CACHED AI MODEL LOADERS (LAZY-LOADED TO PREVENT CLOUD MEMORY EXHAUSTION)
# ==============================================================================
@st.cache_resource(show_spinner="Loading Rakshak Multi-Model Deepfake Image & Video Forensics...")
def load_deepfake_pipeline():
    loaded = []
    try:
        from transformers import pipeline
        for model_name in [
            "Ateeqq/ai-vs-human-image-detector",
            "dima806/deepfake_vs_real_image_detection",
        ]:
            try:
                loaded.append((model_name, pipeline("image-classification", model=model_name)))
            except Exception:
                continue
    except Exception:
        pass
    return loaded


@st.cache_resource(show_spinner="Loading Rakshak BERT Phishing & Scam Classifier...")
def load_phishing_pipeline():
    try:
        from transformers import pipeline
        return pipeline("text-classification", model="ealvaradob/bert-finetuned-phishing")
    except Exception:
        return None


@st.cache_resource(show_spinner="Loading Rakshak Wav2Vec2 AI Voice Clone Forensics...")
def load_audio_models():
    """Loads verified Wav2Vec2 deepfake voice detectors with explicit id2label mapping."""
    loaded = []
    try:
        import torch
        from transformers import AutoFeatureExtractor, AutoModelForAudioClassification

        model_ids = [
            "garystafford/wav2vec2-deepfake-voice-detector",
            "mo-thecreator/Deepfake-audio-detection",
        ]
        for mid in model_ids:
            try:
                extractor = AutoFeatureExtractor.from_pretrained(mid)
                model = AutoModelForAudioClassification.from_pretrained(mid)
                model.eval()
                loaded.append((mid, extractor, model))
            except Exception:
                continue
    except Exception:
        pass
    return loaded


# ==============================================================================
# 1. URL, DNS & CLOUD THREAT INTELLIGENCE ENGINE
# ==============================================================================
def check_dns_and_url_intel(raw_url: str, vt_api_key: str = "") -> dict:
    report = {
        "normalized_url": raw_url,
        "domain": "",
        "dns_valid": False,
        "resolved_ips": [],
        "final_url": raw_url,
        "redirect_hops": 0,
        "urlhaus_hit": False,
        "vt_malicious": 0,
        "flags": [],
    }
    url = raw_url.strip().rstrip(".,);]}>\"'")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    report["normalized_url"] = url

    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower()
    report["domain"] = domain
    if not domain:
        report["flags"].append("Malformed URL with missing domain host")
        return report

    shorteners = (
        "bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "cutt.ly",
        "ow.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "goo.gl",
    )
    if domain in shorteners or any(domain.endswith("." + s) for s in shorteners):
        report["flags"].append(f"URL shortener ({domain}) hides the true destination website")

    try:
        dns_resp = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "A"},
            timeout=2.5,
        ).json()
        answers = [a.get("data") for a in dns_resp.get("Answer", []) if a.get("type") == 1]
        if answers:
            report["dns_valid"] = True
            report["resolved_ips"] = answers
        else:
            report["flags"].append("Domain has no valid public DNS record (unregistered, suspended, or dead scam site)")
    except Exception:
        report["flags"].append("DNS lookup timed out or blocked")

    suspicious_tlds = (
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".icu",
        ".vip", ".click", ".buzz", ".sbs", ".cfd", ".live", ".online", ".site",
    )
    if domain.endswith(suspicious_tlds):
        report["flags"].append(f"High-risk top-level domain ({os.path.splitext(domain)[1]}) frequently used in scam links")
    if "xn--" in domain:
        report["flags"].append("Punycode homograph domain detected (spoofs official characters)")
    try:
        ipaddress.ip_address(domain)
        report["flags"].append("Raw IP address used instead of an official domain name")
    except ValueError:
        pass

    indian_brands = [
        "sbi", "hdfc", "icici", "axis", "pnb", "bob", "kotak", "paytm", "phonepe",
        "gpay", "bhim", "npci", "uidai", "aadhaar", "epfo", "irctc", "incometax",
        "parivahan", "challan", "bescom", "mahavitaran", "indiapost", "trai", "rbi", "lic",
    ]
    official_domains = (
        "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
        "pnbindia.in", "bankofbaroda.in", "kotak.com", "paytm.com", "phonepe.com",
        "npci.org.in", "uidai.gov.in", "epfindia.gov.in", "irctc.co.in",
        "incometax.gov.in", "parivahan.gov.in", "indiapost.gov.in", "trai.gov.in",
        "rbi.org.in", "licindia.in",
    )
    if any(b in domain for b in indian_brands) and not domain.endswith(official_domains):
        report["flags"].append("Impersonates an Indian bank, UPI service, or Government portal on an unofficial domain")

    if any(ext in parsed.path.lower() for ext in (".apk", ".exe", ".msi", ".bat", ".scr", ".vbs", ".ps1")):
        report["flags"].append("CRITICAL: Link points directly to a downloadable executable/APK file")

    try:
        resp = requests.head(url, allow_redirects=True, timeout=2.5, headers={"User-Agent": "Rakshak-CitizenGuard/5.6"})
        report["final_url"] = resp.url
        report["redirect_hops"] = len(resp.history)
        final_host = (urlparse(resp.url).hostname or "").lower()
        if len(resp.history) >= 2:
            report["flags"].append(f"Multi-hop redirect chain ({len(resp.history)} hops -> {final_host})")
        if any(ext in resp.url.lower() for ext in (".apk", ".exe", ".zip")):
            report["flags"].append(f"Redirects to a downloadable payload ({resp.url})")
    except Exception:
        pass

    try:
        uh = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=2.5).json()
        if uh.get("query_status") == "ok":
            report["urlhaus_hit"] = True
            threat_name = uh.get("threat", "Malware distribution")
            report["flags"].append(f"CONFIRMED MALWARE URL in Abuse.ch URLhaus database ({threat_name})")
    except Exception:
        pass

    if vt_api_key.strip():
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            vt_resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": vt_api_key.strip()},
                timeout=3.5,
            )
            if vt_resp.status_code == 200:
                stats = vt_resp.json()["data"]["attributes"]["last_analysis_stats"]
                mal = int(stats.get("malicious", 0))
                report["vt_malicious"] = mal
                if mal > 0:
                    report["flags"].append(f"VirusTotal flagged malicious by {mal} security engines")
        except Exception:
            pass

    return report


# ==============================================================================
# 2. 8-PASS UPI & QR CODE FORENSIC SCANNER
# ==============================================================================
def decode_qr_multipass(pil_img: Image.Image) -> list:
    """8-pass OpenCV + Otsu + CLAHE + Sharpened QR decoder for real-world photos and screenshots."""
    pil_upright = ImageOps.exif_transpose(pil_img).convert("RGB")
    rgb = np.array(pil_upright)
    bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)

    padded = cv2.copyMakeBorder(gray, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=255)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(padded)

    kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
    sharpened = cv2.filter2D(enhanced, -1, kernel)
    _, otsu = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    variants = [
        bgr,
        padded,
        enhanced,
        sharpened,
        otsu,
        cv2.resize(enhanced, None, fx=2.5, fy=2.5, interpolation=cv2.INTER_CUBIC),
        cv2.adaptiveThreshold(enhanced, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 5),
        cv2.bitwise_not(enhanced),
    ]

    detector = cv2.QRCodeDetector()
    found = []

    for img_var in variants:
        try:
            ok, decoded_info, _, _ = detector.detectAndDecodeMulti(img_var)
            if ok and decoded_info:
                for item in decoded_info:
                    if item and item.strip() and item.strip() not in found:
                        found.append(item.strip())
        except Exception:
            pass
        if not found:
            try:
                single, _, _ = detector.detectAndDecode(img_var)
                if single and single.strip() and single.strip() not in found:
                    found.append(single.strip())
            except Exception:
                pass
        if found:
            break
    return found


def audit_upi_or_qr_payload(payload: str, vt_api_key: str = "") -> dict:
    score = 0
    findings = []
    meta = {"Type": "Plain Text", "Raw Payload": payload}

    raw = payload.strip()
    low = raw.lower()

    if raw.startswith("000201"):
        meta["Type"] = "EMVCo / BharatQR Merchant Standard"
        findings.append("Valid EMVCo / NPCI BharatQR tag structure detected (000201)")
        upi_match = re.search(r"([a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64})", raw)
        if upi_match:
            extracted_vpa = upi_match.group(1)
            meta["Extracted VPA"] = extracted_vpa
            findings.append(f"Embedded Merchant VPA: {extracted_vpa}")
        else:
            score += 35
            findings.append("BharatQR payload lacks a recognizable UPI VPA identifier")
        if "5802in" not in low:
            score += 30
            findings.append("Country code is not 'IN' (India) — potential cross-border spoofed QR")

    elif low.startswith("upi://"):
        meta["Type"] = "UPI Payment Intent"
        parsed = urlparse(raw)
        action = parsed.path.lstrip("/").lower()
        params = parse_qs(parsed.query)

        pa = unquote(params.get("pa", [""])[0]).strip()
        pn = unquote(params.get("pn", [""])[0]).strip()
        am = params.get("am", [""])[0].strip()
        mc = params.get("mc", [""])[0].strip()
        orgid = params.get("orgid", [""])[0].strip()
        sign = params.get("sign", [""])[0].strip()
        url_param = unquote(params.get("url", [""])[0]).strip()

        meta.update({
            "Action": action or "pay",
            "Payee VPA (pa)": pa or "MISSING",
            "Payee Name (pn)": pn or "Not Specified",
            "Amount (am)": f"₹{am}" if am else "User-Entered",
            "Merchant Code (mc)": mc or "Peer-to-Peer (P2P)",
            "NPCI Signature (sign)": "Present" if sign else "Unsigned",
        })

        if action in ("collect", "mandate", "autopay"):
            score += 85
            findings.append(f"CRITICAL SCAM TRAP: QR triggers a UPI '{action.upper()}' pull request — scanning a QR is ONLY for paying money, NEVER for receiving money!")

        if am:
            try:
                amt_val = float(am)
                if amt_val > 0:
                    score += 25
                    findings.append(f"Pre-locked deduction amount of ₹{amt_val:,.2f} embedded in QR — verify before entering UPI PIN")
            except ValueError:
                score += 35
                findings.append(f"Malformed amount parameter in UPI string: '{am}'")

        valid_psp_handles = {
            "okicici", "okhdfcbank", "okaxis", "oksbi", "ybl", "ibl", "axl",
            "paytm", "ptyes", "ptaxis", "pthdfc", "ptsbi", "upi", "apl", "rapl",
            "icici", "sbi", "hdfcbank", "axisbank", "kotak", "indus", "federal",
            "aubank", "idfcfirst", "yesbank", "barodampay", "mahb", "cnrb", "uboi",
            "jio", "airtel", "freecharge", "ikwik", "sliceaxis", "naviaxis", "fam",
        }
        if not pa or "@" not in pa:
            score += 65
            findings.append("INVALID UPI QR: Missing or malformed Payee VPA ('pa' parameter)")
        else:
            user_part, psp_handle = pa.split("@", 1)
            if psp_handle.lower() not in valid_psp_handles:
                score += 25
                findings.append(f"Uncommon/unverified PSP bank handle '@{psp_handle}' — double-check recipient name in your UPI app")

            scam_keywords = [
                "refund", "cashback", "prize", "lottery", "reward", "kyc",
                "helpline", "support", "customercare", "care", "offer", "olx",
                "army", "soldier", "challan", "electricity", "customs", "claim",
            ]
            combined_identity = f"{user_part} {pn}".lower()
            if any(w in combined_identity for w in scam_keywords):
                score += 70
                findings.append("FRAUD ALERT: Payee VPA/name uses Indian refund, cashback, or customer-care scam keywords")

            corp_tokens = ("pvt", "ltd", "limited", "store", "mart", "enterprises", "corp", "gov", "ministry", "bank", "airways", "railways")
            if any(t in pn.lower() for t in corp_tokens) and not mc and not orgid and not sign:
                score += 30
                findings.append("Claims to be a company/government merchant in Payee Name, but lacks NPCI Merchant Code (mc), OrgID, and signature")

        if url_param:
            u_rep = check_dns_and_url_intel(url_param, vt_api_key)
            if u_rep["flags"]:
                score += len(u_rep["flags"]) * 25
                findings.extend([f"Embedded UPI URL ({url_param}): {flg}" for flg in u_rep["flags"]])

        if not findings:
            findings.append(f"Standard P2P/Merchant UPI QR for {pn or pa}. Always verify the recipient name on your UPI PIN screen.")

    elif low.startswith(("http://", "https://", "www.")):
        meta["Type"] = "Web URL / Download Link"
        url_rep = check_dns_and_url_intel(raw, vt_api_key)
        meta["Domain"] = url_rep["domain"]
        meta["DNS Valid"] = "Yes" if url_rep["dns_valid"] else "No"
        meta["Resolved IPs"] = ", ".join(url_rep["resolved_ips"]) or "None"
        findings.extend(url_rep["flags"])
        score += len(url_rep["flags"]) * 30
        if not findings:
            findings.append(f"Domain '{url_rep['domain']}' resolves cleanly with no known malware or phishing flags")
    else:
        urls = re.findall(r"(https?://[^\s]+|www\.[^\s]+)", raw)
        if urls:
            meta["Type"] = "Text with Embedded Link"
            for u in urls[:2]:
                u_rep = check_dns_and_url_intel(u, vt_api_key)
                findings.extend(u_rep["flags"])
                score += len(u_rep["flags"]) * 30
        else:
            findings.append("Non-payment plain text QR code (Wi-Fi / vCard / Serial ID)")

    return {"risk_score": min(score, 100), "findings": findings, "meta": meta}


# ==============================================================================
# 3. CALIBRATED MULTI-LAYER DEEPFAKE IMAGE & VIDEO + AUDIO FUSION FORENSICS
# ==============================================================================
def inspect_image_metadata_and_fft(pil_img: Image.Image) -> tuple:
    """Checks C2PA/AI signatures, physical camera EXIF provenance, and calibrated 2D FFT."""
    signals = []
    meta_score = 0.0
    has_verified_camera = False

    # 1. Check raw text chunks / XMP / C2PA signatures
    raw_info = str(pil_img.info).lower()
    ai_markers = [
        "c2pa", "jumbf", "midjourney", "dall-e", "stable diffusion",
        "flux", "imagen", "firefly", "generative", "ai-generated",
        "trainedalgorithmicmedia", "comfyui", "automatic1111",
    ]
    if any(m in raw_info for m in ai_markers):
        meta_score += 75.0
        signals.append("Embedded AI generator / C2PA cryptographic signature found in file headers")

    # 2. Check genuine smartphone/DSLR camera EXIF hardware metadata
    exif = pil_img.getexif()
    if exif:
        tag_map = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
        camera_make = str(tag_map.get("Make", "")).strip()
        camera_model = str(tag_map.get("Model", "")).strip()
        if camera_make and camera_model:
            has_verified_camera = True
            signals.append(f"Verified physical camera EXIF metadata: {camera_make} {camera_model}")

    if not has_verified_camera:
        meta_score += 18.0
        signals.append("No physical camera hardware EXIF tags (Make/Model) present")

    # 3. Calibrated 2D FFT check (downsampled to 512x512 so high-MP camera sharpness doesn't false-trigger)
    gray_512 = np.array(pil_img.convert("L").resize((512, 512)), dtype=np.float32)
    f_shift = np.fft.fftshift(np.fft.fft2(gray_512))
    mag = np.log1p(np.abs(f_shift))
    cy, cx = 256, 256
    r = 64
    center_energy = float(np.mean(mag[cy - r:cy + r, cx - r:cx + r]))
    outer_energy = float(np.mean(mag))
    freq_ratio = outer_energy / (center_energy + 1e-6)
    if freq_ratio < 0.42:
        meta_score += 18.0
        signals.append(f"Abnormal low-frequency FFT concentration ({freq_ratio:.3f}) typical of synthetic smoothing")

    return min(meta_score, 95.0), signals, has_verified_camera


def analyze_single_frame_forensics(pil_img: Image.Image, models: list) -> tuple:
    """Applies EXIF upright rotation, face-crop consensus, and camera provenance calibration."""
    pil_upright = ImageOps.exif_transpose(pil_img).convert("RGB")
    rgb = np.array(pil_upright)

    crops = [("Full Frame", pil_upright)]
    try:
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(64, 64))
        for idx, (x, y, w, h) in enumerate(faces[:2]):
            pad = int(0.28 * max(w, h))
            x1, y1 = max(0, x - pad), max(0, y - pad)
            x2, y2 = min(rgb.shape[1], x + w + pad), min(rgb.shape[0], y + h + pad)
            crops.append((f"Face Crop #{idx + 1}", Image.fromarray(rgb[y1:y2, x1:x2])))
    except Exception:
        pass

    ai_positive_tokens = {"fake", "ai", "artificial", "generated", "deepfake", "synthetic", "manipulated"}
    per_model_scores = []
    model_notes = []

    for model_name, clf in models:
        short_name = model_name.split("/")[-1]
        crop_scores = []
        for crop_label, crop_img in crops:
            try:
                preds = clf(crop_img)
                fake_prob = 0.0
                for p in preds:
                    lbl = p["label"].lower().strip()
                    if lbl == "ai" or any(tok in lbl for tok in ai_positive_tokens):
                        fake_prob = max(fake_prob, float(p["score"]) * 100.0)
                crop_scores.append(fake_prob)
                if fake_prob >= 55.0:
                    model_notes.append(f"{short_name} ({crop_label}): {fake_prob:.1f}% AI probability")
            except Exception:
                continue

        if crop_scores:
            if len(crop_scores) > 1:
                face_avg = float(np.mean(crop_scores[1:]))
                per_model_scores.append(0.70 * face_avg + 0.30 * crop_scores[0])
            else:
                per_model_scores.append(crop_scores[0])

    # Weighted consensus across neural models (prevents single-model false spikes on real photos)
    if len(per_model_scores) >= 2:
        neural_consensus = 0.55 * max(per_model_scores) + 0.45 * min(per_model_scores)
    elif per_model_scores:
        neural_consensus = per_model_scores[0]
    else:
        neural_consensus = 0.0

    heuristic_score, heuristic_signals, has_verified_camera = inspect_image_metadata_and_fft(pil_img)

    if has_verified_camera and heuristic_score < 50.0:
        combined = 0.55 * neural_consensus + 0.15 * heuristic_score
    else:
        combined = 0.72 * neural_consensus + 0.28 * heuristic_score

    return min(round(combined, 2), 99.9), model_notes + heuristic_signals


# ==============================================================================
# 4. DUAL-MODEL WAV2VEC2-XLSR AI VOICE CLONE DETECTOR
# ==============================================================================
def load_audio_mono_16k(audio_bytes: bytes, filename: str) -> tuple:
    ext = os.path.splitext(filename)[1].lower() or ".wav"
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp.write(audio_bytes)
        tmp_path = tmp.name

    try:
        try:
            import soundfile as sf
            from scipy.signal import resample_poly
            data, sr = sf.read(tmp_path, dtype="float32", always_2d=False)
            if data.ndim > 1:
                data = np.mean(data, axis=1)
            if sr != 16000:
                gcd = math.gcd(sr, 16000)
                data = resample_poly(data, 16000 // gcd, sr // gcd).astype(np.float32)
            return data, 16000
        except Exception:
            pass

        import librosa
        wav, sr = librosa.load(tmp_path, sr=16000, mono=True)
        return wav.astype(np.float32), 16000
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def analyze_voice_clone_forensics(wav: np.ndarray, sr: int, models: list) -> dict:
    import torch

    signals = []
    if wav is None or len(wav) < sr // 2:
        return {"clone_score": 0.0, "duration_sec": 0.0, "flatness": 0.0, "hf_ratio": 0.0, "signals": ["Audio clip too short (< 0.5s)"]}

    peak_amp = float(np.max(np.abs(wav))) + 1e-8
    wav_norm = wav / peak_amp
    active_idx = np.where(np.abs(wav_norm) > 0.025)[0]
    wav_speech = wav_norm[active_idx[0]:active_idx[-1]] if len(active_idx) > sr // 2 else wav_norm
    duration_sec = round(len(wav_speech) / float(sr), 2)

    fft_mag = np.abs(np.fft.rfft(wav_speech))
    freqs = np.fft.rfftfreq(len(wav_speech), d=1.0 / sr)
    total_energy = float(np.sum(fft_mag ** 2)) + 1e-9
    hf_energy = float(np.sum(fft_mag[freqs >= 6200] ** 2))
    hf_ratio = hf_energy / total_energy

    frame_len, hop = 512, 256
    frames = [wav_speech[i:i + frame_len] for i in range(0, max(1, len(wav_speech) - frame_len), hop)]
    flatness_vals, rms_vals = [], []
    for fr in frames[:400]:
        if len(fr) < frame_len:
            continue
        spec = np.abs(np.fft.rfft(fr * np.hanning(frame_len))) + 1e-10
        flatness_vals.append(float(np.exp(np.mean(np.log(spec))) / np.mean(spec)))
        rms_vals.append(float(np.sqrt(np.mean(fr ** 2))))

    flatness = float(np.mean(flatness_vals)) if flatness_vals else 0.0
    rms_cv = (float(np.std(rms_vals)) / (float(np.mean(rms_vals)) + 1e-6)) if rms_vals else 1.0

    dsp_score = 0.0
    if hf_ratio < 0.0018:
        dsp_score += 28.0
        signals.append(f"Sharp high-frequency spectral roll-off above 6.2 kHz ({hf_ratio:.5f}) typical of neural TTS vocoders")
    if flatness < 0.0032:
        dsp_score += 24.0
        signals.append(f"Unnaturally smooth harmonic spectral flatness ({flatness:.5f}) lacking natural vocal breath noise")
    if rms_cv < 0.55:
        dsp_score += 18.0
        signals.append(f"Uniform synthetic syllable cadence (amplitude variation {rms_cv:.2f})")

    win_size = int(sr * 4.5)
    chunks = []
    if len(wav_speech) <= win_size:
        chunks.append(wav_speech)
    else:
        step = max(sr * 2, (len(wav_speech) - win_size) // 5)
        for start in range(0, len(wav_speech) - win_size + 1, step):
            chunks.append(wav_speech[start:start + win_size])
            if len(chunks) >= 6:
                break

    neural_scores = []
    for mid, extractor, model in models:
        short_name = mid.split("/")[-1]
        id2label = getattr(model.config, "id2label", {0: "real", 1: "fake"})
        fake_idx = None
        for idx_k, lbl_v in id2label.items():
            lbl_low = str(lbl_v).lower()
            if any(tok in lbl_low for tok in ("fake", "spoof", "ai", "synthetic", "generated")):
                fake_idx = int(idx_k)
                break
        if fake_idx is None:
            fake_idx = 1 if len(id2label) > 1 else 0

        chunk_probs = []
        for ch in chunks:
            try:
                inputs = extractor(ch, sampling_rate=sr, return_tensors="pt", padding=True)
                with torch.no_grad():
                    logits = model(**inputs).logits
                    probs = torch.softmax(logits, dim=-1)[0].cpu().numpy()
                fake_prob = float(probs[fake_idx]) * 100.0
                chunk_probs.append(fake_prob)
            except Exception:
                continue

        if chunk_probs:
            peak_p = max(chunk_probs)
            neural_scores.append(peak_p)
            if peak_p >= 45.0:
                signals.append(f"{short_name} flagged synthetic voice ({peak_p:.1f}% AI probability)")

    if neural_scores:
        peak_neural = max(neural_scores)
        mean_neural = float(np.mean(neural_scores))
        final_clone = max(peak_neural, 0.78 * peak_neural + 0.22 * mean_neural + 0.20 * dsp_score)
    else:
        final_clone = dsp_score
        signals.append("Acoustic DSP fallback active (neural audio weights unavailable)")

    return {
        "clone_score": round(min(final_clone, 99.9), 2),
        "duration_sec": duration_sec,
        "flatness": round(flatness, 5),
        "hf_ratio": round(hf_ratio, 5),
        "signals": signals,
    }


def analyze_video_forensics(video_bytes: bytes, filename: str, models: list) -> dict:
    """Audits BOTH visual frames (face-crops + FFT + neural) AND the video's embedded audio track."""
    ext = os.path.splitext(filename)[1] or ".mp4"
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp.write(video_bytes)
        tmp_path = tmp.name

    frame_scores = []
    collected_signals = []
    sampled_previews = []
    temporal_diffs = []
    audio_clone_score = 0.0

    try:
        cap = cv2.VideoCapture(tmp_path)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if total_frames <= 0:
            total_frames = 120

        indices = np.linspace(0, max(0, total_frames - 1), num=min(16, max(1, total_frames)), dtype=int)
        prev_gray = None

        for idx in indices:
            cap.set(cv2.CAP_PROP_POS_FRAMES, int(idx))
            ok, frame = cap.read()
            if not ok or frame is None:
                continue
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            gray_small = cv2.resize(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY), (128, 128))
            if prev_gray is not None:
                diff = float(np.mean(np.abs(gray_small.astype(np.float32) - prev_gray.astype(np.float32))))
                temporal_diffs.append(diff)
            prev_gray = gray_small

            pil_frame = Image.fromarray(rgb)
            f_score, f_signals = analyze_single_frame_forensics(pil_frame, models)
            frame_scores.append(f_score)
            for s in f_signals:
                if s not in collected_signals:
                    collected_signals.append(s)
            if len(sampled_previews) < 4:
                sampled_previews.append((int(idx), f_score, pil_frame))

        cap.release()

        # Audit embedded audio track inside video for AI TTS voiceovers / voice cloning
        try:
            import librosa
            wav_vid, sr_vid = librosa.load(tmp_path, sr=16000, mono=True)
            if wav_vid is not None and len(wav_vid) > 16000:
                aud_models = load_audio_models()
                aud_res = analyze_voice_clone_forensics(wav_vid, sr_vid, aud_models)
                audio_clone_score = float(aud_res.get("clone_score", 0.0))
                if audio_clone_score >= 40.0:
                    collected_signals.insert(
                        0,
                        f"AI-Generated / Synthetic Voiceover Track Detected ({audio_clone_score:.1f}% AI voice probability)",
                    )
                for a_sig in aud_res.get("signals", []):
                    if a_sig not in collected_signals:
                        collected_signals.append(f"[Audio Track] {a_sig}")
        except Exception:
            pass
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    if not frame_scores:
        return {
            "final_score": round(audio_clone_score, 2),
            "peak_score": round(audio_clone_score, 2),
            "frames_analyzed": 0,
            "signals": collected_signals or ["Could not decode video frames"],
            "previews": [],
        }

    top_k = sorted(frame_scores, reverse=True)[:4]
    visual_peak_mean = float(np.mean(top_k))
    visual_peak_max = float(max(frame_scores))

    if temporal_diffs and float(np.std(temporal_diffs)) > 14.5:
        visual_peak_mean = min(99.9, visual_peak_mean + 12.0)
        collected_signals.append(f"High frame-to-frame temporal pixel jitter (std={np.std(temporal_diffs):.2f})")

    visual_score = max(visual_peak_mean, 0.85 * visual_peak_max)
    final_score = max(visual_score, audio_clone_score)

    return {
        "final_score": round(min(final_score, 99.9), 2),
        "peak_score": round(max(visual_peak_max, audio_clone_score), 2),
        "frames_analyzed": len(frame_scores),
        "signals": collected_signals,
        "previews": sampled_previews,
    }


# ==============================================================================
# 5. SMS, WHATSAPP & DIGITAL ARREST FULL-MESSAGE ANALYZER
# ==============================================================================
def analyze_sms_and_whatsapp(text: str, vt_api_key: str = "") -> dict:
    clf = load_phishing_pipeline()
    ai_peak = 0.0

    if clf is not None:
        chunks = [text[i:i + 480] for i in range(0, len(text), 400)][:4]
        for ch in chunks:
            try:
                out = clf(ch)[0]
                lbl = out["label"].lower()
                sc = float(out["score"]) * 100.0 if any(k in lbl for k in ("phish", "spam", "1")) else (1.0 - float(out["score"])) * 100.0
                ai_peak = max(ai_peak, sc)
            except Exception:
                pass

    scam_rules = [
        (r"(digital arrest|cbi|ncb|enforcement directorate|\bed\b|cyber cell|narcotics|customs parcel|fedex|dhl.*parcel|trai.*disconnect|sim.*block)", 50, "Impersonates Police / CBI / TRAI / Customs ('Digital Arrest' or parcel extortion scam)"),
        (r"(electricity.*disconnect|power.*cut|bijli.*kat|bescom|mahavitaran|uppcl|water.*disconnect|gas.*connection)", 45, "Fake utility bill disconnection urgency scam"),
        (r"(kyc.*update|kyc.*expire|pan.*card.*block|aadhaar.*suspend|account.*block|account.*freeze|sbi.*yono|hdfc.*kyc|icici.*kyc)", 45, "Fake Bank KYC / PAN / Aadhaar account suspension lure"),
        (r"(traffic.*challan|parivahan|echallan|e-challan|rto.*challan|\.apk)", 50, "Fake RTO Traffic e-Challan APK banking Trojan lure"),
        (r"(part.?time job|work from home|ghar baithe|telegram.*task|youtube.*like|prepaid.*task|daily.*income|earning.*app)", 45, "Telegram / WhatsApp prepaid task & fake job investment scam"),
        (r"(lottery|kbc|kaun banega|prize.*money|winner|cashback.*won|claim.*reward|gift.*voucher)", 45, "Fake lottery / KBC / reward claim scam"),
        (r"(share.*otp|otp.*bhejo|cvv|upi.*pin|anydesk|teamviewer|rustdesk|quicksupport|screen.*share)", 60, "Requests secret OTP/PIN or remote screen-sharing app takeover"),
        (r"(loan.*approved|instant.*loan|cibil|harassment|morphed.*photo|nude.*video|sextortion)", 45, "Predatory instant loan / extortion threat indicators"),
    ]

    rule_score = 0
    reasons = []
    for pat, weight, desc in scam_rules:
        if re.search(pat, text, re.IGNORECASE):
            rule_score += weight
            reasons.append(desc)

    cleaned_for_urls = re.sub(r"hxxps?://", "https://", text, flags=re.IGNORECASE)
    urls = list(dict.fromkeys(re.findall(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)", cleaned_for_urls)))
    url_reports = []
    for u in urls[:4]:
        rep = check_dns_and_url_intel(u, vt_api_key)
        url_reports.append(rep)
        if rep["flags"]:
            rule_score += len(rep["flags"]) * 28
            reasons.extend([f"Link ({u}): {flg}" for flg in rep["flags"]])

    upi_ids = list(dict.fromkeys(re.findall(r"\b[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}\b", text)))
    upi_ids = [u for u in upi_ids if not u.lower().endswith((".com", ".in", ".org", ".net", ".gov", ".co"))]
    phones = list(dict.fromkeys(re.findall(r"(?:\+91[\-\s]?)?[6-9]\d{9}\b", text)))

    if upi_ids and rule_score > 0:
        reasons.append(f"Suspicious UPI handle(s) in message: {', '.join(upi_ids)}")
    if phones and rule_score > 0:
        reasons.append(f"Scammer mobile number(s) detected (report on Sanchar Saathi Chakshu): {', '.join(phones)}")

    final_risk = min(100.0, max(ai_peak, 0.50 * ai_peak + 0.80 * rule_score))
    return {
        "risk_score": round(final_risk, 1),
        "ai_score": round(ai_peak, 1),
        "rule_score": min(100, rule_score),
        "reasons": reasons,
        "urls": url_reports,
        "upi_ids": upi_ids,
        "phones": phones,
    }


# ==============================================================================
# 6. UNIVERSAL VIRUS, APK, PDF, DOCX, ZIP & BINARY MALWARE SCANNER
# ==============================================================================
def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    probs = counts[counts > 0] / len(arr)
    return float(-np.sum(probs * np.log2(probs)))


def inspect_raw_buffer_heuristics(buf: bytes, name: str) -> tuple:
    score = 0
    threats = []
    ext = os.path.splitext(name)[1].lower()
    header = buf[:32]

    if header.startswith(b"MZ") and ext not in (".exe", ".dll", ".scr", ".sys", ".msi", ".com"):
        score += 80
        threats.append(f"[{name}] Windows PE Executable (MZ header) disguised as '{ext}'")
    if header.startswith(b"\x7fELF") and ext in (".pdf", ".jpg", ".jpeg", ".png", ".mp4", ".doc", ".docx", ".txt"):
        score += 80
        threats.append(f"[{name}] Linux ELF binary disguised as '{ext}'")
    if re.search(r"\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|mp4|txt)\.(exe|apk|bat|cmd|scr|vbs|js|ps1|jar)$", name.lower()):
        score += 85
        threats.append(f"[{name}] Double-extension social engineering trap detected")

    if ext == ".pdf" or header.startswith(b"%PDF"):
        pdf_triggers = [
            (rb"/JavaScript\b|/JS\b", 45, "PDF contains embedded JavaScript code"),
            (rb"/OpenAction\b|/AA\b", 35, "PDF executes automatic actions immediately when opened"),
            (rb"/Launch\b", 65, "PDF attempts to launch external system commands (/Launch)"),
            (rb"/EmbeddedFile\b", 30, "PDF hides an embedded file attachment inside its stream"),
            (rb"/RichMedia\b|/JBIG2Decode\b", 30, "PDF uses high-risk exploit vector stream (/JBIG2Decode or /RichMedia)"),
        ]
        for pat, pts, desc in pdf_triggers:
            if re.search(pat, buf):
                score += pts
                threats.append(f"[{name}] {desc}")

    if ext in (".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".rtf"):
        if b"vbaProject.bin" in buf or re.search(rb"(AutoOpen|Document_Open|Workbook_Open|Auto_Open)", buf, re.IGNORECASE):
            score += 65
            threats.append(f"[{name}] Contains auto-executing VBA Macro payload (vbaProject.bin / AutoOpen)")
        if b'TargetMode="External"' in buf and (b"http://" in buf or b"https://" in buf or b"file://" in buf):
            score += 55
            threats.append(f"[{name}] Remote template injection link detected inside Office XML relationships")
        if b"oleObject" in buf or b"Equation.3" in buf:
            score += 50
            threats.append(f"[{name}] Embedded OLE / Equation Editor exploit object detected")

    if ext == ".apk" or (header.startswith(b"PK\x03\x04") and b"AndroidManifest.xml" in buf[:8192]):
        dangerous_apk_perms = {
            b"BIND_ACCESSIBILITY_SERVICE": "Requests Accessibility Service takeover (allows Trojan to read screen & click buttons automatically)",
            b"RECEIVE_SMS": "Intercepts incoming bank OTPs and SMS alerts (RECEIVE_SMS)",
            b"READ_SMS": "Reads private SMS inbox & financial messages (READ_SMS)",
            b"SEND_SMS": "Silently sends SMS messages from victim's SIM (SEND_SMS)",
            b"SYSTEM_ALERT_WINDOW": "Draws fake login overlays on top of UPI & banking apps (SYSTEM_ALERT_WINDOW)",
            b"REQUEST_INSTALL_PACKAGES": "Dropper capability to silently install hidden secondary APKs",
            b"READ_CALL_LOG": "Harvests call logs for extortion scams",
            b"RECORD_AUDIO": "Background microphone spying capability",
        }
        apk_hits = []
        try:
            with zipfile.ZipFile(io.BytesIO(buf), "r") as zf:
                names = zf.namelist()
                if "AndroidManifest.xml" in names:
                    manifest_raw = zf.read("AndroidManifest.xml")
                    for perm_b, desc in dangerous_apk_perms.items():
                        if perm_b in manifest_raw:
                            apk_hits.append(desc)
                for dex_name in [n for n in names if n.endswith(".dex")][:4]:
                    dex_data = zf.read(dex_name)
                    if b"SmsManager" in dex_data or b"getDefaultSmsPackage" in dex_data:
                        apk_hits.append("Contains programmatic SMS forwarding/hijacking code (SmsManager)")
                    if b"DexClassLoader" in dex_data or b"InMemoryDexClassLoader" in dex_data:
                        apk_hits.append("Loads encrypted malware payloads dynamically at runtime (DexClassLoader)")
                    if b"MediaProjection" in dex_data:
                        apk_hits.append("Contains live screen-recording spyware API (MediaProjection)")
        except Exception:
            for perm_b, desc in dangerous_apk_perms.items():
                if perm_b in buf:
                    apk_hits.append(desc)

        if apk_hits:
            unique_apk = list(dict.fromkeys(apk_hits))
            score += min(90, len(unique_apk) * 24)
            threats.extend([f"[{name}] {h}" for h in unique_apk])

    generic_sigs = [
        (rb"powershell(\.exe)?\s+.*-(enc|encodedcommand|w\s+hidden|nop)", 55, "Obfuscated hidden PowerShell command execution"),
        (rb"(cmd\.exe\s*/c|/bin/sh\s+-i|/bin/bash\s+-i|nc\s+-e|bash\s+-i\s+>&\s+/dev/tcp)", 60, "Interactive reverse-shell backdoor command"),
        (rb"(VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection)", 50, "Windows process hollowing / memory injection APIs"),
        (rb"(SetWindowsHookEx|GetAsyncKeyState|GetKeyState)", 45, "Keylogger keystroke-capture APIs"),
        (rb"(vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete\s+catalog|bcdedit.*recoveryenabled\s+no)", 75, "Ransomware shadow-copy & recovery deletion command"),
        (rb"(WScript\.Shell|CreateObject\(\"Scripting\.FileSystemObject\"\)|ShellExecute)", 45, "Malicious VBScript/JScript system execution call"),
        (rb"(eval\(base64_decode|exec\(base64\.b64decode|marshal\.loads\(zlib\.decompress)", 45, "Multi-layer encoded script payload execution"),
    ]
    for pat, pts, desc in generic_sigs:
        if re.search(pat, buf, re.IGNORECASE):
            score += pts
            threats.append(f"[{name}] {desc}")

    entropy = calculate_shannon_entropy(buf)
    already_compressed = (".zip", ".gz", ".7z", ".rar", ".jpg", ".jpeg", ".png", ".webp", ".mp4", ".mp3", ".m4a", ".pdf", ".apk", ".docx", ".xlsx", ".pptx")
    if entropy > 7.45 and ext not in already_compressed:
        score += 35
        threats.append(f"[{name}] High Shannon entropy ({entropy:.2f}/8.0) indicates encrypted/packed malware binary")

    return min(score, 100), threats, entropy


def scan_file_for_viruses(file_bytes: bytes, filename: str, vt_api_key: str = "") -> dict:
    md5_h = hashlib.md5(file_bytes).hexdigest()
    sha1_h = hashlib.sha1(file_bytes).hexdigest()
    sha256_h = hashlib.sha256(file_bytes).hexdigest()
    ext = os.path.splitext(filename)[1].lower()

    total_risk, threats, root_entropy = inspect_raw_buffer_heuristics(file_bytes, filename)
    vt_report = None
    mb_report = None
    archive_files_scanned = 1

    if ext == ".zip" and file_bytes[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
                inner_names = [n for n in zf.namelist() if not n.endswith("/")][:20]
                archive_files_scanned = len(inner_names)
                for inner_name in inner_names:
                    try:
                        inner_bytes = zf.read(inner_name)
                        if len(inner_bytes) > 25 * 1024 * 1024:
                            continue
                        sub_risk, sub_threats, _ = inspect_raw_buffer_heuristics(inner_bytes, f"{filename} -> {inner_name}")
                        total_risk = max(total_risk, sub_risk)
                        threats.extend(sub_threats)
                    except RuntimeError:
                        total_risk = max(total_risk, 55)
                        threats.append(f"[{filename} -> {inner_name}] Password-encrypted ZIP archive (frequently used to evade antivirus scanners)")
                        break
        except Exception:
            pass

    if vt_api_key.strip():
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256_h}",
                headers={"x-apikey": vt_api_key.strip()},
                timeout=4.0,
            )
            if resp.status_code == 200:
                attrs = resp.json()["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})
                mal = int(stats.get("malicious", 0))
                susp = int(stats.get("suspicious", 0))
                tot = sum(int(v) for v in stats.values())
                vt_report = {"malicious": mal, "suspicious": susp, "total": tot}
                if mal > 0:
                    total_risk = max(total_risk, min(100, 65 + mal * 5))
                    threats.insert(0, f"CRITICAL: VirusTotal flagged this file as MALICIOUS by {mal}/{tot} antivirus engines!")
                elif susp > 0:
                    total_risk = max(total_risk, 45)
                    threats.insert(0, f"VirusTotal flagged suspicious behavior in {susp}/{tot} engines")
        except Exception:
            pass

    try:
        mb = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256_h},
            timeout=3.5,
        ).json()
        if mb.get("query_status") == "ok" and mb.get("data"):
            item = mb["data"][0]
            sig = item.get("signature") or "Confirmed Malware"
            mb_report = {"signature": sig}
            total_risk = 100
            threats.insert(0, f"CONFIRMED VIRUS / TROJAN: Exact SHA-256 match in Abuse.ch MalwareBazaar ({sig})")
    except Exception:
        pass

    return {
        "filename": filename,
        "size_kb": round(len(file_bytes) / 1024.0, 2),
        "md5": md5_h,
        "sha1": sha1_h,
        "sha256": sha256_h,
        "entropy": round(root_entropy, 3),
        "files_inspected": archive_files_scanned,
        "risk_score": min(total_risk, 100),
        "threats": list(dict.fromkeys(threats)),
        "vt_report": vt_report,
        "mb_report": mb_report,
    }


# ==============================================================================
# 7. LIVE NETWORK, SOCKET & THREAT REPUTATION AUDITOR
# ==============================================================================
def lookup_ip_reputation(ip: str, abuse_key: str = "") -> dict:
    info = {"ip": ip, "hostname": "-", "country": "Unknown", "isp": "Unknown", "abuse_score": 0}
    try:
        info["hostname"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp", timeout=2.0).json()
        if geo.get("status") == "success":
            info["country"] = geo.get("country", "Unknown")
            info["isp"] = geo.get("isp", "Unknown")
    except Exception:
        pass

    if abuse_key.strip():
        try:
            ab = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": abuse_key.strip(), "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=2.5,
            ).json()
            info["abuse_score"] = int(ab.get("data", {}).get("abuseConfidenceScore", 0))
        except Exception:
            pass
    return info


# ==============================================================================
# 8. UNIVERSAL AI AGENT (ANSWERS ANY QUESTION — CYBERCRIME OR GENERAL KNOWLEDGE)
# ==============================================================================
def ask_universal_ai_agent(prompt: str, chat_history: list, groq_key: str = "", gemini_key: str = "", last_scan: str = "") -> str:
    """Answers ANY question (cybersecurity or general) via Groq/Gemini LLM or free live Wikipedia/DuckDuckGo fallback."""
    system_prompt = (
        "You are Rakshak AI Sahayak, an authoritative, helpful, and accurate AI assistant built into India's Citizen Cyber Defense Portal. "
        "You can answer ANY question — whether about cybersecurity, Indian cyber laws (IT Act 2000, BNS, 1930 helpline), science, coding, "
        "history, education, or everyday topics. When relevant to cyber fraud in India, remind citizens of helpline 1930 and cybercrime.gov.in. "
        f"Latest scan context in user's session: {last_scan or 'None'}."
    )

    if groq_key.strip():
        try:
            msgs = [{"role": "system", "content": system_prompt}]
            for m in chat_history[-6:]:
                msgs.append({"role": m["role"], "content": m["content"]})
            msgs.append({"role": "user", "content": prompt})
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {groq_key.strip()}", "Content-Type": "application/json"},
                json={"model": "llama-3.3-70b-versatile", "messages": msgs, "temperature": 0.4, "max_tokens": 900},
                timeout=12.0,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
        except Exception:
            pass

    if gemini_key.strip():
        try:
            resp = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_key.strip()}",
                headers={"Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": f"{system_prompt}\n\nUser Question: {prompt}"}]}]},
                timeout=12.0,
            )
            if resp.status_code == 200:
                return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            pass

    q_low = prompt.lower().strip()

    if any(w in q_low for w in ["apk", "installed", "virus", "hacked", "screen share", "anydesk", "teamviewer"]):
        return (
            "### 🚨 Emergency Steps If You Installed a Malicious APK or Screen-Sharing App\n"
            "1. **Turn on Airplane Mode immediately** (disconnect mobile data & Wi-Fi) so the Trojan cannot forward bank OTPs.\n"
            "2. Go to **Settings → Apps**, locate the unknown app (*RTO Challan, PM Kisan, Customer Support, etc.*), and **Uninstall** it (if blocked, disable it under *Settings → Accessibility* or *Device Admin Apps* first).\n"
            "3. Call your bank's official helpline from another phone to temporarily freeze UPI/net-banking.\n"
            "4. If any money was debited, call **`1930`** or report at **[cybercrime.gov.in](https://cybercrime.gov.in)** immediately."
        )
    if any(w in q_low for w in ["digital arrest", "cbi", "ncb", "customs", "trai", "parcel", "enforcement directorate"]):
        return (
            "### 🚨 'Digital Arrest' Is 100% a Cyber Scam\n"
            "- **Indian Police, CBI, ED, RBI, Customs, or TRAI NEVER conduct interrogations or arrests on WhatsApp/Skype video calls.**\n"
            "- Hang up immediately and never transfer money to any 'RBI verification account'.\n"
            "- Report the caller's number on **Sanchar Saathi (Chakshu)** at `sancharsaathi.gov.in` and dial **`1930`**."
        )
    if any(w in q_low for w in ["upi", "debited", "fraud", "scam", "utr", "1930", "refund"]):
        return (
            "### 🚨 Golden Hour UPI / Bank Fraud Recovery Protocol\n"
            "1. **Dial `1930` immediately** (24×7 National Cyber Crime Helpline) with your **12-digit UPI UTR / Transaction Reference Number**.\n"
            "2. File a formal complaint online at **[cybercrime.gov.in](https://cybercrime.gov.in)** under *Report Cyber Crime → Financial Fraud*.\n"
            "3. Submit the acknowledgement number to your bank branch within 24 hours."
        )

    clean_topic = re.sub(r"^(what is|who is|tell me about|explain|define|how does|what are)\s+", "", q_low).strip(" ?.!")
    try:
        ddg = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": prompt, "format": "json", "no_html": 1, "skip_disambig": 1},
            timeout=4.0,
        ).json()
        abstract = ddg.get("AbstractText") or ddg.get("Answer")
        if abstract:
            src = ddg.get("AbstractURL", "")
            return f"{abstract}\n\n*(Source: {src})*" if src else abstract
    except Exception:
        pass

    try:
        search_resp = requests.get(
            "https://en.wikipedia.org/w/api.php",
            params={"action": "opensearch", "search": clean_topic or prompt, "limit": 1, "format": "json"},
            headers={"User-Agent": "Rakshak-CitizenPortal/5.6"},
            timeout=4.0,
        ).json()
        if len(search_resp) >= 4 and search_resp[1]:
            title = search_resp[1][0]
            summary_resp = requests.get(
                f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote(title)}",
                headers={"User-Agent": "Rakshak-CitizenPortal/5.6"},
                timeout=4.0,
            ).json()
            extract = summary_resp.get("extract")
            page_url = summary_resp.get("content_urls", {}).get("desktop", {}).get("page", "")
            if extract:
                return f"**{title}**\n\n{extract}\n\n*(Reference: {page_url})*"
    except Exception:
        pass

    return (
        f"I searched my built-in knowledge base for **\"{prompt}\"**, and to unlock full conversational AI answers on every complex topic, "
        "paste a free **Groq API Key** (`console.groq.com`) or **Google Gemini API Key** (`aistudio.google.com`) in the left sidebar under **Universal AI Agent Keys**.\n\n"
        f"**Current Session Context:** `{last_scan or 'Ready for scan'}`"
    )


# ==============================================================================
# SIDEBAR & PORTAL HEADER
# ==============================================================================
with st.sidebar:
    st.markdown("### 🛡️ Rakshak")
    st.caption("National Citizen Cyber Defense & AI Forensics")

    st.error("**🇮🇳 National Cyber Helpline: `1930`**\n\nReport Online: **cybercrime.gov.in**\n\nReport Scam Calls/SMS: **sancharsaathi.gov.in**")

    st.markdown("#### 🤖 Universal AI Agent Keys (Free)")
    groq_api_key = st.text_input(
        "Groq API Key (Llama-3.3-70B — Free)",
        value=os.getenv("GROQ_API_KEY", ""),
        type="password",
        help="Optional free key from console.groq.com enables full conversational AI answers on any topic.",
    )
    gemini_api_key = st.text_input(
        "Google Gemini API Key (Free)",
        value=os.getenv("GEMINI_API_KEY", ""),
        type="password",
        help="Optional free key from aistudio.google.com.",
    )

    st.markdown("#### 🔑 Virus & IP Threat Keys (Optional)")
    vt_api_key = st.text_input(
        "VirusTotal API v3 Key (70+ AV Engines)",
        value=os.getenv("VIRUSTOTAL_API_KEY", ""),
        type="password",
    )
    abuse_api_key = st.text_input(
        "AbuseIPDB API Key (IP Threat Score)",
        value=os.getenv("ABUSEIPDB_API_KEY", ""),
        type="password",
    )

st.markdown(
    """
    <div class="main-banner">
        <h2 style="margin:0;">🛡️ Rakshak — National Citizen Cybercrime & Virus Defense Portal</h2>
        <p style="margin:6px 0 0 0; opacity:0.9;">
            Multi-Modal AI Forensics for UPI/QR Fraud • Digital Arrest & WhatsApp Scams • Deepfake Videos & Voice Clones • APK/PDF/ZIP Virus Scanning
        </p>
    </div>
    <div class="helpline-strip">
        <strong>🚨 Emergency Golden Hour Alert:</strong> Lost money in a UPI or cyber scam? Dial <strong>1930</strong> immediately with your 12-digit UTR number or file an urgent complaint at <strong>cybercrime.gov.in</strong>.
    </div>
    """,
    unsafe_allow_html=True,
)

# ==============================================================================
# 8-TAB CYBER DEFENSE WORKSPACE
# ==============================================================================
tab_qr, tab_sms, tab_df, tab_voice, tab_virus, tab_net, tab_ai, tab_guide = st.tabs([
    "📱 UPI & QR Scam Guard",
    "📩 SMS & WhatsApp Shield",
    "🎭 Deepfake Image & Video",
    "🎙️ AI Voice Clone Detector",
    "🦠 Virus, APK & Doc Scanner",
    "🌐 Live Network Guard",
    "🤖 Rakshak AI Agent",
    "🇮🇳 Citizen Action Guide",
])

# ------------------------------------------------------------------------------
# TAB 1: UPI & QR SCAM GUARD
# ------------------------------------------------------------------------------
with tab_qr:
    st.subheader("📱 8-Pass UPI Payment & Malicious QR Code Scanner")
    st.write("Upload a screenshot or photo of any QR code before scanning it with GPay, PhonePe, Paytm, or BHIM.")

    c_q1, c_q2 = st.columns(2)
    with c_q1:
        qr_img_file = st.file_uploader("Upload QR Screenshot or Photo", type=["png", "jpg", "jpeg", "webp"], key="qr_up")
        raw_qr_input = st.text_input("Or paste UPI string / QR link directly:", placeholder="upi://collect?pa=refund@ybl&pn=CustomerCare&am=4999")
    with c_q2:
        qr_cam = st.camera_input("Or scan live using Camera", key="qr_cam")

    active_qr_img = qr_img_file or qr_cam
    if st.button("🔍 Scan & Audit QR Code", type="primary", key="run_qr"):
        decoded_list = []
        if active_qr_img is not None:
            decoded_list.extend(decode_qr_multipass(Image.open(active_qr_img)))
        if raw_qr_input.strip() and raw_qr_input.strip() not in decoded_list:
            decoded_list.append(raw_qr_input.strip())

        if not decoded_list:
            st.error("No QR code could be decoded. Ensure the full square QR code is visible without glare.")
        else:
            for payload in decoded_list:
                audit = audit_upi_or_qr_payload(payload, vt_api_key)
                st.session_state["last_scan"] = f"QR/UPI Scan -> Risk {audit['risk_score']}/100"

                m1, m2 = st.columns([1, 2])
                m1.metric("QR Fraud Risk Score", f"{audit['risk_score']} / 100")
                m2.code(payload, language="text")

                if audit["risk_score"] >= 60:
                    st.markdown("<div class='verdict-danger'><strong>🚨 HIGH DANGER — DO NOT SCAN OR ENTER YOUR UPI PIN</strong></div>", unsafe_allow_html=True)
                elif audit["risk_score"] >= 25:
                    st.markdown("<div class='verdict-warn'><strong>⚠️ CAUTION — VERIFY PAYEE IDENTITY & AMOUNT BEFORE PAYING</strong></div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div class='verdict-safe'><strong>✅ VERIFIED STRUCTURE — NO KNOWN FRAUD INDICATORS</strong></div>", unsafe_allow_html=True)

                st.json(audit["meta"])
                for f in audit["findings"]:
                    st.write(f"- {f}")

# ------------------------------------------------------------------------------
# TAB 2: SMS & WHATSAPP SCAM SHIELD
# ------------------------------------------------------------------------------
with tab_sms:
    st.subheader("📩 SMS, WhatsApp & 'Digital Arrest' Scam Detector")
    msg_input = st.text_area(
        "Paste the suspicious SMS, WhatsApp forward, or job/challan alert:",
        height=150,
        placeholder="Paste full SMS or WhatsApp message here...",
    )

    if st.button("🛡️ Scan Message & Links", type="primary", key="run_sms"):
        if not msg_input.strip():
            st.warning("Please paste a message first.")
        else:
            with st.spinner("Running Rakshak BERT transformer + Indian cybercrime rules + live DNS/URLhaus checks..."):
                s_res = analyze_sms_and_whatsapp(msg_input, vt_api_key)

            st.session_state["last_scan"] = f"SMS/WhatsApp Scan -> Risk {s_res['risk_score']}%"
            c1, c2, c3 = st.columns(3)
            c1.metric("Overall Scam Risk", f"{s_res['risk_score']}%")
            c2.metric("AI Classifier Score", f"{s_res['ai_score']}%")
            c3.metric("Links Extracted", len(s_res["urls"]))

            if s_res["risk_score"] >= 60:
                st.markdown("<div class='verdict-danger'><strong>🚨 SCAM / PHISHING ALERT — DO NOT CLICK LINKS, CALL BACK, OR SHARE OTP</strong></div>", unsafe_allow_html=True)
            elif s_res["risk_score"] >= 30:
                st.markdown("<div class='verdict-warn'><strong>⚠️ SUSPICIOUS MESSAGE — VERIFY THROUGH OFFICIAL APP OR 1930</strong></div>", unsafe_allow_html=True)
            else:
                st.markdown("<div class='verdict-safe'><strong>✅ LOW PHISHING RISK</strong></div>", unsafe_allow_html=True)

            for r in s_res["reasons"]:
                st.write(f"- {r}")

            if s_res["urls"]:
                st.markdown("**Extracted URL Live Intelligence:**")
                for u_info in s_res["urls"]:
                    st.write(f"- `{u_info['normalized_url']}` → DNS Valid: **{u_info['dns_valid']}** | IPs: `{', '.join(u_info['resolved_ips']) or 'None'}`")

# ------------------------------------------------------------------------------
# TAB 3: CALIBRATED MULTI-LAYER DEEPFAKE IMAGE & VIDEO + AUDIO FUSION FORENSICS
# ------------------------------------------------------------------------------
with tab_df:
    st.subheader("🎭 Deepfake & AI-Generated Media Forensics (Images & Videos)")
    st.write("Audits **both** visual frames (EXIF orientation + face crops + calibrated FFT + dual Vision Transformers) **and** embedded video voiceovers.")

    df_file = st.file_uploader(
        "Upload suspicious photo or video",
        type=["jpg", "jpeg", "png", "webp", "mp4", "mov", "avi", "mkv"],
        key="df_up",
    )

    if df_file is not None and st.button("🔬 Run Rakshak Deepfake Forensics", type="primary", key="run_df"):
        models = load_deepfake_pipeline()
        ext = os.path.splitext(df_file.name)[1].lower()

        if ext in (".mp4", ".mov", ".avi", ".mkv"):
            with st.spinner("Sampling 16 video frames, extracting faces, auditing audio voiceover & running FFT forensics..."):
                v_res = analyze_video_forensics(df_file.read(), df_file.name, models)

            score = v_res["final_score"]
            st.session_state["last_scan"] = f"Video Deepfake Scan ({df_file.name}) -> {score:.1f}% AI"
            c1, c2, c3 = st.columns(3)
            c1.metric("AI / Deepfake Probability", f"{score:.2f}%")
            c2.metric("Peak Signal Score", f"{v_res['peak_score']:.2f}%")
            c3.metric("Frames Audited", v_res["frames_analyzed"])

            if score >= 55.0:
                st.markdown(f"<div class='verdict-danger'><strong>🚨 AI-GENERATED / DEEPFAKE MEDIA DETECTED ({score:.1f}% confidence)</strong></div>", unsafe_allow_html=True)
            elif score >= 30.0:
                st.markdown(f"<div class='verdict-warn'><strong>⚠️ SUSPICIOUS SYNTHETIC ARTIFACTS DETECTED ({score:.1f}%)</strong></div>", unsafe_allow_html=True)
            else:
                st.markdown(f"<div class='verdict-safe'><strong>✅ LIKELY AUTHENTIC CAMERA FOOTAGE ({100 - score:.1f}% real confidence)</strong></div>", unsafe_allow_html=True)

            for sig in v_res["signals"]:
                st.write(f"- {sig}")

            if v_res["previews"]:
                cols = st.columns(len(v_res["previews"]))
                for col, (f_idx, f_sc, f_img) in zip(cols, v_res["previews"]):
                    col.image(f_img, caption=f"Frame #{f_idx} ({f_sc:.1f}% AI)", use_container_width=True)
        else:
            pil_img = Image.open(df_file)
            pil_display = ImageOps.exif_transpose(pil_img).convert("RGB")
            c_img, c_res = st.columns([1, 1.3])
            with c_img:
                st.image(pil_display, caption="Uploaded Image", use_container_width=True)
            with c_res:
                with st.spinner("Analyzing EXIF camera provenance, face crops & calibrated 2D FFT spectrum..."):
                    score, signals = analyze_single_frame_forensics(pil_img, models)

                st.session_state["last_scan"] = f"Image Forensics ({df_file.name}) -> {score:.1f}% AI"
                st.metric("AI Manipulation / Generation Probability", f"{score:.2f}%")

                if score >= 55.0:
                    st.markdown(f"<div class='verdict-danger'><strong>🚨 AI-GENERATED / MANIPULATED IMAGE ({score:.1f}% AI confidence)</strong></div>", unsafe_allow_html=True)
                elif score >= 30.0:
                    st.markdown(f"<div class='verdict-warn'><strong>⚠️ SUSPICIOUS / MISSING CAMERA PROVENANCE ({score:.1f}%)</strong></div>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<div class='verdict-safe'><strong>✅ AUTHENTIC PHOTOGRAPH ({100 - score:.2f}% real confidence)</strong></div>", unsafe_allow_html=True)

                for sig in signals:
                    st.write(f"- {sig}")

# ------------------------------------------------------------------------------
# TAB 4: DUAL-MODEL AI VOICE CLONE DETECTOR
# ------------------------------------------------------------------------------
with tab_voice:
    st.subheader("🎙️ Dual-Model AI Voice Clone & Synthetic Speech Detector")
    st.write("Detects AI voice cloners (**ElevenLabs, Kokoro, Speechify, Polly, RVC**) using **Wav2Vec2-XLSR neural detectors**, **silence-trimmed 4.5s speech windows**, and **vocoder spectral forensics**.")

    aud_file = st.file_uploader("Upload voice note or call recording", type=["wav", "mp3", "ogg", "flac", "m4a"], key="aud_up")
    if aud_file is not None and st.button("🎧 Detect AI Voice Clone", type="primary", key="run_aud"):
        st.audio(aud_file)
        with st.spinner("Decoding audio, trimming silence & running Rakshak Wav2Vec2-XLSR voice clone models..."):
            try:
                wav_data, sr = load_audio_mono_16k(aud_file.read(), aud_file.name)
                aud_models = load_audio_models()
                v_audit = analyze_voice_clone_forensics(wav_data, sr, aud_models)

                score = v_audit["clone_score"]
                st.session_state["last_scan"] = f"Voice Clone Scan ({aud_file.name}) -> {score:.1f}% AI"

                c1, c2, c3 = st.columns(3)
                c1.metric("AI Voice Clone Probability", f"{score:.2f}%")
                c2.metric("Active Speech Analyzed", f"{v_audit['duration_sec']} sec")
                c3.metric("High-Freq Vocoder Ratio", f"{v_audit['hf_ratio']}")

                if score >= 55.0:
                    st.markdown(f"<div class='verdict-danger'><strong>🚨 AI-CLONED / SYNTHETIC VOICE DETECTED ({score:.1f}% confidence)</strong></div>", unsafe_allow_html=True)
                elif score >= 35.0:
                    st.markdown(f"<div class='verdict-warn'><strong>⚠️ SUSPICIOUS VOCAL ARTIFACTS — VERIFY CALLER IDENTITY ({score:.1f}%)</strong></div>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<div class='verdict-safe'><strong>✅ NATURAL HUMAN VOICE ({100 - score:.1f}% human confidence)</strong></div>", unsafe_allow_html=True)

                for sig in v_audit["signals"]:
                    st.write(f"- {sig}")
            except Exception as e:
                st.error(f"Could not decode audio file ({e}). Please upload a `.wav`, `.mp3`, `.flac`, or `.ogg` audio file.")

# ------------------------------------------------------------------------------
# TAB 5: UNIVERSAL VIRUS, APK, PDF, DOCX & ZIP SCANNER
# ------------------------------------------------------------------------------
with tab_virus:
    st.subheader("🦠 Universal Virus, APK, PDF, DOCX & ZIP Malware Scanner")
    v_file = st.file_uploader("Upload any file (.apk, .exe, .pdf, .docx, .xlsx, .zip, .bat, .ps1)", key="virus_up")
    if v_file is not None and st.button("🛡️ Deep Scan File for Viruses", type="primary", key="run_virus"):
        with st.spinner("Inspecting binary headers, unpacking APK/DOCX/ZIP structures & querying global threat feeds..."):
            rep = scan_file_for_viruses(v_file.read(), v_file.name, vt_api_key)

        st.session_state["last_scan"] = f"Virus Scan ({rep['filename']}) -> Risk {rep['risk_score']}/100"
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Virus / Malware Risk", f"{rep['risk_score']} / 100")
        m2.metric("Shannon Entropy", f"{rep['entropy']} / 8.0")
        m3.metric("Items Inspected", rep["files_inspected"])
        if rep["vt_report"]:
            m4.metric("VirusTotal AV Hits", f"{rep['vt_report']['malicious']} / {rep['vt_report']['total']}")
        else:
            m4.metric("File Size", f"{rep['size_kb']} KB")

        if rep["risk_score"] >= 60:
            st.markdown("<div class='verdict-danger'><strong>🚨 VIRUS / TROJAN / EXPLOIT DETECTED — DO NOT OPEN OR INSTALL</strong></div>", unsafe_allow_html=True)
        elif rep["risk_score"] >= 25:
            st.markdown("<div class='verdict-warn'><strong>⚠️ SUSPICIOUS FILE STRUCTURE — TREAT WITH EXTREME CAUTION</strong></div>", unsafe_allow_html=True)
        else:
            st.markdown("<div class='verdict-safe'><strong>✅ CLEAN — NO VIRUS SIGNATURES, MACROS, OR TROJAN PERMISSIONS FOUND</strong></div>", unsafe_allow_html=True)

        for t in rep["threats"]:
            st.write(f"- {t}")

        with st.expander("🔐 Cryptographic Hashes (MD5 / SHA-1 / SHA-256)"):
            st.code(
                f"File:    {rep['filename']}\n"
                f"MD5:     {rep['md5']}\n"
                f"SHA-1:   {rep['sha1']}\n"
                f"SHA-256: {rep['sha256']}",
                language="text",
            )

# ------------------------------------------------------------------------------
# TAB 6: LIVE NETWORK & SOCKET THREAT GUARD (MACOS + LINUX SAFE)
# ------------------------------------------------------------------------------
with tab_net:
    st.subheader("🌐 Live Network, Interface & Socket Threat Guard")
    if st.button("📡 Run Live Network & Socket Audit", type="primary", key="run_net"):
        if_rows = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface, addr_list in addrs.items():
            is_up = stats[iface].isup if iface in stats else False
            ipv4s = [a.address for a in addr_list if a.family == socket.AF_INET]
            if ipv4s:
                if_rows.append({"Interface": iface, "Status": "UP" if is_up else "DOWN", "IPv4 Address": ", ".join(ipv4s)})

        if if_rows:
            st.markdown("**Active Network Interfaces:**")
            st.dataframe(if_rows, use_container_width=True)

        raw_conns = []
        try:
            for c in psutil.net_connections(kind="inet"):
                p_name = "System"
                if c.pid:
                    try:
                        p_name = psutil.Process(c.pid).name()
                    except Exception:
                        pass
                raw_conns.append((p_name, c.pid, c.status, c.laddr, c.raddr))
        except psutil.AccessDenied:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    for c in proc.net_connections(kind="inet"):
                        raw_conns.append((proc.info["name"] or "App", proc.info["pid"], c.status, c.laddr, c.raddr))
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue

        conns = []
        unique_ips = set()
        listening_ports = []

        for proc_name, pid, status, laddr, raddr in raw_conns:
            if status == "LISTEN" and laddr:
                listening_ports.append({"Process": proc_name, "PID": pid, "Local IP": laddr.ip, "Listening Port": laddr.port})
            elif status == "ESTABLISHED" and raddr:
                rip = raddr.ip
                try:
                    ip_obj = ipaddress.ip_address(rip)
                    if not ip_obj.is_private and not ip_obj.is_loopback:
                        unique_ips.add(rip)
                        conns.append({"Process": proc_name, "PID": pid, "Remote IP": rip, "Port": raddr.port})
                except ValueError:
                    pass

        suspicious_c2_ports = {4444, 5555, 6666, 6667, 1337, 31337, 9001, 9050, 8443}
        ip_intel = {}
        if unique_ips:
            ip_list = list(unique_ips)[:25]
            with ThreadPoolExecutor(max_workers=10) as ex:
                results = ex.map(lambda ip: lookup_ip_reputation(ip, abuse_api_key), ip_list)
                ip_intel = dict(zip(ip_list, results))

        st.markdown("**Live Outbound Public IP Connections:**")
        if conns:
            out_rows = []
            for item in conns:
                intel = ip_intel.get(item["Remote IP"], {})
                port_flag = "⚠️ High-Risk Port" if item["Port"] in suspicious_c2_ports else "Normal"
                out_rows.append({
                    "Process": item["Process"],
                    "Remote IP": item["Remote IP"],
                    "Hostname": intel.get("hostname", "-"),
                    "Port": item["Port"],
                    "Port Risk": port_flag,
                    "Country": intel.get("country", "Unknown"),
                    "ISP / Cloud": intel.get("isp", "Unknown"),
                    "AbuseIPDB Score": f"{intel.get('abuse_score', 0)}%",
                })
            st.dataframe(out_rows, use_container_width=True)
        else:
            st.success("Zero suspicious external connections active right now.")

        if listening_ports:
            with st.expander(f"🔌 Open Listening Server Ports ({len(listening_ports)} active)"):
                st.dataframe(listening_ports, use_container_width=True)

# ------------------------------------------------------------------------------
# TAB 7: UNIVERSAL AI AGENT (ANSWERS ANY QUESTION)
# ------------------------------------------------------------------------------
with tab_ai:
    st.subheader("🤖 Rakshak AI Sahayak — Universal Assistant")
    st.caption("Ask ANY question — cybercrime emergency help, Indian IT Act laws, coding, science, general knowledge, or scan results.")

    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = [
            {"role": "assistant", "content": "Namaste! I am **Rakshak AI Sahayak**. Ask me anything — from cybercrime emergency steps (`1930`) to science, history, coding, or general knowledge!"}
        ]

    for msg in st.session_state["chat_history"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    user_q = st.chat_input("Ask Rakshak any question here...")
    if user_q:
        st.session_state["chat_history"].append({"role": "user", "content": user_q})
        with st.chat_message("user"):
            st.markdown(user_q)

        with st.chat_message("assistant"):
            with st.spinner("Rakshak AI is thinking..."):
                reply = ask_universal_ai_agent(
                    user_q,
                    st.session_state["chat_history"],
                    groq_api_key,
                    gemini_api_key,
                    st.session_state.get("last_scan", ""),
                )
            st.markdown(reply)
        st.session_state["chat_history"].append({"role": "assistant", "content": reply})

# ------------------------------------------------------------------------------
# TAB 8: INTERACTIVE CITIZEN ACTION GUIDE & COMPLAINT GENERATOR
# ------------------------------------------------------------------------------
with tab_guide:
    st.subheader("🇮🇳 Citizen Action Guide & Official Cybercrime Complaint Generator")

    g_col1, g_col2 = st.columns([1.1, 1])
    with g_col1:
        st.markdown("#### 📋 Official Government of India Portals")
        st.markdown(
            """
            | Portal / Helpline | Official Purpose | Access |
            | :--- | :--- | :--- |
            | **National Cyber Helpline (`1930`)** | Freeze fraudulent UPI/bank transfers within the Golden Hour | Dial **`1930`** (24×7 Toll-Free) |
            | **National Cyber Crime Portal** | File formal complaints for financial fraud, deepfakes & harassment | **cybercrime.gov.in** |
            | **Sanchar Saathi — Chakshu (DoT)** | Report scam calls, WhatsApp impersonation & fake SMS | **sancharsaathi.gov.in** |
            | **CEIR Portal** | Block and trace lost/stolen mobile phones across India | **ceir.gov.in** |
            | **RBI Sachet Portal** | Check if an investment/loan app is RBI/SEBI registered | **sachet.rbi.org.in** |
            | **CERT-In** | Report critical malware, ransomware & security incidents | **cert-in.org.in** |
            """
        )

    with g_col2:
        st.markdown("#### 📝 Instant Cybercrime Complaint Draft Generator")
        victim_name = st.text_input("Your Full Name", placeholder="e.g., Rahul Sharma")
        incident_type = st.selectbox(
            "Type of Cybercrime",
            ["UPI / Bank Financial Fraud", "Fake APK / Malware Hacking", "Digital Arrest / Impersonation Call", "Deepfake / AI Voice Clone Extortion", "SMS / WhatsApp Phishing Scam"],
        )
        amount_lost = st.text_input("Amount Lost (₹) & 12-Digit UTR Number", placeholder="e.g., ₹15,000 | UTR: 432198765432")
        suspect_info = st.text_input("Scammer Phone / UPI ID / Website", placeholder="e.g., +91-98XXXXXXXX / scammer@ybl")

        if st.button("📄 Generate Official Complaint Draft", type="primary", key="gen_complaint"):
            today_str = datetime.now().strftime("%d %B %Y, %I:%M %p")
            draft = (
                f"To,\nThe Nodal Cyber Cell Officer / Bank Branch Manager,\n"
                f"Subject: Urgent Cybercrime Complaint & Transaction Freeze Request ({incident_type})\n\n"
                f"Respected Sir/Madam,\n"
                f"I, {victim_name or '[Your Name]'}, wish to report an incident of {incident_type} that occurred on {today_str}.\n"
                f"- Financial Loss & UTR Reference: {amount_lost or 'N/A'}\n"
                f"- Suspect Phone / UPI ID / URL: {suspect_info or 'N/A'}\n"
                f"- Technical Forensics Note: {st.session_state.get('last_scan', 'Verified via Rakshak Cyber Defense Portal')}\n\n"
                f"I request you to urgently freeze the beneficiary account/merchant ID under RBI Golden Hour guidelines and register this complaint on cybercrime.gov.in (Helpline 1930).\n\n"
                f"Sincerely,\n{victim_name or '[Your Name]'}"
            )
            st.text_area("Copy & Paste into cybercrime.gov.in or Email to Your Bank:", value=draft, height=230)
            st.download_button("⬇️ Download Complaint Letter (.txt)", data=draft, file_name="Rakshak_Cybercrime_Complaint.txt")
