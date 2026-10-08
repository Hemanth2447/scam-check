# ==========================================================
# SENTRY PAY - BANK SCAM DETECTION API
# app.py
# ==========================================================

import json

import time

import re
from pathlib import Path

from fastapi import FastAPI, Request
from pydantic import BaseModel
import os
import requests
HF_MODEL_URL = "https://api-inference.huggingface.co/models/Nope112300/sentrypay-distilbert"
HF_TOKEN = os.getenv("HF_TOKEN", "")
HF_HEADERS = {"Authorization": f"Bearer {HF_TOKEN}"}
# ==========================================================
# PATHS
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

MODEL_DIR = BASE_DIR / "model"

HEADERS_FILE = (
    BASE_DIR
    / "assets"
    / "sender_validation"
    / "verified_bank_headers.json"
)

# ==========================================================
# LOAD VERIFIED HEADERS
# ==========================================================

print()
print("=" * 60)
print(" LOADING VERIFIED TRAI HEADERS ")
print("=" * 60)

VERIFIED_HEADERS = {}
if HEADERS_FILE.exists():
    with open(
        HEADERS_FILE,
        "r",
        encoding="utf-8"
    ) as f:
        VERIFIED_HEADERS = json.load(f)
    print(f"[SUCCESS] Loaded {len(VERIFIED_HEADERS)} Verified Headers.")
else:
    print(f"[WARNING] Headers file not found at {HEADERS_FILE}")

# ==========================================================
# LABELS (STRICTLY SAFE AND SCAM)
# ==========================================================

LABELS = {
    0: "SAFE",
    1: "SCAM"
}

# ==========================================================
# KEYWORD MATCHING ENGINE (EXTENSIVE LIST)
# ==========================================================

SCAM_KEYWORDS = [
    # Financial Urgency / Threats / Extortion
    "account blocked", "account suspended", "account deactivated", "account freeze", "account closed",
    "card blocked", "debit card blocked", "credit card blocked", "sim blocked", "sim will be blocked",
    "electricity disconnect", "power disconnected", "power cut tonight", "bill overdue disconnect",
    "fine of rs", "penalty of rs", "legal notice", "arrest warrant", "police case", "court order",
    "action required immediately", "within 24 hours", "within 12 hours", "urgent update",
    "unauthorized transaction reported",

    # KYC & Verification Traps
    "kyc expired", "update kyc", "complete your kyc", "pan card not linked", "aadhaar not linked",
    "pan update pending", "kyc verification failed", "unblock account click", "re-activate your account",

    # Lottery, Rewards, Cashbacks & Fake Lures
    "lottery", "won lottery", "you have won", "won prize", "winner", "lucky winner",
    "congratulations you won", "lucky draw", "claim your reward", "claim reward", "reward points expire",
    "redeem reward points", "cashback of rs", "cashback credited claim", "cash prize", "free gift",
    "gift voucher worth", "scratch card", "claim bonus", "claim refund", "income tax refund",
    "tax refund approved", "pre-approved loan of rs", "instant loan without cibil",

    # Phishing Calls-to-Action & Credential Harvesting
    "click here to", "click link to", "visit link", "login to verify", "update here:",
    "download apk", "install quicksupport", "install anydesk", "install rustdesk", "install teamviewer",
    "support apk", "customer care call", "toll free number:", "share otp to cancel", "forward this sms",
    "enter upi pin to receive", "send upi pin", "enter pin to get money",

    # Suspicious URL Shorteners & Suspicious Domains
    "bit.ly/", "tinyurl.com/", "is.gd/", "cutt.ly/", "rb.gy/", "t.co/", "shorturl.at/",
    ".apk", ".xyz", ".top", ".ru", ".tk", ".work", ".click", ".link/",

    # Work-from-Home & Telegram Scams
    "part time job", "work from home earn", "daily income rs", "earn 2000-5000",
    "telegram task", "like youtube videos", "crypto investment earn", "double your money"
]

SAFE_KEYWORDS = [
    # Banking Transactions
    "debited by", "debited with", "credited with", "credited by", "deposited", "withdrawn from",
    "spent on", "avl bal", "available balance", "ac bal", "account balance", "a/c no", "a/c x",
    "a/c *", "acct ending", "ref no", "ref no:", "rrn", "rrn:", "utr", "utr:", "txn id",
    "transaction id", "transaction successful", "payment successful", "money sent to", "received rs",
    "salary credited", "interest credited", "atm cash withdrawal", "neft", "rtgs", "imps",
    "upi ref", "mandate created", "autopay", "cleared through cheque",

    # Legitimate Authentication & Verification Codes
    "otp", "one time password", "verification code", "security code", "login otp", "auth code",
    "secret otp", "do not share", "valid for", "expires in", "sample test", "birth and death",
    "registration otp", "password reset code",

    # Telecom & Data Notifications (Airtel, Jio, Vi, BSNL)
    "consumed", "data consumed", "daily data limit", "data balance", "50% alert", "90% alert",
    "100% alert", "pack validity", "recharge successful", "bill paid", "plan expires",
    "validity recharge", "talktime", "unlimited calls", "airtel", "jio", "vodafone", "vi ", "bsnl",

    # Utilities & Booking Services
    "welcome to", "order confirmed", "order delivered", "shipped", "out for delivery",
    "pnr", "booking confirmed", "ticket confirmed", "flight status", "electricity bill paid",
    "gas bill paid", "water bill paid", "statement for your", "thank you for using",

    # Multilingual Telecom / Service (e.g. Tamil alerts)
    "டேட்டா", "ரீசார்ஜ்", "இருப்பு", "செலுத்தப்பட்டது", "வங்கி"
]

def keyword_match_classification(message: str, sender: str = ""):
    """
    Classifies a message as SAFE or SCAM strictly using comprehensive keyword matching.
    """
    clean_text = (message or "").strip().lower()
    clean_sender = (sender or "").strip().lower()

    # 1. Check for SCAM keywords
    matched_scam = [kw for kw in SCAM_KEYWORDS if kw in clean_text]
    
    # Suspicious external links
    if re.search(r'https?://[^\s]+(?:\.xyz|\.top|\.ru|\.tk|\.click)', clean_text) or ".apk" in clean_text or "http://" in clean_text:
        matched_scam.append("untrusted_link")

    # 2. Check for SAFE keywords
    matched_safe = [kw for kw in SAFE_KEYWORDS if kw in clean_text]

    # Decision logic
    if matched_scam:
        confidence = min(98.0, 85.0 + len(matched_scam) * 4.0)
        return "SCAM", confidence, matched_scam

    if matched_safe:
        confidence = min(98.0, 88.0 + len(matched_safe) * 3.0)
        return "SAFE", confidence, matched_safe

    # Check verified TRAI sender formats (e.g., AD-HDFCBK, JM-GCCCRP-S, AT-AIRTEL-S)
    if re.match(r'^[a-z]{2}-[a-z0-9]{5,8}(-[a-z0-9])?$', clean_sender):
        return "SAFE", 90.0, ["verified_sender_format"]

    # If no risk or threat triggers are found, classify as SAFE
    return "SAFE", 85.0, ["no_suspicious_patterns"]

# ==========================================================
# EXPLANATION TEMPLATES
# ==========================================================

SAFE_VERIFIED = [
    "The message was classified as a legitimate banking notification.",
    "The sender ID matches an officially registered banking header.",
    "The calculated risk score is very low."
]

SAFE_UNVERIFIED = [
    "The message was classified as a legitimate notification.",
    "The sender ID could not be verified in the national bank registry.",
    "The calculated risk score is low."
]

MODERATE_VERIFIED = [
    "The message requires additional attention.",
    "The sender ID is officially verified.",
    "Verify the information before taking action."
]

MODERATE_UNVERIFIED = [
    "The message requires additional attention.",
    "The sender ID could not be verified.",
    "Proceed carefully before responding."
]

SCAM_VERIFIED = [
    "The message has been classified as high risk.",
    "The sender ID is verified but the content contains deceptive scam triggers.",
    "Avoid acting until independently verified."
]

SCAM_UNVERIFIED = [
    "The message has been classified as high risk.",
    "The sender ID could not be verified.",
    "Do not interact with the message or open any links."
]

# ==========================================================
# FASTAPI
# ==========================================================

app = FastAPI(
    title="Sentry Pay Scam Detection API",
    version="1.0.0"
)

@app.middleware("http")
async def handle_head_requests(request: Request, call_next):
    if request.method == "HEAD":
        request.scope["method"] = "GET"

    response = await call_next(request)
    return response

@app.get("/")
def root():
    return {
        "message": "SentryPay Scam Detection API",
        "status": "running"
    }

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "SentryPay Scam Detection API"
    }

# ==========================================================
# REQUEST MODEL
# ==========================================================

class AnalyzeRequest(BaseModel):
    sender: str = ""
    message: str

print()
print("=" * 60)
print(" API READY ")
print("=" * 60)

# ==========================================================
# SENDER NORMALIZATION
# ==========================================================

def normalize_sender(sender: str):
    if sender is None:
        return ""

    sender = sender.strip().upper()

    if sender == "":
        return ""

    sender = sender.replace(" ", "")

    parts = sender.split("-")

    for part in parts:
        part = part.strip()
        if 6 <= len(part) <= 7:
            return part

    if 6 <= len(sender) <= 7:
        return sender

    return ""

# ==========================================================
# VERIFY TRAI HEADER
# ==========================================================

def verify_sender(sender: str):
    sender = normalize_sender(sender)

    if sender == "":
        return {
            "verified": False,
            "status": "NOT_PROVIDED",
            "bank_name": None,
            "sender_id": ""
        }

    if sender in VERIFIED_HEADERS:
        return {
            "verified": True,
            "status": "VERIFIED",
            "bank_name": VERIFIED_HEADERS[sender],
            "sender_id": sender
        }

    return {
        "verified": False,
        "status": "UNVERIFIED",
        "bank_name": None,
        "sender_id": sender
    }

# ==========================================================
# MODEL & KEYWORD PREDICTION
# ==========================================================
def predict_message(message: str, sender: str = ""):
  # 1. Primary Keyword Matching Analysis
  kw_prediction, kw_confidence, matched_keywords = (
      keyword_match_classification(message, sender=sender)
  )

  # 2. Try Hugging Face Serverless Inference API
  try:
    response = requests.post(
        HF_MODEL_URL, headers=HF_HEADERS, json={"inputs": message}, timeout=5
    )

    if response.status_code == 200:
      hf_data = response.json()

      # Flatten nested lists if returned
      if isinstance(hf_data, list) and len(hf_data) > 0:
        if isinstance(hf_data[0], list):
          hf_results = hf_data[0]
        else:
          hf_results = hf_data

        # Map predictions to probabilities
        prob_map = {
            item["label"].upper(): item["score"] * 100 for item in hf_results
        }
        p_safe = prob_map.get("SAFE", prob_map.get("LABEL_0", 0.0))
        p_scam = prob_map.get("SCAM", prob_map.get("LABEL_1", 0.0))

        # Combine Keyword rules with HF Model probabilities
        if kw_prediction == "SCAM":
          final_pred = "SCAM"
          scam_prob = max(85.0, p_scam)
          safe_prob = 100.0 - scam_prob
          conf = kw_confidence
        elif kw_prediction == "SAFE":
          final_pred = "SAFE"
          safe_prob = max(85.0, p_safe)
          scam_prob = 100.0 - safe_prob
          conf = kw_confidence
        else:
          top_item = max(hf_results, key=lambda x: x["score"])
          raw_label = top_item["label"].upper()

          if raw_label in ["SCAM", "LABEL_1"]:
            final_pred = "SCAM"
            scam_prob = p_scam
            safe_prob = 100.0 - p_scam
          else:
            final_pred = "SAFE"
            safe_prob = p_safe
            scam_prob = 100.0 - p_safe

          conf = top_item["score"] * 100

        return {
            "prediction": final_pred,
            "confidence": round(conf, 2),
            "safe_probability": round(safe_prob, 2),
            "scam_probability": round(scam_prob, 2),
            "matched_keywords": matched_keywords,
        }
  except Exception as e:
    print(f"Hugging Face API call failed: {e}")

  # 3. Fallback to pure Keyword Engine
  scam_prob = 90.0 if kw_prediction == "SCAM" else 10.0
  safe_prob = 100.0 - scam_prob

  return {
      "prediction": kw_prediction,
      "confidence": round(kw_confidence, 2),
      "safe_probability": round(safe_prob, 2),
      "scam_probability": round(scam_prob, 2),
      "matched_keywords": matched_keywords,
  }

# ==========================================================
# RISK SCORE
# ==========================================================

def calculate_risk(
    prediction,
    verified
):
    risk = prediction["scam_probability"]

    if verified and risk < 70:
        risk = max(0, risk - 10)

    risk = max(0, min(100, risk))

    if risk <= 40:
        level = "SAFE"
    elif risk <= 70:
        level = "MODERATE"
    else:
        level = "HIGH_RISK"

    return {
        "risk_score": round(risk, 2),
        "risk_level": level
    }

print()
print("[SUCCESS] Prediction Engine Loaded.")
print("[SUCCESS] Sender Validator Loaded.")
print("[SUCCESS] Risk Engine Loaded.")

# ==========================================================
# EXPLANATION ENGINE
# ==========================================================

def generate_explanation(
    prediction,
    risk_level,
    sender_info,
    matched_keywords=None
):
    verified = sender_info["verified"]

    if prediction == "SAFE":
        if verified:
            return SAFE_VERIFIED
        return SAFE_UNVERIFIED

    if risk_level == "MODERATE":
        if verified:
            return MODERATE_VERIFIED
        return MODERATE_UNVERIFIED

    if verified:
        return SCAM_VERIFIED
    return SCAM_UNVERIFIED

# ==========================================================
# BUILD RESPONSE
# ==========================================================

def build_response(
    sender,
    message
):
    sender_info = verify_sender(sender)
    prediction = predict_message(message, sender=sender)
    risk = calculate_risk(
        prediction,
        sender_info["verified"]
    )
    reasons = generate_explanation(
        prediction["prediction"],
        risk["risk_level"],
        sender_info,
        matched_keywords=prediction.get("matched_keywords")
    )

    return {
        "prediction": prediction["prediction"],
        "classification_confidence": prediction["confidence"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "sender_status": sender_info["status"],
        "sender_id": sender_info["sender_id"],
        "bank_name": sender_info["bank_name"],
        "reasons": reasons,
        "matched_keywords": prediction.get("matched_keywords", [])
    }

# ==========================================================
# MAIN API
# ==========================================================

@app.post("/analyze")
def analyze(data: AnalyzeRequest):
    result = build_response(
        sender=data.sender,
        message=data.message
    )
    return result

# ==========================================================
# LOCAL RUN
# ==========================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )