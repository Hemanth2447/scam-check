# ==========================================================
# SENTRY PAY - BANK SCAM DETECTION API
# app.py
#
# Part 1
# Imports
# Configuration
# Model Loading
# Sender Header Loading
# FastAPI Initialization
# ==========================================================

import json
import torch
import time
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification
)


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
# LOAD MODEL
# ==========================================================

print("=" * 60)
print(" LOADING SENTRY MODEL ")
print("=" * 60)

DEVICE = torch.device(
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)

print(f"Device : {DEVICE}")

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_DIR
)

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_DIR
)

model.to(DEVICE)

model.eval()
torch.set_num_threads(1)

print("[SUCCESS] Model Loaded.")

# ==========================================================
# LOAD VERIFIED HEADERS
# ==========================================================

print()

print("=" * 60)
print(" LOADING VERIFIED TRAI HEADERS ")
print("=" * 60)

with open(
    HEADERS_FILE,
    "r",
    encoding="utf-8"
) as f:

    VERIFIED_HEADERS = json.load(f)

print(
    f"[SUCCESS] Loaded {len(VERIFIED_HEADERS)} Verified Headers."
)

# ==========================================================
# LABELS
# ==========================================================

LABELS = {

    0: "SAFE",

    1: "SCAM",

    2: "NON_BANK"

}

# ==========================================================
# EXPLANATION TEMPLATES
# ==========================================================

SAFE_VERIFIED = [

    "The message was classified as a legitimate banking notification.",

    "The sender ID matches an officially registered banking header.",

    "The calculated risk score is very low."

]

SAFE_UNVERIFIED = [

    "The message was classified as a legitimate banking notification.",

    "The sender ID could not be verified.",

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

    "The sender ID is verified but the content appears suspicious.",

    "Avoid acting until independently verified."

]

SCAM_UNVERIFIED = [

    "The message has been classified as high risk.",

    "The sender ID could not be verified.",

    "Do not interact with the message until verified."

]

NON_BANK_RESPONSE = [

    "This message is not related to banking.",

    "Use Sentry AI if you still wish to analyse it."

]

# ==========================================================
# FASTAPI
# ==========================================================

app = FastAPI(

    title="Sentry Pay Scam Detection API",

    version="1.0.0"

)
from fastapi import Request

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

    # Split using '-'
    parts = sender.split("-")

    # Find only valid 6 or 7 character header
    for part in parts:
        part = part.strip()
        if 6 <= len(part) <= 7:

            return part

    # If no '-' and already 6-7 chars
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
# MODEL PREDICTION
# ==========================================================

def predict_message(message: str):

    inputs = tokenizer(

        message,

        return_tensors="pt",

        truncation=True,

        padding=True,

        max_length=96

    )

    inputs = {

        k: v.to(DEVICE)

        for k, v in inputs.items()

    }
    start = time.time()

    with torch.inference_mode():

        outputs = model(**inputs)

    print(f"Inference Time: {time.time() - start:.2f} sec")

    probabilities = torch.softmax(

        outputs.logits,

        dim=1

    )[0]

    safe_prob = float(probabilities[0]) * 100

    scam_prob = float(probabilities[1]) * 100

    non_bank_prob = float(probabilities[2]) * 100

    prediction = int(torch.argmax(probabilities))

    confidence = float(probabilities[prediction]) * 100

    return {

        "prediction": LABELS[prediction],

        "confidence": round(confidence, 2),

        "safe_probability": round(safe_prob, 2),

        "scam_probability": round(scam_prob, 2),

        "non_bank_probability": round(non_bank_prob, 2)

    }


# ==========================================================
# RISK SCORE
# ==========================================================

def calculate_risk(

    prediction,

    verified

):

    if prediction["prediction"] == "NON_BANK":

        return {

            "risk_score": 0,

            "risk_level": "NON_BANK"

        }

    risk = prediction["scam_probability"]

    if verified:

        risk = risk - 10

    risk = max(0, min(100, risk))

    if risk <= 50:

        level = "SAFE"

    elif risk <= 75:

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

    sender_info

):

    if prediction == "NON_BANK":

        return NON_BANK_RESPONSE

    verified = sender_info["verified"]

    if risk_level == "SAFE":

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

    # ---------------------------------------------
    # Sender Validation
    # ---------------------------------------------

    sender_info = verify_sender(sender)

    # ---------------------------------------------
    # AI Prediction
    # ---------------------------------------------

    prediction = predict_message(message)

    # ---------------------------------------------
    # NON BANK
    # ---------------------------------------------

    if prediction["prediction"] == "NON_BANK":

       return {

        "prediction": "NON_BANK",

        "classification_confidence": prediction["confidence"],

        "risk_score": 0,

        "risk_level": "NON_BANK",

        "sender_status": sender_info["status"],

        "sender_id": sender_info["sender_id"],

        "bank_name": sender_info["bank_name"],

        "reasons": NON_BANK_RESPONSE

    }

    # ---------------------------------------------
    # Risk Calculation
    # ---------------------------------------------

    risk = calculate_risk(

        prediction,

        sender_info["verified"]

    )

    # ---------------------------------------------
    # Explanation
    # ---------------------------------------------

    reasons = generate_explanation(

        prediction["prediction"],

        risk["risk_level"],

        sender_info

    )

    # ---------------------------------------------
    # Final JSON
    # ---------------------------------------------

    return {

    "prediction": prediction["prediction"],

    "classification_confidence": prediction["confidence"],

    "risk_score": risk["risk_score"],

    "risk_level": risk["risk_level"],

    "sender_status": sender_info["status"],

    "sender_id": sender_info["sender_id"],

    "bank_name": sender_info["bank_name"],

    "reasons": reasons

}


# ==========================================================
# HEALTH CHECK
# ==========================================================


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