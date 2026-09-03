# 🛡️ SentryPay Bank Scam Detection API

A FastAPI-based inference service for detecting banking SMS scams using a fine-tuned DistilBERT model.

## Features

- DistilBERT-based SMS classification
- Detects:
  - SAFE Banking Messages
  - SCAM / Phishing Messages
  - NON_BANK Messages
- Official TRAI verified sender validation
- Risk Score (0–100)
- Risk Levels
  - SAFE
  - MODERATE
  - HIGH RISK
  - NON_BANK
- Human-readable explanation
- FastAPI REST API
-  Ready for Hugging Face Spaces deployment

---
---

## Datasets

The model was trained using a combination of publicly available datasets and custom-curated datasets to provide balanced coverage of legitimate banking messages, phishing attacks, financial fraud, and general SMS conversations.

| Dataset  | Source | Coverage |
|:---------|:-------|:---------|
| SMS Spam Collection | UCI Machine Learning Repository | Legitimate (ham) SMS and general spam messages used for NON_BANK classification. |
| Financial SMS Scam Dataset | Kaggle | Banking scams, financial fraud, phishing, fake loans, investment scams and fraudulent financial messages. |
| OpenPhish | OpenPhish | Verified phishing URLs targeting banking and financial services. |
| PhishTank | PhishTank | Community-verified phishing URLs filtered for banking-related websites. |
| Legitimate Banking SMS | Custom Curated | Genuine banking alerts including credits, debits, UPI, OTPs, cards, loans, deposits, account updates and service notifications. |
| Additional Scam SMS | Custom Curated | Banking phishing, fake KYC, fake rewards, UPI fraud, account suspension, OTP theft, impersonation and social engineering scams. |
| Banking URL Dataset | Custom Curated | Official banking websites and legitimate financial institution URLs. |
| Non-Bank SMS Dataset | Custom Curated | Personal conversations, shopping, education, healthcare, travel, entertainment, deliveries, utilities, social and promotional messages. |
| Verified Bank Sender Headers | TRAI (Telecom Regulatory Authority of India) | Official registered SMS sender headers used for sender verification. |

The final training dataset was created by cleaning, deduplicating, balancing and combining all of the above datasets before training the model.
## Project Structure

```text
.
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── model/
└── assets/
    └── sender_validation/
        └── verified_bank_headers.json
```

---

## Run Locally

Install dependencies

```bash
pip install -r requirements.txt
```

Run

```bash
python app.py
```

or

```bash
uvicorn app:app --host 0.0.0.0 --port 7860
```

---

## API Endpoint

POST

```
/analyze
```

Example Request

```json
{
  "sender": "JX-SBIUPI-S",
  "message": "Your account has been credited with ₹500."
}
```

Example Response

```json
{
  "prediction": "SAFE",
  "classification_confidence": 99.98,
  "risk_score": 0,
  "risk_level": "SAFE",
  "sender_status": "VERIFIED",
  "sender_id": "SBIUPI",
  "bank_name": "STATE BANK OF INDIA",
  "reasons": [
    "The message appears to be legitimate.",
    "The sender ID is officially verified.",
    "No immediate fraud indicators were detected."
  ]
}
```

---

## Model

- Base Model: DistilBERT
- Classes:
  - SAFE
  - SCAM
  - NON_BANK

---

## Sender Verification

Official TRAI registered SMS headers are used to verify sender identities before risk adjustment.

---

## License

For educational and hackathon purposes.