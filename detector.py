import re

KEYWORD_CATEGORIES = [
    (
        "Urgency words detected",
        ["act now", "urgent", "immediate action", "respond immediately",
         "limited time", "expires today", "account suspended", "verify immediately",
         "last chance", "final notice", "within 24 hours", "within 48 hours",
         "time sensitive", "action required", "don't delay"],
        4, 20
    ),
    (
        "Financial fraud phrases detected",
        ["wire transfer", "western union", "money order", "bank transfer",
         "send money", "transfer funds", "nigerian prince", "inheritance funds",
         "unclaimed funds", "lottery winnings", "prize money", "financial assistance",
         "investment opportunity", "guaranteed return", "risk free"],
        6, 30
    ),
    (
        "Phishing / credential harvesting phrases detected",
        ["click here to verify", "confirm your account", "update your information",
         "your account will be closed", "verify your identity", "login to your account",
         "sign in to confirm", "reset your password", "enter your credentials",
         "your password has expired", "account verification required",
         "provide your details", "validate your account"],
        7, 35
    ),
    (
        "Fake prize / lottery phrases detected",
        ["you have won", "congratulations you", "selected as winner",
         "claim your prize", "you are the lucky", "lucky winner",
         "claim your reward", "free gift", "you have been chosen",
         "winning notification", "award notification", "jackpot"],
        5, 25
    ),
    (
        "Impersonation of trusted authority detected",
        ["irs notice", "internal revenue service", "social security administration",
         "microsoft support", "apple support", "paypal security",
         "amazon security", "google account team", "federal bureau",
         "department of homeland", "official notice from"],
        5, 20
    ),
]

REGEX_RULES = [
    (r'(?:[A-Z]{5,}\s*){3,}',                              15, "Excessive use of capital letters (shouting pattern)"),
    (r'!{2,}|(?:.*!){4,}',                                 10, "Excessive exclamation marks (pressure tactic)"),
    (r'\b(?:password|passwd|pin)\b',                        20, "Directly asks for password or PIN"),
    (r'\b(?:ssn|social security number|social security no)\b', 20, "Requests Social Security Number"),
    (r'\b(?:bank account|account number|routing number)\b', 15, "Requests banking details"),
    (r'\b(?:credit card|card number|cvv|expiry date)\b',    15, "Requests credit card information"),
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',      18, "Link uses raw IP address instead of domain (suspicious)"),
    (r'bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.gy', 12, "Contains shortened/obfuscated URL"),
    (r'\bclick\s+(?:here|below|this\s+link)\b',              8, "Generic click-here link anchor (phishing pattern)"),
    (r'\bdo\s+not\s+(?:ignore|delete|discard)\b',            6, "Instruction not to dismiss email (pressure tactic)"),
    (r'(?:\$\s*\d[\d,]*(?:\.\d{2})?.*?){3,}',              10, "Multiple monetary amounts mentioned (financial lure)"),
]


def analyze(email_text: str) -> dict:
    text_lower = email_text.lower()
    score = 0
    reasons = []

    for label, keywords, weight, cap in KEYWORD_CATEGORIES:
        hits = [kw for kw in keywords if kw in text_lower]
        if hits:
            contribution = min(len(hits) * weight, cap)
            score += contribution
            reasons.append(f"{label} — e.g. \"{hits[0]}\"")

    for pattern, delta, reason in REGEX_RULES:
        if re.search(pattern, email_text, re.IGNORECASE):
            score += delta
            reasons.append(reason)

    alpha = [c for c in email_text if c.isalpha()]
    if len(alpha) > 50:
        upper_ratio = sum(1 for c in alpha if c.isupper()) / len(alpha)
        if upper_ratio > 0.4:
            score += 10
            reasons.append("Abnormally high uppercase-to-lowercase ratio")

    score = min(score, 100)

    if score <= 30:
        risk_level = "Safe"
    elif score <= 60:
        risk_level = "Suspicious"
    else:
        risk_level = "High Risk"

    if not reasons:
        reasons.append("No fraud indicators detected")

    return {"score": score, "risk_level": risk_level, "reasons": reasons}
