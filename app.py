import os
import re
import math
import socket
import ssl
import datetime
import urllib.parse
import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="PhishShield Security Engine",
    description="Live Threat Intelligence and Heuristic URL Analysis API",
    version="1.0.0"
)

# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "banking", "update", "signin",
    "wallet", "paypal", "apple", "google", "meta", "support", "billing",
    "password", "auth", "confirm", "free", "claim", "reward"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "tiny.cc", "rb.gy", "cutt.ly"
]

class ScanRequest(BaseModel):
    url: str

def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy to detect domain randomization algorithms (DGA)."""
    if not text:
        return 0.0
    text_lower = text.lower()
    entropy = 0.0
    for char in set(text_lower):
        p_x = float(text_lower.count(char)) / len(text_lower)
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def check_dns_resolution(domain: str) -> dict:
    """Performs live DNS resolution to check if domain exists and resolve IP."""
    try:
        ip_address = socket.gethostbyname(domain)
        return {"resolves": True, "ip": ip_address}
    except Exception:
        return {"resolves": False, "ip": None}

def check_ssl_certificate(domain: str) -> dict:
    """Inspects live SSL certificate validity."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                not_after = cert.get('notAfter')
                expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.datetime.utcnow()).days
                return {
                    "valid": True,
                    "issuer": issuer.get('organizationName', 'Unknown'),
                    "days_until_expiry": days_left
                }
    except Exception:
        return {"valid": False, "issuer": None, "days_until_expiry": 0}

def check_google_safe_browsing(url: str) -> dict:
    """Queries Google Safe Browsing API v4 if API key is provided."""
    if not GOOGLE_SAFE_BROWSING_KEY:
        return {"checked": False, "flagged": False, "threat_types": []}
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"
    payload = {
        "client": {"clientId": "phishshield", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(endpoint, json=payload, timeout=4)
        data = res.json()
        if "matches" in data and len(data["matches"]) > 0:
            threats = [m.get("threatType") for m in data["matches"]]
            return {"checked": True, "flagged": True, "threat_types": threats}
        return {"checked": True, "flagged": False, "threat_types": []}
    except Exception:
        return {"checked": False, "flagged": False, "threat_types": []}

@app.post("/api/scan")
def analyze_url(req: ScanRequest):
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    parsed = urllib.parse.urlparse(raw_url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    domain_clean = domain.split(":")[0]

    # Feature Extractions
    has_ip = bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', domain_clean))
    is_shortener = any(short in domain_clean.lower() for short in SHORTENERS)
    num_dots = domain_clean.count('.')
    has_at_symbol = "@" in raw_url
    entropy = calculate_entropy(domain_clean)
    found_keywords = [w for w in SUSPICIOUS_KEYWORDS if w in raw_url.lower()]
    is_https = raw_url.startswith("https://")

    # Real Network Checks
    dns_info = check_dns_resolution(domain_clean)
    ssl_info = check_ssl_certificate(domain_clean) if is_https else {"valid": False, "issuer": None, "days_until_expiry": 0}
    gsb_info = check_google_safe_browsing(raw_url)

    # Risk Scoring Logic
    risk_score = 0
    reasons = []

    if gsb_info["flagged"]:
        risk_score += 80
        reasons.append(f"Flagged by Google Safe Browsing ({', '.join(gsb_info['threat_types'])})")

    if has_ip:
        risk_score += 35
        reasons.append("URL uses an raw IP address instead of a domain name")

    if is_shortener:
        risk_score += 25
        reasons.append("URL uses a known link obfuscation/shortener service")

    if has_at_symbol:
        risk_score += 20
        reasons.append("URL contains an '@' symbol used for credential redirection")

    if num_dots >= 4:
        risk_score += 15
        reasons.append("Excessive subdomains detected in host address")

    if entropy > 4.1:
        risk_score += 20
        reasons.append(f"High domain entropy ({entropy}) indicates algorithmically generated domain (DGA)")

    if found_keywords:
        risk_score += min(len(found_keywords) * 12, 36)
        reasons.append(f"Contains phishing target keywords: {', '.join(found_keywords)}")

    if not is_https:
        risk_score += 10
        reasons.append("Insecure HTTP protocol (missing SSL/TLS encryption)")

    if not dns_info["resolves"]:
        risk_score += 20
        reasons.append("Domain failed DNS resolution (unregistered or dead domain)")

    final_score = min(max(risk_score, 0), 100)

    if final_score >= 65:
        verdict = "MALICIOUS"
    elif final_score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "status": "success",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "data": {
            "url": raw_url,
            "domain": domain_clean,
            "verdict": verdict,
            "risk_score": final_score,
            "reasons": reasons,
            "network": {
                "ip_address": dns_info["ip"],
                "dns_resolves": dns_info["resolves"],
                "ssl": ssl_info
            },
            "heuristics": {
                "has_ip_host": has_ip,
                "is_shortener": is_shortener,
                "subdomain_count": max(0, num_dots - 1),
                "domain_entropy": entropy,
                "keywords_found": found_keywords,
                "uses_https": is_https
            },
            "threat_intelligence": gsb_info
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
    
