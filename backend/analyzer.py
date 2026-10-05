import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>'\"\]\)]+", re.I)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
FROM_RE = re.compile(r"^from:\s*(.+)$", re.I | re.M)
REPLY_RE = re.compile(r"^reply-to:\s*(.+)$", re.I | re.M)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "rb.gy", "shorturl.at", "tiny.cc",
}
URGENCY = [
    "act now", "within 24 hours", "within 1 hour", "account suspended",
    "verify immediately", "urgent", "final notice", "limited time",
    "click here now", "last warning", "unauthorized login", "will be closed",
    "suspended", "immediately", "expire",
]
SECRET_ASK = [
    "password", "otp", "one-time code", "one time code", "ssn",
    "bank details", "seed phrase", "credit card", "login details",
    "verify your identity", "confirm your account",
]
ATTACHMENTS = [".exe", ".scr", ".iso", ".hta", ".js", ".vbs", ".bat", ".cmd", ".msi", ".html"]
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "country", "support"}
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
}


def extract_urls(text: str) -> list[str]:
    found = []
    for raw in URL_RE.findall(text or ""):
        cleaned = raw.rstrip(".,;:!?")
        if cleaned not in found:
            found.append(cleaned)
    return found


def _domain(value: str) -> str:
    value = (value or "").strip().lower()
    match = EMAIL_RE.search(value)
    if match:
        return match.group(0).split("@", 1)[1]
    host = urlparse(value).hostname
    return (host or value).lower()


def _official(host: str, domains: list[str]) -> bool:
    return any(host == item or host.endswith("." + item) for item in domains)


def brand_flag(host: str) -> str | None:
    folded = host.replace("0", "o").replace("1", "l").replace("rn", "m")
    for brand, domains in BRANDS.items():
        if _official(host, domains):
            continue
        if brand in host or brand in folded:
            return f"Possible {brand} lookalike domain"
    return None


def url_flags(url: str) -> list[str]:
    flags = []
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        flags.append("IP address used as host")
    elif host.count(".") >= 3:
        flags.append("Many subdomains")
    if host in SHORTENERS or any(host.endswith("." + item) for item in SHORTENERS):
        flags.append("URL shortener")
    if "xn--" in host:
        flags.append("Punycode host")
    if parsed.scheme == "http":
        flags.append("Not HTTPS")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        flags.append(f"Risky TLD .{tld}")
    lookalike = brand_flag(host)
    if lookalike:
        flags.append(lookalike)
    if any(token in (parsed.path or "").lower() for token in ["login", "verify", "secure", "update", "wallet"]):
        flags.append("Sensitive word in path")
    return flags


def header_flags(text: str) -> list[dict]:
    flags = []
    from_match = FROM_RE.search(text or "")
    reply_match = REPLY_RE.search(text or "")
    if not from_match:
        return flags
    from_raw = from_match.group(1)
    from_domain = _domain(from_raw)
    display = re.sub(r"<[^>]+>", "", from_raw).strip(" \"'")
    if display and from_domain:
        for brand, domains in BRANDS.items():
            if brand in display.lower() and not _official(from_domain, domains):
                flags.append({
                    "type": "sender",
                    "detail": f"Display name mentions {brand}, but the address domain is {from_domain}",
                })
                break
    if reply_match:
        reply_domain = _domain(reply_match.group(1))
        if reply_domain and from_domain and reply_domain != from_domain:
            flags.append({
                "type": "sender",
                "detail": f"Reply-To domain {reply_domain} does not match From domain {from_domain}",
            })
    return flags


def score_email(text: str) -> dict:
    raw = text or ""
    lower = raw.lower()
    urls = extract_urls(raw)
    indicators = []
    url_rows = []
    score = 0

    url_points = 0
    for url in urls:
        flags = url_flags(url)
        url_rows.append({"url": url, "flags": flags})
        if flags:
            indicators.append({"type": "url", "value": url, "flags": flags})
            url_points += 8 + (4 * max(0, len(flags) - 1))
    url_points = min(url_points, 40)
    score += url_points

    if any(phrase in lower for phrase in SECRET_ASK):
        indicators.append({"type": "request", "detail": "Asks for a password, code, payment detail, or account confirmation"})
        score += 20
    urgency_hits = [phrase for phrase in URGENCY if phrase in lower]
    if urgency_hits:
        indicators.append({"type": "language", "detail": "Urgency or threat wording", "matches": urgency_hits[:4]})
        score += 20
    attachment_hits = [item for item in ATTACHMENTS if item in lower]
    if attachment_hits:
        indicators.append({"type": "attachment", "detail": "Mentions a risky attachment type", "matches": attachment_hits})
        score += 15
    indicators.extend(header_flags(raw))
    if any(item["type"] == "sender" for item in indicators):
        score += 20

    score = max(0, min(score, 100))
    band = "low" if score <= 30 else "medium" if score <= 60 else "high"
    return {
        "risk_score": score,
        "band": band,
        "urls": url_rows,
        "indicators": indicators,
        "emails_found": EMAIL_RE.findall(raw),
        "urgency_matches": urgency_hits,
    }


def next_step(band: str) -> str:
    if band == "high":
        return "Do not click links, open attachments, or reply. Open the official site yourself and report the message there."
    if band == "medium":
        return "Do not use the link in the message. Check the account from the official app or a bookmark you already trust."
    return "No strong phishing signals in the rules. Still do not send passwords or codes by email."
