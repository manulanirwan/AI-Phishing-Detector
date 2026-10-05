const URL_RE = /https?:\/\/[^\s<>'"\]\)]+/gi;
const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;

const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rb.gy", "shorturl.at", "tiny.cc"];
const URGENCY = ["act now", "within 24 hours", "within 1 hour", "account suspended", "verify immediately", "urgent", "final notice", "limited time", "click here now", "last warning", "unauthorized login", "will be closed", "suspended", "immediately", "expire"];
const SECRET_ASK = ["password", "otp", "one-time code", "one time code", "ssn", "bank details", "seed phrase", "credit card", "login details", "verify your identity", "confirm your account"];
const ATTACHMENTS = [".exe", ".scr", ".iso", ".hta", ".js", ".vbs", ".bat", ".cmd", ".msi", ".html"];
const RISKY_TLDS = ["tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "country", "support"];
const BRANDS = {
  paypal: ["paypal.com"],
  microsoft: ["microsoft.com", "office.com", "live.com", "outlook.com"],
  apple: ["apple.com", "icloud.com"],
  google: ["google.com", "gmail.com"],
  amazon: ["amazon.com"],
  netflix: ["netflix.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],
};

function extractUrls(text) {
  const found = [];
  for (const raw of text.match(URL_RE) || []) {
    const cleaned = raw.replace(/[.,;:!?]+$/, "");
    if (!found.includes(cleaned)) found.push(cleaned);
  }
  return found;
}

function domainFrom(value) {
  const match = String(value || "").match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  if (match) return match[0].split("@")[1].toLowerCase();
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return String(value || "").toLowerCase();
  }
}

function isOfficial(host, domains) {
  return domains.some((item) => host === item || host.endsWith(`.${item}`));
}

function brandFlag(host) {
  const folded = host.replaceAll("0", "o").replaceAll("1", "l").replaceAll("rn", "m");
  for (const [brand, domains] of Object.entries(BRANDS)) {
    if (isOfficial(host, domains)) continue;
    if (host.includes(brand) || folded.includes(brand)) return `Possible ${brand} lookalike domain`;
  }
  return null;
}

function urlFlags(url) {
  const flags = [];
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return ["Unreadable URL"];
  }
  const host = parsed.hostname.toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) flags.push("IP address used as host");
  else if (host.split(".").length - 1 >= 3) flags.push("Many subdomains");
  if (SHORTENERS.some((item) => host === item || host.endsWith(`.${item}`))) flags.push("URL shortener");
  if (host.includes("xn--")) flags.push("Punycode host");
  if (parsed.protocol === "http:") flags.push("Not HTTPS");
  const tld = host.includes(".") ? host.split(".").at(-1) : "";
  if (RISKY_TLDS.includes(tld)) flags.push(`Risky TLD .${tld}`);
  const lookalike = brandFlag(host);
  if (lookalike) flags.push(lookalike);
  if (["login", "verify", "secure", "update", "wallet"].some((token) => parsed.pathname.toLowerCase().includes(token))) {
    flags.push("Sensitive word in path");
  }
  return flags;
}

function headerFlags(text) {
  const flags = [];
  const fromMatch = text.match(/^from:\s*(.+)$/im);
  const replyMatch = text.match(/^reply-to:\s*(.+)$/im);
  if (!fromMatch) return flags;
  const fromRaw = fromMatch[1];
  const fromDomain = domainFrom(fromRaw);
  const display = fromRaw.replace(/<[^>]+>/g, "").replace(/["']/g, "").trim();
  if (display && fromDomain) {
    for (const [brand, domains] of Object.entries(BRANDS)) {
      if (display.toLowerCase().includes(brand) && !isOfficial(fromDomain, domains)) {
        flags.push({ type: "sender", detail: `Display name mentions ${brand}, but the address domain is ${fromDomain}` });
        break;
      }
    }
  }
  if (replyMatch) {
    const replyDomain = domainFrom(replyMatch[1]);
    if (replyDomain && fromDomain && replyDomain !== fromDomain) {
      flags.push({ type: "sender", detail: `Reply-To domain ${replyDomain} does not match From domain ${fromDomain}` });
    }
  }
  return flags;
}

export function scoreEmail(text) {
  const raw = text || "";
  const lower = raw.toLowerCase();
  const urls = extractUrls(raw);
  const indicators = [];
  const urlRows = [];
  let score = 0;
  let urlPoints = 0;

  for (const url of urls) {
    const flags = urlFlags(url);
    urlRows.push({ url, flags });
    if (flags.length) {
      indicators.push({ type: "url", value: url, flags });
      urlPoints += 8 + 4 * Math.max(0, flags.length - 1);
    }
  }
  urlPoints = Math.min(urlPoints, 40);
  score += urlPoints;

  if (SECRET_ASK.some((phrase) => lower.includes(phrase))) {
    indicators.push({ type: "request", detail: "Asks for a password, code, payment detail, or account confirmation" });
    score += 20;
  }
  const urgencyHits = URGENCY.filter((phrase) => lower.includes(phrase));
  if (urgencyHits.length) {
    indicators.push({ type: "language", detail: "Urgency or threat wording", matches: urgencyHits.slice(0, 4) });
    score += 20;
  }
  const attachmentHits = ATTACHMENTS.filter((item) => lower.includes(item));
  if (attachmentHits.length) {
    indicators.push({ type: "attachment", detail: "Mentions a risky attachment type", matches: attachmentHits });
    score += 15;
  }
  indicators.push(...headerFlags(raw));
  if (indicators.some((item) => item.type === "sender")) score += 20;

  score = Math.max(0, Math.min(score, 100));
  const band = score <= 30 ? "low" : score <= 60 ? "medium" : "high";
  return {
    risk_score: score,
    band,
    urls: urlRows,
    indicators,
    emails_found: raw.match(EMAIL_RE) || [],
    urgency_matches: urgencyHits,
  };
}

export function nextStep(band) {
  if (band === "high") return "Do not click links, open attachments, or reply. Open the official site yourself and report the message there.";
  if (band === "medium") return "Do not use the link in the message. Check the account from the official app or a bookmark you already trust.";
  return "No strong phishing signals in the rules. Still do not send passwords or codes by email.";
}

export function verdictFromBand(band) {
  if (band === "high") return "phishing";
  if (band === "medium") return "suspicious";
  return "likely_benign";
}
