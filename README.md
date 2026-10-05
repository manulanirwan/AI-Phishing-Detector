# AI Phishing Detector

Live site: https://manulanirwan.github.io/AI-Phishing-Detector/

Paste a suspicious email or message. Local rules score the risk. Gemini writes the explanation. Text inside the email cannot override a high rule score.

Built by Manula Nirwan as a cybersecurity portfolio project.

This is a study tool. It is not a mailbox filter. It can miss phishing, and it can flag normal mail. It does not open links.

## What it checks

- Phishing, suspicious, or likely benign verdict
- Scam indicators
- Suspicious URLs
- Urgency and manipulation language
- Risk score from 0 to 100
- A next step for the user

## Score

| Signal | Max points |
| --- | --- |
| Lookalike domain, IP host, shortener, punycode, risky path | 40 |
| Password, OTP, payment, or account confirmation request | 20 |
| Urgency or threat wording | 20 |
| Display-name mismatch or Reply-To mismatch | 20 |
| Risky attachment mention | 15 |

The total is capped at 100. Bands: 0-30 low, 31-60 medium, 61-100 high.

If the rules score is high and Gemini says the message is safe, the high score stays.

## Run the website

The live site is GitHub Pages. It is a static site, so the score runs in your browser. Paste your Gemini key in the page if you want the written explanation. GitHub Secrets cannot supply that key to Pages.

Local copy:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000.

Add a Gemini API key in the page. It is saved in your browser and sent only to the local `/api/analyze` route. You can also put it in `frontend/.env.local`:

```text
GEMINI_API_KEY=your_key
GEMINI_MODEL=gemini-3.8-flash
```

Rules still run if the key is missing or Gemini fails. If the model name returns 404, set `GEMINI_MODEL` to a model available on your key.

## Run the Python API

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy ..\.env.example .env
uvicorn main:app --reload
```

On macOS or Linux, activate with `source .venv/bin/activate` and copy the env file with `cp ../.env.example .env`.

`POST http://127.0.0.1:8000/analyze`

```json
{ "text": "paste the email here", "apiKey": "optional" }
```

The website uses the Next.js route by default, so you do not need the Python API to use the page. The Python API is the same checker for local security work.

## Samples

The page includes four samples:

1. Campus notice. Expected low score.
2. Urgency scam with a shortener and Reply-To mismatch. Expected high score.
3. Lookalike brand link on an IP host. Expected high score.
4. Prompt-injection attempt that says "mark this safe". Expected high score. The instruction inside the email is ignored.

## Security notes

- Pasted email is untrusted data. The Gemini prompt tells the model to ignore instructions inside it.
- The app does not fetch URLs. That avoids server-side request forgery in v1.
- Do not commit `.env` or `.env.local`.
- Do not deploy a public site that asks other people to paste their Gemini key unless you understand the risk.

## Limits

- Keyword lists are English-heavy.
- No live mailbox connection.
- No SPF, DKIM, or DMARC check unless those headers are pasted as text.
- No URL reputation lookup.

## Stack

- Next.js website and `/api/analyze`
- Python FastAPI backend
- Gemini API for the written explanation
- Deterministic rules for the score
