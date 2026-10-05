"use client";

import { useEffect, useMemo, useState } from "react";
import "./globals.css";
import { SAMPLES } from "../lib/samples";
import { analyzeMessage } from "../lib/analyze-client";

const KEY = "phishing-detector-gemini-key";

function ring(score, band) {
  const color = band === "high" ? "#b42318" : band === "medium" ? "#b54708" : "#067647";
  const dash = Math.round((score / 100) * 289);
  return (
    <svg className="ring" viewBox="0 0 120 120" aria-hidden="true">
      <circle cx="60" cy="60" r="46" fill="none" stroke="#e6eef6" strokeWidth="12" />
      <circle cx="60" cy="60" r="46" fill="none" stroke={color} strokeWidth="12" strokeLinecap="round" strokeDasharray={`${dash} 289`} transform="rotate(-90 60 60)" />
      <text x="60" y="66" textAnchor="middle" fontSize="26" fontFamily="IBM Plex Mono, monospace" fill="#102033">{score}</text>
    </svg>
  );
}

export default function Page() {
  const [text, setText] = useState(SAMPLES[1].text);
  const [apiKey, setApiKey] = useState("");
  const [active, setActive] = useState("urgent");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  useEffect(() => {
    const saved = window.localStorage.getItem(KEY);
    if (saved) setApiKey(saved);
  }, []);

  function saveKey(value) {
    setApiKey(value);
    if (value.trim()) window.localStorage.setItem(KEY, value.trim());
    else window.localStorage.removeItem(KEY);
  }

  async function analyze() {
    setLoading(true);
    setError("");
    try {
      const data = await analyzeMessage(text, apiKey);
      setResult(data);
    } catch (err) {
      setError(err.message || "Analysis failed");
    } finally {
      setLoading(false);
    }
  }

  function copyReport() {
    if (!result) return;
    const lines = [
      `Risk score: ${result.risk_score} (${result.band})`,
      `Verdict: ${result.verdict}`,
      `Summary: ${result.summary}`,
      `Next step: ${result.next_step}`,
      "Indicators:",
      ...(result.indicators || []).map((item) => `- ${item.detail || item.value || item.type}: ${(item.flags || item.matches || []).join(", ")}`),
    ];
    navigator.clipboard.writeText(lines.join("\n"));
  }

  const count = useMemo(() => text.length, [text]);

  return (
    <main className="app">
      <nav className="nav">
        <div className="brand"><span className="mark">PD</span> AI Phishing Detector</div>
        <a href="https://github.com/manulanirwan/AI-Phishing-Detector">GitHub</a>
      </nav>
      <header className="hero">
        <p className="kicker">Cybersecurity project</p>
        <h1>Check the message before you click.</h1>
        <p className="lede">Paste an email. Local rules score the links, sender mismatch, urgency, and secret requests. Gemini writes the explanation. A high rule score cannot be talked down by text inside the email.</p>
      </header>
      <section className="layout">
        <div className="card">
          <h2>Message</h2>
          <p className="hint">Headers help. From and Reply-To are checked when they are present.</p>
          <div className="samples">
            {SAMPLES.map((sample) => (
              <button key={sample.id} className={active === sample.id ? "chip active" : "chip"} onClick={() => { setText(sample.text); setActive(sample.id); setResult(null); }}>
                {sample.label}
              </button>
            ))}
          </div>
          <textarea value={text} onChange={(event) => { setText(event.target.value); setActive(""); }} placeholder="Paste the email or message here" />
          <p className="note">{count.toLocaleString()} / 20,000 characters</p>
          <div className="row">
            <button className="primary" onClick={analyze} disabled={loading || !text.trim()}>{loading ? "Checking..." : "Analyze message"}</button>
            <button className="ghost" onClick={() => { setText(""); setResult(null); setActive(""); }}>Clear</button>
            <button className="ghost" onClick={copyReport} disabled={!result}>Copy report</button>
          </div>
          <div className="keybox">
            <label htmlFor="key">Gemini API key</label>
            <input id="key" type="password" value={apiKey} onChange={(event) => saveKey(event.target.value)} placeholder="Optional. Rules still run without it." autoComplete="off" />
            <p className="note">The key stays in this browser and is sent only to Google for the explanation. GitHub Pages cannot hide a server key, so do not share this browser profile.</p>
          </div>
          {error ? <p className="error">{error}</p> : null}
        </div>
        <div className="card">
          {!result ? <div className="empty">Run an analysis to see the score, links, and next step.</div> : (
            <>
              <div className="scorehead">
                <div>
                  <div className={`band ${result.band}`}>{result.band} risk</div>
                  <h2 style={{ textTransform: "capitalize" }}>{result.verdict.replaceAll("_", " ")}</h2>
                  <span className="pill">{result.ai_used ? "Rules + Gemini" : "Rules only"}</span>
                </div>
                {ring(result.risk_score, result.band)}
              </div>
              <div className={result.conflict ? "callout warn" : "callout"}>
                <strong>Next step. </strong>{result.next_step}
              </div>
              <p>{result.summary}</p>
              {result.ai_error ? <p className="error">{result.ai_error}</p> : null}
              <h3>Indicators</h3>
              <ul className="list">
                {result.indicators.length === 0 ? <li>No strong rule indicators.</li> : result.indicators.map((item, index) => (
                  <li key={index}>{item.detail || item.value}{(item.flags || item.matches || []).length ? ` (${(item.flags || item.matches).join(", ")})` : ""}</li>
                ))}
              </ul>
              <h3>URLs</h3>
              <div className="list">
                {result.urls.length === 0 ? <div className="url">No URLs found.</div> : result.urls.map((item) => (
                  <div className="url" key={item.url}>
                    <code>{item.url}</code>
                    <div className="flags">{item.flags.length ? item.flags.map((flag) => <span className="flag" key={flag}>{flag}</span>) : <span className="flag" style={{ background: "#d1fadf", color: "#067647" }}>No URL flag</span>}</div>
                  </div>
                ))}
              </div>
              <h3>Manipulation language</h3>
              <ul className="list">
                {(result.manipulation || []).length === 0 ? <li>None detected.</li> : result.manipulation.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </>
          )}
        </div>
      </section>
      <section className="steps">
        <div className="step"><b>1. Parse</b> Extract links, addresses, From, and Reply-To.</div>
        <div className="step"><b>2. Score</b> Rules cap URL risk at 40 and sender mismatch at 20.</div>
        <div className="step"><b>3. Explain</b> Gemini may explain. It cannot erase a high score.</div>
        <div className="step"><b>4. Act</b> Open the real site yourself. Do not trust the link in the mail.</div>
      </section>
      <footer>Study tool by Manula Nirwan. This is not a mailbox filter and it can miss well-written phishing. Do not fetch or click the links it flags.</footer>
    </main>
  );
}
