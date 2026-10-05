# 🛡️ ScamShield — Scam & Fraud Detector

**Built for ForgeHacks Online 2026 · AI + Cybersecurity track**

## 🔴 Live Demo

**👉 https://scamshield-jyfk.onrender.com**

Try it now — paste any suspicious message, check a link, or upload a scam screenshot.

## Problem

India loses thousands of crores to digital fraud every year — UPI collect-request scams, OTP theft, fake KYC messages, "digital arrest" video-call extortion, job-fee frauds, and lottery scams. The victims are disproportionately non-English speakers who receive these attacks as SMS/WhatsApp messages on their phones. Existing advice ("be careful") doesn't help in the moment of panic. **ScamShield** is a free, mobile-first tool that checks a suspicious message or link *right now*, explains the danger in plain English or Hindi, and tells the victim exactly what to do next — including the national cyber helpline **1930** and the reporting portal **cybercrime.gov.in**.

## Features

| # | Feature | What it does |
|---|---------|--------------|
| 1 | **Message analyzer** (RECOGNIZE) | Paste suspicious SMS/WhatsApp/email text → scam risk score 0–100, red flags with plain-language explanations, EN + HI |
| 2 | **Link checker** (VERIFY) | Paste a URL → 10 phishing heuristics (typosquatting, punycode, IP hosts, shorteners, suspicious TLDs, brand embedding, `@` trick…) → verdict + reasons |
| 3 | **Screenshot → OCR** (multimodal) | Upload a scam screenshot → server-side Tesseract OCR (English + Hindi) extracts the text in ~2s → feeds the analyzer. Images are processed, never stored |
| 4 | **Similar-scam matching** | TF-IDF + cosine similarity against 16 known scam templates → "this looks like a Digital arrest threat (82% match)" |
| 5 | **Scam pattern library** (PREVENT) | 6 India-specific scam cards (UPI collect, OTP, fake KYC, job fee, digital arrest, lottery) — how to spot + what to do, bilingual |
| 6 | **Action guide** (RESPOND) | Step-by-step: stop contact → call 1930 → report at cybercrime.gov.in → alert bank → warn others |
| 7 | **Voice readout** | 🔊 Listen button reads the verdict aloud via Web Speech API (hi-IN / en-US) — for low-literacy users |
| 8 | **History** | Recent checks in localStorage (device only) |
| 9 | **PWA** | Installable, dark+gold theme, service worker — pattern library works offline |
| 10 | **Browser extension** (MV3) | Right-click selected text → "Check with ScamShield" → opens app pre-filled (`?q=`) |

One-click **demo scam** button loads a realistic "digital arrest" message → big red verdict → red flags → what-to-do steps. That's the 30-second demo.

## Tech stack

- **Frontend:** React 19 + TypeScript + Vite + Tailwind CSS (dark + gold theme, mobile-first)
- **Backend:** Express + TypeScript (compiled to JS with `tsc`, served via `node dist/index.js` — no ts-node)
- **Detection:** deterministic rule engine (12 text patterns × EN/HI) + URL heuristics (10 checks) + TF-IDF/cosine similarity (16 templates)
- **OCR:** Tesseract.js (client-side, eng+hin)
- **Voice:** Web Speech API (client-side)
- **PWA:** manifest.json + cache-first service worker
- **Deploy:** single Render web service, Express serves `web/dist` (same-origin API)

## Run locally

```bash
npm run install:all   # install server + web deps
npm run build         # compile server (tsc) + build web (vite)
npm start             # start server on :3001 (serves API + frontend)
npm test              # 25 E2E tests (spawns server automatically)
```

Open http://localhost:3001.

## API docs

### `POST /api/analyze-text`
Staged pipeline: Extractor → Scorer → Explainer → Advisor.

```bash
curl -X POST http://localhost:3001/api/analyze-text \
  -H 'Content-Type: application/json' \
  -d '{"text":"Your SBI account will be BLOCKED. Share the OTP immediately.","lang":"en"}'
# → {"score":75,"riskLevel":"dangerous","redFlags":[...],"explanation":"...","recommendedActions":[...],"similarKnownScams":[...],"engine":"rule-based",...}
```

Add `"debug": true` (or `?debug=true`) to include per-stage outputs under `stages`.

### `POST /api/analyze-url`

```bash
curl -X POST http://localhost:3001/api/analyze-url \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://xn--sbi-verify.tk/login","lang":"en"}'
# → {"score":60,"verdict":"dangerous","reasons":[...],"host":"xn--sbi-verify.tk","engine":"rule-based"}
```

### `GET /api/scam-patterns`
Returns the 6-entry bilingual scam library.

### `GET /api/health`
`{"ok":true,"engine":"rule-based","service":"scamshield"}`

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full diagram (mermaid):
client PWA (React + Tesseract OCR + Speech + service worker) → same-origin
Express API → staged pipeline (rule engine + URL heuristics + TF-IDF similarity);
browser extension feeds selected text via `?q=`.

## AI disclosure (honest)

| Component | What it really is |
|-----------|-------------------|
| Text risk score | **Rule-based heuristics** — 12 hand-written pattern groups (EN+HI regexes) with weights, summed and capped at 100. Labeled `engine: "rule-based"` in every response. |
| URL verdict | **Rule-based heuristics** — 10 structural checks + Levenshtein typosquat detection. Not a trained classifier. |
| Similar scams | **TF-IDF + cosine similarity** against 16 hand-written templates. Statistical text matching, not embeddings or an LLM. |
| Staged pipeline | **Deterministic 4-stage pipeline** (Extractor → Scorer → Explainer → Advisor). Called a "staged agent pipeline" for structure; it is not an LLM agent. |
| OCR | **Tesseract.js** — classic OCR engine running on-device, not a vision LLM. |
| LLM hook | **Not connected.** The code has no LLM calls. A provider could be plugged in later; until then every result is heuristic and says so. |

Heuristics have blind spots: novel scam scripts, sarcasm, and mixed-language tricks can slip through. **When in doubt, call 1930.** This tool is educational, not legal or security advice.

## Screenshots

> Screenshots will be added after deployment (place 1280×800 PNGs here):

| Screenshot | File |
|------------|------|
| Analyzer — dangerous verdict (digital arrest demo) | `docs/shots/1-verdict.png` |
| URL checker — phishing verdict | `docs/shots/2-url.png` |
| OCR from screenshot | `docs/shots/3-ocr.png` |
| Scam pattern library | `docs/shots/4-library.png` |
| Hindi mode | `docs/shots/5-hindi.png` |
| Mobile view | `docs/shots/6-mobile.png` |

## Project structure

```
scamshield/
├── server/            # Express + TS backend
│   ├── src/
│   │   ├── index.ts       # routes + serves web/dist
│   │   ├── pipeline.ts    # 4-stage analysis pipeline
│   │   ├── detector.ts    # 12 rule groups (EN+HI)
│   │   ├── urlChecker.ts  # 10 URL heuristics
│   │   ├── similarity.ts  # TF-IDF + cosine, 16 templates
│   │   └── patterns.ts    # 6 scam library entries (bilingual)
│   └── tests/e2e.test.mjs # 25 E2E tests
├── web/               # React + Vite + Tailwind PWA
│   ├── src/App.tsx    # UI (analyzer, library, guide, history)
│   └── public/        # manifest.json, sw.js, icons
├── extension/         # MV3 Chrome extension (context menu → ?q=)
├── docs/architecture.md
└── render.yaml        # Render deploy (free, singapore)
```

## License

MIT — see [LICENSE](LICENSE).
