# ScamShield Architecture

## System overview

```mermaid
flowchart TB
    subgraph Client["Browser (PWA)"]
        UI["React UI\n(EN + HI toggle)"]
        OCR["Tesseract.js OCR\n(client-side, eng+hin)"]
        TTS["Web Speech API\n(verdict readout)"]
        SW["Service Worker\n(cache-first)"]
        UI --> OCR
        UI --> TTS
        SW -.-> UI
    end

    subgraph Server["Express server (compiled JS)"]
        API["REST API\n/api/analyze-text\n/api/analyze-url\n/api/scam-patterns"]
        PIPE["Staged pipeline\nExtractor → Scorer → Explainer → Advisor"]
        RULES["Rule engine\n12 text patterns (EN+HI)"]
        URLH["URL heuristics\n10 checks"]
        SIM["Similarity engine\nTF-IDF + cosine\n16 scam templates"]
        LIB["Pattern library\n6 India scam cards"]
        API --> PIPE
        PIPE --> RULES
        PIPE --> URLH
        PIPE --> SIM
        API --> LIB
    end

    subgraph Ext["Browser extension (MV3)"]
        CM["Context menu:\n'Check with ScamShield'"]
        CM -->|"?q=text"| UI
    end

    UI -->|same-origin /api/*| API
    Server -->|serves| UI
```

## Request flow — text analysis

```
POST /api/analyze-text { text, lang, debug? }
        │
        ▼
┌─────────────┐
│ 1. Extractor │  matchRules(text) → matched rule codes
│              │  extractUrls(text) → links found
├─────────────┤
│ 2. Scorer    │  score = Σ weights (cap 100)
│              │  risk = score≥60 dangerous · ≥30 suspicious · else safe
├─────────────┤
│ 3. Explainer │  localized red flags + plain-language explanation
├─────────────┤
│ 4. Advisor   │  recommended actions (incl. 1930 + cybercrime.gov.in)
│              │  similarKnownScams via TF-IDF + cosine vs 16 templates
└─────────────┘
        │
        ▼
{ score, riskLevel, redFlags, explanation, recommendedActions,
  similarKnownScams, engine: "rule-based", stages? (debug only) }
```

## URL check flow

```
POST /api/analyze-url { url, lang }
  → normalize → 10 heuristic checks (IP host, punycode, typosquat
    via Levenshtein vs known brands, shortener, suspicious TLD,
    brand embedding, @ trick, subdomains, login bait, no HTTPS)
  → { score, verdict, reasons[], engine: "rule-based" }
```

## Deployment

Single Render web service (free plan): the Express server serves the
compiled React bundle from `web/dist` and the API from the same origin —
no CORS tricks, no localhost fallbacks.

## Honesty notes

- Everything labeled `engine: "rule-based"` is deterministic heuristics,
  not a trained model. The README's AI Disclosure section lists exactly
  what is rules vs what could be LLM-backed later.
- OCR runs fully on-device via Tesseract.js; no image ever leaves the browser.
- The "similarity engine" is TF-IDF + cosine similarity, not an embedding model.
- The "staged agent pipeline" is a deterministic 4-stage pipeline, not an LLM agent.
