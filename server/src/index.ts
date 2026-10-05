import cors from 'cors';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { type Lang } from './detector.js';
import { runTextPipeline } from './pipeline.js';
import { analyzeUrl } from './urlChecker.js';
import { SCAM_PATTERNS } from './patterns.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(cors());
app.use(express.json({ limit: '64kb' }));

// Basic security headers.
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Simple in-memory rate limiter: 60 requests/min per IP on API routes.
const rateMap = new Map<string, { count: number; reset: number }>();
app.use('/api/', (req, res, next) => {
  const ip = req.ip ?? 'unknown';
  const now = Date.now();
  const entry = rateMap.get(ip);
  if (!entry || now > entry.reset) {
    rateMap.set(ip, { count: 1, reset: now + 60_000 });
    return next();
  }
  entry.count += 1;
  if (entry.count > 60) {
    return res.status(429).json({ error: 'Too many requests — please slow down.' });
  }
  next();
});

function pickLang(v: unknown): Lang {
  return v === 'hi' ? 'hi' : 'en';
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, engine: 'rule-based', service: 'scamshield' });
});

// POST /api/analyze-text — { text, lang, debug? } — staged pipeline
app.post('/api/analyze-text', (req, res) => {
  try {
    const text = String(req.body?.text ?? '').trim();
    if (!text) {
      return res.status(400).json({ error: 'No text provided' });
    }
    if (text.length > 5000) {
      return res.status(400).json({ error: 'Text too long (max 5000 chars)' });
    }
    const debug = req.body?.debug === true || req.query.debug === 'true';
    const result = runTextPipeline(text, pickLang(req.body?.lang), debug);
    res.json(result);
  } catch (e: unknown) {
    res.status(500).json({ error: e instanceof Error ? e.message : 'Analysis failed' });
  }
});

// POST /api/analyze-url — { url, lang }
app.post('/api/analyze-url', (req, res) => {
  try {
    const url = String(req.body?.url ?? '').trim();
    if (!url) {
      return res.status(400).json({ error: 'No URL provided' });
    }
    const result = analyzeUrl(url, pickLang(req.body?.lang));
    res.json(result);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : 'URL check failed';
    const status = /valid URL|http\/https/i.test(msg) ? 400 : 500;
    res.status(status).json({ error: msg });
  }
});

// GET /api/scam-patterns
app.get('/api/scam-patterns', (_req, res) => {
  res.json({ patterns: SCAM_PATTERNS });
});

const PORT = Number(process.env.PORT || 3001);

// Serve frontend static files in production (web/dist)
const distDir = path.resolve(__dirname, '../../web/dist');
app.use(express.static(distDir));
app.get('*', (_req, res) => {
  res.sendFile(path.join(distDir, 'index.html'));
});

app.listen(PORT, () => console.log(`ScamShield server on :${PORT}`));
