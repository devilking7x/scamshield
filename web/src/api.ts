// Same-origin API client. In production the Express server serves web/dist,
// so relative paths hit the same host — no localhost fallback.
import type { Lang } from './i18n';

export interface RedFlag {
  code: string;
  label: string;
  detail: string;
  weight: number;
}

export interface SimilarScam {
  templateId: string;
  name: string;
  category: string;
  score: number;
}

export interface TextResult {
  score: number;
  riskLevel: 'safe' | 'suspicious' | 'dangerous';
  redFlags: RedFlag[];
  explanation: string;
  recommendedActions: string[];
  similarKnownScams: SimilarScam[];
  engine: string;
  demo: boolean;
  lang: Lang;
}

export interface UrlReason {
  code: string;
  label: string;
  detail: string;
  weight: number;
}

export interface UrlResult {
  score: number;
  verdict: 'safe' | 'suspicious' | 'dangerous';
  reasons: UrlReason[];
  normalizedUrl: string;
  host: string;
  engine: string;
  lang: Lang;
}

export interface ScamPattern {
  id: string;
  icon: string;
  titleEn: string;
  titleHi: string;
  summaryEn: string;
  summaryHi: string;
  spotEn: string[];
  spotHi: string[];
  doEn: string[];
  doHi: string[];
  exampleEn: string;
  exampleHi: string;
}

async function handle<T>(r: Response): Promise<T> {
  const j = (await r.json().catch(() => ({}))) as T & { error?: string };
  if (!r.ok) throw new Error(j.error || `Request failed (${r.status})`);
  return j as T;
}

export function analyzeText(text: string, lang: Lang): Promise<TextResult> {
  return fetch('/api/analyze-text', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, lang }),
  }).then(handle<TextResult>);
}

export function analyzeUrl(url: string, lang: Lang): Promise<UrlResult> {
  return fetch('/api/analyze-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, lang }),
  }).then(handle<UrlResult>);
}

export function getPatterns(): Promise<{ patterns: ScamPattern[] }> {
  return fetch('/api/scam-patterns').then(handle<{ patterns: ScamPattern[] }>);
}
