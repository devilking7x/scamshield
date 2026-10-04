import { useEffect, useState } from 'react';
import { createWorker } from 'tesseract.js';
import type { Lang } from './i18n';
import { STR } from './i18n';
import { analyzeText, analyzeUrl, getPatterns } from './api';
import type { RedFlag, ScamPattern, SimilarScam, TextResult, UrlReason, UrlResult } from './api';

type Tab = 'message' | 'url' | 'ocr';
type Level = 'safe' | 'suspicious' | 'dangerous';

interface HistItem {
  id: number;
  type: 'text' | 'url';
  input: string;
  score: number;
  level: Level;
  ts: number;
}

const LEVEL_COLOR: Record<Level, string> = {
  safe: '#22c55e',
  suspicious: '#f59e0b',
  dangerous: '#ef4444',
};

function speak(text: string, lang: Lang): void {
  if (!('speechSynthesis' in window)) return;
  window.speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.lang = lang === 'hi' ? 'hi-IN' : 'en-US';
  const voices = window.speechSynthesis.getVoices();
  const match = voices.find((v) => v.lang.toLowerCase().startsWith(lang === 'hi' ? 'hi' : 'en'));
  if (match) u.voice = match;
  window.speechSynthesis.speak(u);
}

function stopSpeak(): void {
  if ('speechSynthesis' in window) window.speechSynthesis.cancel();
}

function ScoreRing({ score, level }: { score: number; level: Level }) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const color = LEVEL_COLOR[level];
  return (
    <div className="relative w-36 h-36">
      <svg viewBox="0 0 128 128" className="w-36 h-36 -rotate-90">
        <circle cx="64" cy="64" r={r} fill="none" stroke="#2a2415" strokeWidth="12" />
        <circle
          cx="64" cy="64" r={r} fill="none" stroke={color} strokeWidth="12"
          strokeLinecap="round" strokeDasharray={c}
          strokeDashoffset={c - (score / 100) * c} className="ring-anim"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold" style={{ color }}>{score}</span>
        <span className="text-xs text-stone-400">/ 100</span>
      </div>
    </div>
  );
}

function RiskBadge({ level, levelLang }: { level: Level; levelLang: Lang }) {
  const s = STR[levelLang];
  const label = level === 'safe' ? s.safe : level === 'suspicious' ? s.suspicious : s.dangerous;
  return (
    <span
      className="inline-block px-4 py-1.5 rounded-full font-bold text-sm"
      style={{ backgroundColor: LEVEL_COLOR[level] + '22', color: LEVEL_COLOR[level], border: `1px solid ${LEVEL_COLOR[level]}` }}
    >
      {label}
    </span>
  );
}

function FlagList({ flags }: { flags: RedFlag[] }) {
  if (!flags.length) return null;
  return (
    <ul className="space-y-3">
      {flags.map((f) => (
        <li key={f.code} className="border-l-4 pl-3 py-1" style={{ borderColor: '#d4af37' }}>
          <div className="font-semibold text-goldlight">🚩 {f.label}</div>
          <div className="text-sm text-stone-300 mt-0.5">{f.detail}</div>
        </li>
      ))}
    </ul>
  );
}

function ReasonList({ reasons }: { reasons: UrlReason[] }) {
  if (!reasons.length) return null;
  return (
    <ul className="space-y-3">
      {reasons.map((f) => (
        <li key={f.code} className="border-l-4 pl-3 py-1" style={{ borderColor: '#d4af37' }}>
          <div className="font-semibold text-goldlight">🔗 {f.label}</div>
          <div className="text-sm text-stone-300 mt-0.5">{f.detail}</div>
        </li>
      ))}
    </ul>
  );
}

function SimilarList({ items, lang }: { items: SimilarScam[]; lang: Lang }) {
  const s = STR[lang];
  if (!items.length) return null;
  return (
    <div className="mt-4">
      <div className="font-bold text-gold mb-2">🧬 {s.similarTitle}</div>
      <ul className="space-y-2">
        {items.map((it) => (
          <li key={it.templateId} className="flex items-center justify-between bg-black/30 rounded-lg px-3 py-2 text-sm">
            <span className="text-stone-200">{it.name}</span>
            <span className="text-goldlight font-mono">{Math.round(it.score * 100)}% {s.matchPct}</span>
          </li>
        ))}
      </ul>
      <div className="text-xs text-stone-500 mt-1">{s.similarityNote}</div>
    </div>
  );
}

function ActionSteps({ actions, lang }: { actions: string[]; lang: Lang }) {
  const s = STR[lang];
  const renderAction = (a: string, i: number) => {
    if (a.includes('https://cybercrime.gov.in')) {
      const parts = a.split('https://cybercrime.gov.in');
      return (
        <li key={i} className="flex gap-2 text-sm text-stone-200">
          <span className="text-gold">▸</span>
          <span>{parts[0]}<a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer" className="text-goldlight underline font-semibold">cybercrime.gov.in</a>{parts[1]}</span>
        </li>
      );
    }
    return (
      <li key={i} className="flex gap-2 text-sm text-stone-200">
        <span className="text-gold">▸</span><span>{a}</span>
      </li>
    );
  };
  return (
    <div className="mt-4">
      <div className="font-bold text-gold mb-2">✅ {s.whatToDo}</div>
      <ul className="space-y-1.5">{actions.map(renderAction)}</ul>
      <div className="flex flex-wrap gap-2 mt-3">
        <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer"
          className="px-4 py-2 rounded-lg bg-gold text-black font-bold text-sm hover:bg-goldlight">
          🚨 {s.reportLink}
        </a>
        <a href="tel:1930" className="px-4 py-2 rounded-lg border border-gold text-gold font-bold text-sm hover:bg-gold/10">
          📞 {s.helpline}
        </a>
      </div>
    </div>
  );
}

function ListenButton({ text, lang }: { text: string; lang: Lang }) {
  const s = STR[lang];
  const [speaking, setSpeaking] = useState(false);
  if (!('speechSynthesis' in window)) return null;
  return (
    <button
      onClick={() => {
        if (speaking) { stopSpeak(); setSpeaking(false); }
        else { speak(text, lang); setSpeaking(true); window.setTimeout(() => setSpeaking(false), 30000); }
      }}
      className="px-4 py-2 rounded-lg border border-gold text-gold font-bold text-sm hover:bg-gold/10"
    >
      🔊 {speaking ? s.stopListening : s.listen}
    </button>
  );
}

export default function App() {
  const [lang, setLang] = useState<Lang>('en');
  const s = STR[lang];
  const [tab, setTab] = useState<Tab>('message');

  const [msgText, setMsgText] = useState('');
  const [urlText, setUrlText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [textResult, setTextResult] = useState<TextResult | null>(null);
  const [urlResult, setUrlResult] = useState<UrlResult | null>(null);

  const [patterns, setPatterns] = useState<ScamPattern[]>([]);
  const [history, setHistory] = useState<HistItem[]>(() => {
    try { return JSON.parse(localStorage.getItem('scamshield-history') || '[]') as HistItem[]; }
    catch { return []; }
  });

  // OCR state
  const [imgFile, setImgFile] = useState<File | null>(null);
  const [imgPreview, setImgPreview] = useState<string | null>(null);
  const [ocrState, setOcrState] = useState<'idle' | 'working' | 'done' | 'error'>('idle');
  const [ocrProgress, setOcrProgress] = useState(0);
  const [ocrText, setOcrText] = useState('');

  useEffect(() => {
    getPatterns().then((d) => setPatterns(d.patterns)).catch(() => {});
    // Extension / shared link prefill: ?q=<selected text>
    const q = new URLSearchParams(window.location.search).get('q');
    if (q) {
      setMsgText(q.slice(0, 5000));
      setTab('message');
      window.setTimeout(() => document.getElementById('analyzer')?.scrollIntoView({ behavior: 'smooth' }), 300);
    }
  }, []);

  const addHistory = (item: Omit<HistItem, 'id' | 'ts'>) => {
    const h = [{ ...item, id: Date.now(), ts: Date.now() }, ...history].slice(0, 20);
    setHistory(h);
    try { localStorage.setItem('scamshield-history', JSON.stringify(h)); } catch { /* ignore */ }
  };

  const doAnalyzeText = async (text: string) => {
    const t = text.trim();
    if (!t) { setError(s.errorEmpty); return; }
    setError(''); setLoading(true); setTextResult(null); setUrlResult(null);
    try {
      const r = await analyzeText(t, lang);
      setTextResult(r);
      addHistory({ type: 'text', input: t.slice(0, 120), score: r.score, level: r.riskLevel });
    } catch {
      setError(s.errorFailed);
    } finally {
      setLoading(false);
    }
  };

  const doAnalyzeUrl = async () => {
    const u = urlText.trim();
    if (!u) { setError(s.errorUrl); return; }
    setError(''); setLoading(true); setTextResult(null); setUrlResult(null);
    try {
      const r = await analyzeUrl(u, lang);
      setUrlResult(r);
      addHistory({ type: 'url', input: u.slice(0, 120), score: r.score, level: r.verdict });
    } catch (e) {
      setError(e instanceof Error ? e.message : s.errorFailed);
    } finally {
      setLoading(false);
    }
  };

  const onImagePick = (f: File | undefined) => {
    if (!f) return;
    setImgFile(f);
    setOcrState('idle'); setOcrText(''); setOcrProgress(0);
    const reader = new FileReader();
    reader.onload = () => setImgPreview(String(reader.result));
    reader.readAsDataURL(f);
  };

  const runOcr = async () => {
    if (!imgFile) return;
    setOcrState('working'); setOcrProgress(0); setError('');
    try {
      const worker = await createWorker(['eng', 'hin'], 1, {
        logger: (m: { status: string; progress: number }) => {
          if (m.status === 'recognizing text') setOcrProgress(Math.round(m.progress * 100));
        },
      });
      const { data } = await worker.recognize(imgFile);
      await worker.terminate();
      const extracted = (data.text || '').trim();
      setOcrText(extracted);
      setOcrState(extracted ? 'done' : 'error');
    } catch {
      setOcrState('error');
    }
  };

  const levelOf = (r: TextResult | UrlResult): Level =>
    'riskLevel' in r ? r.riskLevel : r.verdict;

  const speakSummary = (r: TextResult | UrlResult): string => {
    const lvl = levelOf(r);
    const label = lvl === 'safe' ? s.safe : lvl === 'suspicious' ? s.suspicious : s.dangerous;
    const flags = 'redFlags' in r
      ? r.redFlags.map((f) => f.label).join('. ')
      : r.reasons.map((f) => f.label).join('. ');
    return `${s.score}: ${r.score}. ${label}. ${flags}`;
  };

  const verbs = [
    { icon: '🔍', t: s.vRecognize, d: s.vRecognizeD, href: '#analyzer' },
    { icon: '🔗', t: s.vVerify, d: s.vVerifyD, href: '#analyzer' },
    { icon: '📚', t: s.vPrevent, d: s.vPreventD, href: '#library' },
    { icon: '🚨', t: s.vRespond, d: s.vRespondD, href: '#guide' },
  ];

  return (
    <div className="min-h-screen bg-coal text-stone-100">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-coal/90 backdrop-blur border-b border-gold/20">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <a href="#top" className="flex items-center gap-2">
            <span className="text-2xl">🛡️</span>
            <span className="font-bold text-xl text-gold">ScamShield</span>
          </a>
          <nav className="hidden md:flex gap-6 text-sm text-stone-300">
            <a href="#analyzer" className="hover:text-gold">{s.ctaAnalyze}</a>
            <a href="#library" className="hover:text-gold">{s.ctaLibrary}</a>
            <a href="#guide" className="hover:text-gold">{s.guide}</a>
          </nav>
          <div className="flex rounded-full border border-gold/40 overflow-hidden text-sm font-bold">
            <button onClick={() => setLang('en')} className={`px-3 py-1.5 ${lang === 'en' ? 'bg-gold text-black' : 'text-gold'}`}>EN</button>
            <button onClick={() => setLang('hi')} className={`px-3 py-1.5 ${lang === 'hi' ? 'bg-gold text-black' : 'text-gold'}`}>हिंदी</button>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section id="top" className="hero-glow">
        <div className="max-w-6xl mx-auto px-4 pt-14 pb-10 text-center">
          <div className="text-6xl mb-4">🛡️</div>
          <h1 className="text-4xl md:text-6xl font-extrabold text-white">{s.heroTitle}</h1>
          <p className="text-gold text-lg mt-2 font-semibold">{s.tagline}</p>
          <p className="text-stone-300 max-w-2xl mx-auto mt-4">{s.heroSub}</p>
          <div className="flex flex-wrap justify-center gap-3 mt-6">
            <a href="#analyzer" className="px-6 py-3 rounded-xl bg-gold text-black font-bold hover:bg-goldlight">{s.ctaAnalyze}</a>
            <a href="#library" className="px-6 py-3 rounded-xl border border-gold text-gold font-bold hover:bg-gold/10">{s.ctaLibrary}</a>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-10 text-left">
            {verbs.map((v) => (
              <a key={v.t} href={v.href} className="card p-4 hover:border-gold transition-colors">
                <div className="text-2xl">{v.icon}</div>
                <div className="font-bold text-goldlight mt-1">{v.t}</div>
                <div className="text-xs text-stone-400 mt-0.5">{v.d}</div>
              </a>
            ))}
          </div>
        </div>
      </section>

      {/* Analyzer */}
      <section id="analyzer" className="max-w-4xl mx-auto px-4 py-10">
        <div className="card p-6">
          <div className="flex gap-2 mb-5">
            {(['message', 'url', 'ocr'] as Tab[]).map((tb) => (
              <button
                key={tb}
                onClick={() => { setTab(tb); setError(''); }}
                className={`px-4 py-2 rounded-lg font-bold text-sm ${tab === tb ? 'bg-gold text-black' : 'border border-gold/40 text-gold'}`}
              >
                {tb === 'message' ? `💬 ${s.tabMessage}` : tb === 'url' ? `🔗 ${s.tabUrl}` : `📷 ${s.tabOcr}`}
              </button>
            ))}
          </div>

          {tab === 'message' && (
            <div>
              <textarea
                value={msgText} onChange={(e) => setMsgText(e.target.value.slice(0, 5000))}
                placeholder={s.msgPlaceholder} rows={6}
                className="w-full bg-black/40 border border-gold/30 rounded-xl p-4 text-stone-100 placeholder:text-stone-500"
              />
              <div className="flex flex-wrap items-center justify-between gap-3 mt-3">
                <span className="text-xs text-stone-500">{msgText.length} / 5000</span>
                <div className="flex gap-2">
                  <button onClick={() => setMsgText(s.demoMsg)} className="px-4 py-2.5 rounded-xl border border-gold/50 text-gold text-sm font-bold hover:bg-gold/10">
                    ⚡ {s.tryDemo}
                  </button>
                  <button onClick={() => doAnalyzeText(msgText)} disabled={loading}
                    className="px-6 py-2.5 rounded-xl bg-gold text-black font-bold hover:bg-goldlight disabled:opacity-50">
                    {loading ? s.analyzing : `🔍 ${s.analyze}`}
                  </button>
                </div>
              </div>
            </div>
          )}

          {tab === 'url' && (
            <div>
              <input
                value={urlText} onChange={(e) => setUrlText(e.target.value)}
                placeholder={s.urlPlaceholder}
                className="w-full bg-black/40 border border-gold/30 rounded-xl p-4 text-stone-100 placeholder:text-stone-500"
                onKeyDown={(e) => { if (e.key === 'Enter') doAnalyzeUrl(); }}
              />
              <div className="flex justify-end mt-3">
                <button onClick={doAnalyzeUrl} disabled={loading}
                  className="px-6 py-2.5 rounded-xl bg-gold text-black font-bold hover:bg-goldlight disabled:opacity-50">
                  {loading ? s.analyzing : `🔍 ${s.analyze}`}
                </button>
              </div>
            </div>
          )}

          {tab === 'ocr' && (
            <div>
              <p className="text-xs text-stone-400 mb-3">{s.ocrHint}</p>
              {!imgPreview ? (
                <label className="block border-2 border-dashed border-gold/40 rounded-xl p-8 text-center cursor-pointer hover:border-gold">
                  <div className="text-4xl mb-2">📷</div>
                  <div className="text-gold font-bold">{s.ocrUpload}</div>
                  <input type="file" accept="image/*" className="hidden"
                    onChange={(e) => onImagePick(e.target.files?.[0])} />
                </label>
              ) : (
                <div>
                  <img src={imgPreview} alt="upload preview" className="max-h-56 rounded-xl border border-gold/30 mx-auto" />
                  <div className="flex flex-wrap justify-center gap-2 mt-3">
                    <button onClick={() => { setImgFile(null); setImgPreview(null); setOcrState('idle'); setOcrText(''); }}
                      className="px-4 py-2 rounded-lg border border-gold/40 text-gold text-sm font-bold">🔄 {s.ocrChange}</button>
                    <button onClick={runOcr} disabled={ocrState === 'working'}
                      className="px-4 py-2 rounded-lg bg-gold text-black text-sm font-bold disabled:opacity-50">
                      {ocrState === 'working' ? `${s.ocrWorking} ${ocrProgress}%` : `👁️ ${s.ocrExtract}`}
                    </button>
                  </div>
                  {ocrState === 'working' && (
                    <div className="w-full bg-black/40 rounded-full h-2.5 mt-3">
                      <div className="bg-gold h-2.5 rounded-full transition-all" style={{ width: `${ocrProgress}%` }} />
                    </div>
                  )}
                  {ocrState === 'error' && <p className="text-red-400 text-sm mt-3 text-center">{s.ocrError}</p>}
                  {ocrState === 'done' && (
                    <div className="mt-4">
                      <textarea value={ocrText} onChange={(e) => setOcrText(e.target.value.slice(0, 5000))} rows={5}
                        className="w-full bg-black/40 border border-gold/30 rounded-xl p-4 text-stone-100" />
                      <div className="flex justify-end mt-3">
                        <button onClick={() => doAnalyzeText(ocrText)} disabled={loading || !ocrText.trim()}
                          className="px-6 py-2.5 rounded-xl bg-gold text-black font-bold hover:bg-goldlight disabled:opacity-50">
                          {loading ? s.analyzing : `🔍 ${s.ocrAnalyze}`}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {error && <p className="text-red-400 text-sm mt-3">⚠️ {error}</p>}

          {/* Text result */}
          {textResult && (
            <div className="mt-6 border-t border-gold/20 pt-6">
              <div className="flex flex-col md:flex-row gap-6 items-center">
                <ScoreRing score={textResult.score} level={textResult.riskLevel} />
                <div className="flex-1 text-center md:text-left">
                  <div className="text-sm text-stone-400">{s.score}</div>
                  <div className="mt-1"><RiskBadge level={textResult.riskLevel} levelLang={lang} /></div>
                  <div className="mt-3"><ListenButton text={speakSummary(textResult)} lang={lang} /></div>
                </div>
              </div>
              <div className="mt-5">
                <div className="font-bold text-gold mb-2">🚩 {s.redFlags} ({textResult.redFlags.length})</div>
                {textResult.redFlags.length ? <FlagList flags={textResult.redFlags} /> : <p className="text-stone-400 text-sm">{s.noFlags}</p>}
              </div>
              <SimilarList items={textResult.similarKnownScams} lang={lang} />
              <div className="mt-4">
                <div className="font-bold text-gold mb-1">💡 {s.explanation}</div>
                <p className="text-stone-300 text-sm">{textResult.explanation}</p>
              </div>
              <ActionSteps actions={textResult.recommendedActions} lang={lang} />
              <p className="text-xs text-stone-500 mt-4">🤖 {s.heuristicNote}</p>
            </div>
          )}

          {/* URL result */}
          {urlResult && (
            <div className="mt-6 border-t border-gold/20 pt-6">
              <div className="flex flex-col md:flex-row gap-6 items-center">
                <ScoreRing score={urlResult.score} level={urlResult.verdict} />
                <div className="flex-1 text-center md:text-left">
                  <div className="text-sm text-stone-400">{s.score}</div>
                  <div className="mt-1"><RiskBadge level={urlResult.verdict} levelLang={lang} /></div>
                  <div className="text-xs text-stone-500 mt-2 font-mono break-all">{urlResult.host}</div>
                  <div className="mt-3"><ListenButton text={speakSummary(urlResult)} lang={lang} /></div>
                </div>
              </div>
              <div className="mt-5">
                <div className="font-bold text-gold mb-2">🔗 {s.redFlags} ({urlResult.reasons.length})</div>
                {urlResult.reasons.length ? <ReasonList reasons={urlResult.reasons} /> : <p className="text-stone-400 text-sm">{s.noFlags}</p>}
              </div>
              <p className="text-xs text-stone-500 mt-4">🤖 {s.heuristicNote}</p>
            </div>
          )}
        </div>
      </section>

      {/* Library */}
      <section id="library" className="max-w-6xl mx-auto px-4 py-10">
        <h2 className="text-3xl font-extrabold text-center text-white">📚 {s.library}</h2>
        <p className="text-stone-400 text-center mt-2 mb-8">{s.librarySub}</p>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {patterns.map((p) => (
            <details key={p.id} className="card p-5 group">
              <summary className="cursor-pointer list-none">
                <div className="text-3xl">{p.icon}</div>
                <div className="font-bold text-goldlight mt-2 text-lg">{lang === 'hi' ? p.titleHi : p.titleEn}</div>
                <div className="text-sm text-stone-400 mt-1">{lang === 'hi' ? p.summaryHi : p.summaryEn}</div>
                <div className="text-gold text-xs mt-2 font-bold group-open:hidden">+ {lang === 'hi' ? 'विस्तार' : 'Details'}</div>
              </summary>
              <div className="mt-4 space-y-3 text-sm">
                <div>
                  <div className="font-bold text-gold text-xs uppercase">👁️ {s.howToSpot}</div>
                  <ul className="list-disc list-inside text-stone-300 mt-1 space-y-0.5">
                    {(lang === 'hi' ? p.spotHi : p.spotEn).map((x, i) => <li key={i}>{x}</li>)}
                  </ul>
                </div>
                <div>
                  <div className="font-bold text-gold text-xs uppercase">✅ {s.whatToDoLib}</div>
                  <ul className="list-disc list-inside text-stone-300 mt-1 space-y-0.5">
                    {(lang === 'hi' ? p.doHi : p.doEn).map((x, i) => <li key={i}>{x}</li>)}
                  </ul>
                </div>
                <div className="bg-black/40 rounded-lg p-3">
                  <div className="font-bold text-gold text-xs uppercase">💬 {s.exampleMsg}</div>
                  <p className="text-stone-400 italic mt-1">"{lang === 'hi' ? p.exampleHi : p.exampleEn}"</p>
                </div>
              </div>
            </details>
          ))}
        </div>
      </section>

      {/* Action guide */}
      <section id="guide" className="max-w-4xl mx-auto px-4 py-10">
        <h2 className="text-3xl font-extrabold text-center text-white">🚨 {s.guide}</h2>
        <p className="text-stone-400 text-center mt-2 mb-8">{s.guideSub}</p>
        <div className="space-y-3">
          {[s.step1t, s.step2t, s.step3t, s.step4t, s.step5t].map((title, i) => {
            const descs = [s.step1d, s.step2d, s.step3d, s.step4d, s.step5d];
            return (
              <div key={i} className="card p-5">
                <div className="font-bold text-goldlight text-lg">{title}</div>
                <div className="text-stone-300 text-sm mt-1">{descs[i]}</div>
              </div>
            );
          })}
        </div>
        <div className="flex flex-wrap justify-center gap-3 mt-6">
          <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer"
            className="px-6 py-3 rounded-xl bg-gold text-black font-bold hover:bg-goldlight">🚨 {s.reportLink}</a>
          <a href="tel:1930" className="px-6 py-3 rounded-xl border border-gold text-gold font-bold hover:bg-gold/10">📞 {s.helpline}</a>
        </div>
      </section>

      {/* History */}
      <section id="history" className="max-w-4xl mx-auto px-4 py-10">
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-extrabold text-white">🕘 {s.history}</h2>
            {history.length > 0 && (
              <button onClick={() => { setHistory([]); localStorage.removeItem('scamshield-history'); }}
                className="text-xs text-stone-400 hover:text-gold border border-stone-700 rounded-lg px-3 py-1.5">
                🗑️ {s.clearHistory}
              </button>
            )}
          </div>
          {history.length === 0 ? (
            <p className="text-stone-500 text-sm">{s.emptyHistory}</p>
          ) : (
            <ul className="space-y-2">
              {history.map((h) => (
                <li key={h.id} className="flex items-center gap-3 bg-black/30 rounded-lg px-4 py-2.5 text-sm">
                  <span>{h.type === 'text' ? '💬' : '🔗'}</span>
                  <span className="flex-1 text-stone-300 truncate">{h.input}</span>
                  <span className="font-mono font-bold" style={{ color: LEVEL_COLOR[h.level] }}>{h.score}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gold/20 mt-6">
        <div className="max-w-6xl mx-auto px-4 py-8 text-center">
          <div className="text-2xl mb-2">🛡️</div>
          <div className="text-gold font-bold">ScamShield</div>
          <p className="text-stone-500 text-xs mt-2">{s.footer}</p>
          <p className="text-stone-600 text-xs mt-1">{s.footerNote}</p>
        </div>
      </footer>
    </div>
  );
}
