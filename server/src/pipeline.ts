/**
 * ScamShield staged analysis pipeline.
 *
 * The text analysis runs as four visible stages:
 *   1. Extractor — match rule signals, pull out URLs, count characters
 *   2. Scorer    — weighted sum → 0-100 score → risk level
 *   3. Explainer — localized red flags + plain-language explanation
 *   4. Advisor   — recommended actions + similar known scam templates
 *
 * Each stage is logged. Pass `debug: true` (POST body or ?debug=true)
 * to get the per-stage outputs in the response under `stages`.
 *
 * This is a deterministic staged pipeline of heuristics — honestly
 * documented in the README as a "staged agent pipeline", not an LLM agent.
 */

import {
  buildActions,
  buildExplanation,
  buildFlags,
  buildTrustSignals,
  extractUrls,
  matchRules,
  riskOf,
  scoreOf,
  type Lang,
  type PipelineStages,
  type TextAnalysis,
} from './detector.js';
import { findSimilarScams } from './similarity.js';

function log(stage: string, data: Record<string, unknown>): void {
  console.log(`[pipeline] stage=${stage}`, JSON.stringify(data));
}

export function runTextPipeline(
  rawText: string,
  lang: Lang = 'en',
  debug = false,
): TextAnalysis {
  const text = rawText.slice(0, 5000);

  // Stage 1 — Extractor
  const matched = matchRules(text);
  const urls = extractUrls(text);
  log('extractor', { matched: matched.map((r) => r.code), urls: urls.length, chars: text.length });

  // Stage 2 — Scorer
  const score = scoreOf(matched);
  const riskLevel = riskOf(score);
  log('scorer', { score, riskLevel });

  // Stage 3 — Explainer
  const redFlags = buildFlags(matched, lang);
  const trustSignals = buildTrustSignals(matched, lang);
  const explanation = buildExplanation(riskLevel, lang);
  log('explainer', { flags: redFlags.length, trust: trustSignals.length });

  // Stage 4 — Advisor
  const recommendedActions = buildActions(riskLevel, lang);
  const similarKnownScams = findSimilarScams(text, lang);
  log('advisor', { actions: recommendedActions.length, similar: similarKnownScams.length });

  const result: TextAnalysis = {
    score,
    riskLevel,
    redFlags,
    trustSignals,
    explanation,
    recommendedActions,
    similarKnownScams,
    engine: 'rule-based',
    demo: process.env.SCAMSHIELD_DEMO !== '0',
    lang,
  };

  if (debug) {
    const stages: PipelineStages = {
      extractor: { matchedCodes: matched.map((r) => r.code), urlCount: urls.length, charCount: text.length },
      scorer: { score, riskLevel },
      explainer: { flagCount: redFlags.length },
      advisor: { actionCount: recommendedActions.length, similarCount: similarKnownScams.length },
    };
    result.stages = stages;
  }

  return result;
}
