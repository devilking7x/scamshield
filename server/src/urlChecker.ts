/**
 * ScamShield URL phishing heuristics.
 *
 * Rule-based feature extraction over the URL structure:
 * IP hosts, punycode, URL shorteners, suspicious TLDs, typosquatting
 * (Levenshtein distance vs known Indian brands), brand-name embedding in
 * lookalike domains, '@' tricks, non-HTTPS, and login/verify path bait.
 *
 * Labeled as rule-based in every response (see `engine`).
 */

export type Lang = 'en' | 'hi';
export type Verdict = 'safe' | 'suspicious' | 'dangerous';

export interface UrlReason {
  code: string;
  label: string;
  detail: string;
  weight: number;
}

export interface UrlVerdict {
  score: number;
  verdict: Verdict;
  reasons: UrlReason[];
  normalizedUrl: string;
  host: string;
  engine: 'rule-based';
  lang: Lang;
}

// Known brands scammers impersonate in India
const BRANDS = [
  'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm', 'phonepe', 'gpay',
  'amazon', 'flipkart', 'irctc', 'incometax', 'uidai', 'epfo', 'rbi',
  'whatsapp', 'telegram', 'jio', 'airtel',
];

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 'rb.gy',
  'cutt.ly', 'is.gd', 'rebrand.ly', 's.id', 'shorturl.at',
]);

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'buzz', 'country',
  'stream', 'download', 'review', 'work', 'rest', 'link', 'zip', 'mov',
]);
// Free Freenom TLDs — extremely abused by phishers, deserve a higher weight.
const HIGH_RISK_TLDS = new Set(['tk', 'ml', 'ga', 'cf', 'gq']);

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return dp[m][n];
}

interface Check {
  code: string;
  weight: number;
  test: (u: URL, host: string, labels: string[]) => boolean;
  labelEn: string; labelHi: string; detailEn: string; detailHi: string;
}

// prettier-ignore
const CHECKS: Check[] = [
  {
    code: 'ip_host', weight: 35,
    test: (u, host) => IP_RE.test(host),
    labelEn: 'IP address instead of a domain name',
    labelHi: 'डोमेन नाम की जगह IP एड्रेस',
    detailEn: 'Legitimate banks and companies use domain names, not raw IP addresses. IP-based links are a classic phishing sign.',
    detailHi: 'असली बैंक और कंपनियाँ डोमेन नाम इस्तेमाल करती हैं, IP एड्रेस नहीं। IP वाले लिंक फिशिंग की पुरानी निशानी हैं।',
  },
  {
    code: 'punycode', weight: 20,
    test: (u, host) => host.includes('xn--'),
    labelEn: 'Punycode / lookalike characters in domain',
    labelHi: 'डोमेन में छद्म अक्षर (punycode)',
    detailEn: 'The domain uses encoded characters designed to visually mimic a trusted brand (homograph attack).',
    detailHi: 'डोमेन में ऐसे एन्कोडेड अक्षर हैं जो भरोसेमंद ब्रांड जैसे दिखने के लिए बनाए गए हैं।',
  },
  {
    code: 'shortener', weight: 15,
    test: (u, host) => SHORTENERS.has(host.replace(/^www\./, '')),
    labelEn: 'URL shortener hides the real destination',
    labelHi: 'URL shortener असली पता छिपा रहा है',
    detailEn: 'Shortened links hide where you will actually land. Expand the link (or ask the sender for the full URL) before clicking.',
    detailHi: 'छोटे लिंक असली पता छिपाते हैं। क्लिक करने से पहले लिंक को expand करें या पूरा URL माँगें।',
  },
  {
    code: 'suspicious_tld', weight: 20,
    test: (u, host, labels) => {
      const tld = labels[labels.length - 1] || '';
      if (HIGH_RISK_TLDS.has(tld)) return true;
      // lower weight for other cheap TLDs — handled via combo bonus instead
      return false;
    },
    labelEn: 'High-risk free top-level domain (.tk/.ml/.ga/.cf/.gq)',
    labelHi: 'जोखिम भरा मुफ्त टॉप-लेवल डोमेन (.tk/.ml/.ga/.cf/.gq)',
    detailEn: 'This free domain extension is extremely abused by scammers. Real Indian banks use .co.in or .com — never these.',
    detailHi: 'यह मुफ्त डोमेन एक्सटेंशन ठगों द्वारा बहुत ज़्यादा दुरुपयोग किया जाता है। असली भारतीय बैंक .co.in या .com इस्तेमाल करते हैं — ये कभी नहीं।',
  },
  {
    code: 'cheap_tld', weight: 8,
    test: (u, host, labels) => {
      const tld = labels[labels.length - 1] || '';
      return SUSPICIOUS_TLDS.has(tld) && !HIGH_RISK_TLDS.has(tld);
    },
    labelEn: 'Cheap / unusual top-level domain',
    labelHi: 'सस्ता / असामान्य टॉप-लेवल डोमेन',
    detailEn: 'Unusual cheap domain extensions (.xyz, .top, .click...) are often used for throwaway scam sites.',
    detailHi: 'असामान्य सस्ते डोमेन एक्सटेंशन (.xyz, .top, .click...) अक्सर फेंकने वाली ठगी साइटों के लिए इस्तेमाल होते हैं।',
  },
  {
    code: 'typosquat', weight: 25,
    test: (u, host, labels) => {
      const main = labels[labels.length - 2] || '';
      if (!main || main.length < 3) return false;
      return BRANDS.some((b) => {
        const d = levenshtein(main, b);
        return d >= 1 && d <= 2 && main !== b;
      });
    },
    labelEn: 'Typosquat: near-miss of a known brand',
    labelHi: 'टाइपोस्क्वैट: मशहूर ब्रांड से मिलता-जुलता नाम',
    detailEn: 'The domain is one or two letters off a well-known brand (e.g. "sb1" vs "sbi") — a classic trick to fool quick readers.',
    detailHi: 'डोमेन किसी मशहूर ब्रांड से सिर्फ एक-दो अक्षर अलग है (जैसे "sb1" बनाम "sbi") — जल्दी पढ़ने वालों को धोखा देने की पुरानी चाल।',
  },
  {
    code: 'brand_embed', weight: 20,
    test: (u, host, labels) => {
      const realDomains = [
        'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com',
        'paytm.com', 'phonepe.com', 'irctc.co.in', 'incometax.gov.in', 'uidai.gov.in',
        'epfindia.gov.in', 'rbi.org.in',
      ];
      if (realDomains.some((d) => host === d || host.endsWith('.' + d))) return false;
      return BRANDS.some((b) => host.includes(b));
    },
    labelEn: 'Brand name embedded in a lookalike domain',
    labelHi: 'नकली डोमेन में ब्रांड का नाम घुसाया गया',
    detailEn: 'The link mentions a trusted brand but the actual domain is not the brand\'s official website (e.g. "sbi-offer.tk" is not SBI).',
    detailHi: 'लिंक में भरोसेमंद ब्रांड का नाम है, लेकिन असली डोमेन ब्रांड की आधिकारिक वेबसाइट नहीं है (जैसे "sbi-offer.tk" SBI नहीं है)।',
  },
  {
    code: 'at_trick', weight: 15,
    test: (u) => u.href.includes('@'),
    labelEn: '"@" trick in URL',
    labelHi: 'URL में "@" वाली चाल',
    detailEn: 'Everything before "@" in a link is ignored by browsers — scammers use it to fake a trusted address.',
    detailHi: 'ब्राउज़र "@" से पहले का हिस्सा नज़रअंदाज़ कर देता है — ठग इससे भरोसेमंद पता होने का नाटक करते हैं।',
  },
  {
    code: 'many_subdomains', weight: 8,
    test: (u, host, labels) => labels.length >= 4,
    labelEn: 'Excessive subdomains',
    labelHi: 'बहुत ज़्यादा सबडोमेन',
    detailEn: 'Long chains of subdomains (login.verify.sbi...) are used to bury the real domain at the end.',
    detailHi: 'सबडोमेन की लंबी श्रृंखला असली डोमेन को आखिर में छिपाने के लिए इस्तेमाल होती है।',
  },
  {
    code: 'login_bait', weight: 10,
    test: (u) => /(login|verify|secure|account|update|kyc|signin)/i.test(u.pathname + u.search),
    labelEn: '"Login / verify" bait in the path',
    labelHi: 'पाथ में "लॉगिन / वेरिफाई" का चारा',
    detailEn: 'Phishing pages love urgent-sounding paths like /verify-account or /login-secure to harvest credentials.',
    detailHi: 'फिशिंग पेज /verify-account जैसे ज़रूरी लगने वाले पाथ इस्तेमाल करते हैं ताकि आपकी जानकारी चुरा सकें।',
  },
  {
    code: 'brand_in_path', weight: 10,
    test: (u) => BRANDS.some((b) => (u.pathname + u.search).toLowerCase().includes(b)),
    labelEn: 'Trusted brand name in the link path',
    labelHi: 'लिंक के पाथ में भरोसेमंद ब्रांड का नाम',
    detailEn: 'The path mentions a trusted brand to look legitimate, but the domain itself is unrelated to that brand.',
    detailHi: 'पाथ में भरोसेमंद ब्रांड का नाम है ताकि असली लगे, लेकिन डोमेन उस ब्रांड से जुड़ा नहीं है।',
  },
  {
    code: 'no_https', weight: 5,
    test: (u) => u.protocol === 'http:',
    labelEn: 'Not using HTTPS',
    labelHi: 'HTTPS इस्तेमाल नहीं हो रहा',
    detailEn: 'The connection is not encrypted. Never enter passwords, OTPs or card details on non-HTTPS pages.',
    detailHi: 'कनेक्शन एन्क्रिप्टेड नहीं है। गैर-HTTPS पेज पर कभी पासवर्ड, OTP या कार्ड जानकारी न डालें।',
  },
];

export function analyzeUrl(raw: string, lang: Lang = 'en'): UrlVerdict {
  let input = raw.trim().slice(0, 2000);
  if (!/^https?:\/\//i.test(input)) input = 'https://' + input;

  let u: URL;
  try {
    u = new URL(input);
  } catch {
    throw new Error(lang === 'hi' ? 'यह मान्य URL नहीं लगता' : 'That does not look like a valid URL');
  }
  if (!['http:', 'https:'].includes(u.protocol)) {
    throw new Error(lang === 'hi' ? 'सिर्फ http/https लिंक जाँचे जाते हैं' : 'Only http/https links can be checked');
  }

  const host = u.hostname.toLowerCase();
  const labels = host.split('.');
  const reasons: UrlReason[] = [];
  let score = 0;

  for (const c of CHECKS) {
    try {
      if (c.test(u, host, labels)) {
        score += c.weight;
        reasons.push({
          code: c.code,
          label: lang === 'hi' ? c.labelHi : c.labelEn,
          detail: lang === 'hi' ? c.detailHi : c.detailEn,
          weight: c.weight,
        });
      }
    } catch {
      // ignore single-check failures
    }
  }

  score = Math.min(100, score);
  reasons.sort((a, b) => b.weight - a.weight);
  // Combo bonus: multiple independent phishing signals = much more dangerous.
  if (reasons.length >= 3) {
    score = Math.min(100, score + 15);
    reasons.push({
      code: 'combo',
      label: lang === 'hi' ? 'कई स्वतंत्र फिशिंग संकेत एक साथ' : 'Multiple independent phishing signals combined',
      detail: lang === 'hi'
        ? 'तीन या ज़्यादा अलग-अलग चेतावनी संकेत एक साथ मिलना लगभग पक्का फिशिंग है।'
        : 'Three or more independent warning signals together is almost certainly phishing.',
      weight: 15,
    });
    reasons.sort((a, b) => b.weight - a.weight);
  }
  const verdict: Verdict = score >= 60 ? 'dangerous' : score >= 30 ? 'suspicious' : 'safe';

  return {
    score,
    verdict,
    reasons,
    normalizedUrl: u.href,
    host,
    engine: 'rule-based',
    lang,
  };
}
