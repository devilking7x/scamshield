/**
 * ScamShield semantic similarity engine.
 *
 * Compares an incoming message against a local database of known scam
 * message templates using TF-IDF + cosine similarity. No external API.
 * Honestly labeled as a "similarity engine" — it is NOT an ML classifier.
 */

export interface ScamTemplate {
  id: string;
  nameEn: string;
  nameHi: string;
  category: string;
  text: string;
}

export interface SimilarScam {
  templateId: string;
  name: string;
  category: string;
  score: number; // 0..1 cosine similarity
}

const STOPWORDS = new Set([
  // english
  'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'to', 'of', 'and',
  'for', 'on', 'in', 'your', 'you', 'yours', 'will', 'with', 'please', 'this',
  'that', 'from', 'has', 'have', 'had', 'it', 'its', 'as', 'at', 'by', 'or',
  'not', 'no', 'do', 'does', 'did', 'can', 'could', 'should', 'would', 'may',
  'our', 'we', 'he', 'she', 'they', 'them', 'his', 'her', 'their', 'i', 'me',
  'my', 'us', 'if', 'so', 'but', 'just', 'now', 'here', 'there', 'all',
  // hindi
  'का', 'की', 'के', 'है', 'में', 'से', 'को', 'पर', 'यह', 'आप', 'आपका', 'आपकी',
  'और', 'या', 'ने', 'कोई', 'कृपया', 'तुरंत', 'द्वारा', 'लिए', 'साथ', 'हैं',
  'था', 'थी', 'हो', 'होगा', 'होगी', 'करें', 'करे',
]);

function tokenize(text: string): string[] {
  const tokens = text.toLowerCase().match(/[a-z0-9\u0900-\u097f]+/g) || [];
  return tokens.filter((w) => !STOPWORDS.has(w) && (w.length >= 2 || /^\d+$/.test(w)));
}

// prettier-ignore
export const SCAM_TEMPLATES: ScamTemplate[] = [
  {
    id: 'digital-arrest-en', nameEn: 'Digital arrest threat', nameHi: 'डिजिटल अरेस्ट धमकी',
    category: 'digital-arrest',
    text: 'This is CBI officer. Your Aadhaar card is linked to money laundering case. You are under digital arrest. Stay on video call. Transfer money for verification or you will be arrested by police.',
  },
  {
    id: 'digital-arrest-hi', nameEn: 'Digital arrest threat', nameHi: 'डिजिटल अरेस्ट धमकी',
    category: 'digital-arrest',
    text: 'मैं CBI अधिकारी बोल रहा हूँ। आपका आधार मनी लॉन्ड्रिंग केस से जुड़ा है। आप डिजिटल अरेस्ट में हैं। वीडियो कॉल पर रहें। वेरिफिकेशन के लिए पैसे ट्रांसफर करें वरना गिरफ्तार होंगे।',
  },
  {
    id: 'otp-bank-en', nameEn: 'Bank OTP fraud', nameHi: 'बैंक OTP ठगी',
    category: 'otp',
    text: 'Dear customer your bank account will be blocked within 24 hours. Share the OTP sent to your mobile number immediately to verify and unblock your account. Do not ignore.',
  },
  {
    id: 'otp-hi', nameEn: 'Bank OTP fraud', nameHi: 'बैंक OTP ठगी',
    category: 'otp',
    text: 'प्रिय ग्राहक आपका खाता 24 घंटे में बंद हो जाएगा। खाता चालू रखने के लिए तुरंत भेजा गया ओटीपी बताएं।',
  },
  {
    id: 'upi-collect-en', nameEn: 'UPI collect request fraud', nameHi: 'UPI collect request ठगी',
    category: 'upi',
    text: 'I am sending payment for your online ad. Approve the collect request in your UPI app and enter your UPI PIN to receive the money in your account.',
  },
  {
    id: 'upi-collect-hi', nameEn: 'UPI collect request fraud', nameHi: 'UPI collect request ठगी',
    category: 'upi',
    text: 'मैं आपके विज्ञापन के पैसे भेज रहा हूँ। पैसे पाने के लिए UPI ऐप में collect request approve करें और अपना UPI PIN डालें।',
  },
  {
    id: 'kyc-en', nameEn: 'Fake KYC update', nameHi: 'फर्जी KYC अपडेट',
    category: 'kyc',
    text: 'Your bank KYC is expired and account will be frozen. Update KYC immediately by clicking this link and entering your details. Last date today.',
  },
  {
    id: 'kyc-hi', nameEn: 'Fake KYC update', nameHi: 'फर्जी KYC अपडेट',
    category: 'kyc',
    text: 'आपका बैंक KYC एक्सपायर हो गया है और खाता फ्रीज़ हो जाएगा। इस लिंक पर क्लिक करके तुरंत KYC अपडेट करें। आज आखिरी तारीख है।',
  },
  {
    id: 'job-fee-en', nameEn: 'Fake job fee scam', nameHi: 'फर्जी नौकरी फीस ठगी',
    category: 'job',
    text: 'Congratulations you are selected for work from home job with monthly salary. Pay registration fee to start work and get your offer letter today.',
  },
  {
    id: 'job-fee-hi', nameEn: 'Fake job fee scam', nameHi: 'फर्जी नौकरी फीस ठगी',
    category: 'job',
    text: 'बधाई हो आप work from home नौकरी के लिए चुने गए हैं। काम शुरू करने के लिए रजिस्ट्रेशन फीस दें और आज ही ऑफर लेटर पाएं।',
  },
  {
    id: 'lottery-en', nameEn: 'Lottery prize fee scam', nameHi: 'लॉटरी इनाम फीस ठगी',
    category: 'lottery',
    text: 'Congratulations your mobile number has won lottery prize of twenty five lakh rupees. Pay processing fee and tax to claim your prize money now.',
  },
  {
    id: 'lottery-hi', nameEn: 'Lottery prize fee scam', nameHi: 'लॉटरी इनाम फीस ठगी',
    category: 'lottery',
    text: 'बधाई हो आपके मोबाइल नंबर ने लॉटरी में पच्चीस लाख रुपये जीते हैं। इनाम पाने के लिए प्रोसेसिंग फीस और टैक्स अभी दें।',
  },
  {
    id: 'customer-care-anydesk', nameEn: 'Fake customer care (screen sharing)', nameHi: 'फर्जी कस्टमर केयर',
    category: 'support',
    text: 'I am calling from customer care. To fix your issue please install AnyDesk app from play store and share the code so our team can access your phone screen.',
  },
  {
    id: 'electricity-bill', nameEn: 'Electricity bill disconnection scam', nameHi: 'बिजली बिल ठगी',
    category: 'utility',
    text: 'Dear consumer your electricity connection will be disconnected tonight due to unpaid bill. Call our officer immediately and pay to avoid disconnection.',
  },
  {
    id: 'delivery-otp', nameEn: 'Fake delivery OTP scam', nameHi: 'फर्जी डिलीवरी OTP ठगी',
    category: 'otp',
    text: 'Your parcel delivery is attempted. Share the OTP received on your phone to reschedule delivery today or the parcel will be returned.',
  },
  {
    id: 'crypto-double', nameEn: 'Crypto doubling scam', nameHi: 'क्रिप्टो दोगुना ठगी',
    category: 'investment',
    text: 'Double your crypto investment guaranteed. Send bitcoin to our wallet and receive double amount back within one hour. Limited offer risk free profit.',
  },
];

interface Vec {
  weights: Map<string, number>;
  norm: number;
}

const idf = new Map<string, number>();
const templateVecs: Vec[] = [];

function buildIndex(): void {
  const docs = SCAM_TEMPLATES.map((t) => tokenize(t.text));
  const df = new Map<string, number>();
  for (const tokens of docs) {
    for (const tok of new Set(tokens)) {
      df.set(tok, (df.get(tok) || 0) + 1);
    }
  }
  const N = docs.length;
  for (const [tok, count] of df) {
    idf.set(tok, Math.log(N / count));
  }
  for (const tokens of docs) {
    const tf = new Map<string, number>();
    for (const tok of tokens) tf.set(tok, (tf.get(tok) || 0) + 1);
    const weights = new Map<string, number>();
    let sumSq = 0;
    for (const [tok, c] of tf) {
      const w = (c / tokens.length) * (idf.get(tok) || 0);
      weights.set(tok, w);
      sumSq += w * w;
    }
    templateVecs.push({ weights, norm: Math.sqrt(sumSq) });
  }
}

buildIndex();

function vectorize(text: string): Vec {
  const tokens = tokenize(text);
  const tf = new Map<string, number>();
  for (const tok of tokens) tf.set(tok, (tf.get(tok) || 0) + 1);
  const weights = new Map<string, number>();
  let sumSq = 0;
  for (const [tok, c] of tf) {
    const idfW = idf.get(tok);
    if (idfW === undefined) continue; // unknown terms add nothing
    const w = (c / tokens.length) * idfW;
    weights.set(tok, w);
    sumSq += w * w;
  }
  return { weights, norm: Math.sqrt(sumSq) };
}

const SIM_THRESHOLD = 0.15;

export function findSimilarScams(text: string, lang: 'en' | 'hi' = 'en', topN = 3): SimilarScam[] {
  const q = vectorize(text);
  if (q.norm === 0) return [];
  const scored = SCAM_TEMPLATES.map((t, i) => {
    const v = templateVecs[i];
    let dot = 0;
    let shared = 0;
    for (const [tok, w] of q.weights) {
      const tw = v.weights.get(tok);
      if (tw !== undefined) {
        dot += w * tw;
        shared++;
      }
    }
    // Require at least 2 shared content tokens — a single rare word
    // (e.g. "tonight") must not trigger a match on its own.
    if (shared < 2) return { template: t, score: 0 };
    const score = v.norm === 0 ? 0 : dot / (q.norm * v.norm);
    return { template: t, score };
  })
    .filter((s) => s.score >= SIM_THRESHOLD)
    .sort((a, b) => b.score - a.score)
    .slice(0, topN);

  return scored.map((s) => ({
    templateId: s.template.id,
    name: lang === 'hi' ? s.template.nameHi : s.template.nameEn,
    category: s.template.category,
    score: Math.round(s.score * 100) / 100,
  }));
}
