/**
 * ScamShield rule-based text detection engine.
 *
 * This is a HEURISTIC engine, not an AI model. It scores messages against
 * known scam pattern rules (English + Hindi). Results are labeled as
 * rule-based in every API response — see the `engine` field.
 *
 * An optional LLM hook can be added later via the LLM_ANALYZE_URL env var;
 * when unset, the rule engine is the only analyzer and says so honestly.
 */

export type Lang = 'en' | 'hi';
export type RiskLevel = 'safe' | 'suspicious' | 'dangerous';

export interface RedFlag {
  code: string;
  label: string;
  detail: string;
  weight: number;
}

export interface TextAnalysis {
  score: number;
  riskLevel: RiskLevel;
  redFlags: RedFlag[];
  trustSignals: RedFlag[];
  explanation: string;
  recommendedActions: string[];
  similarKnownScams: import('./similarity.js').SimilarScam[];
  engine: 'rule-based';
  demo: boolean;
  lang: Lang;
  stages?: PipelineStages;
}

export interface PipelineStages {
  extractor: { matchedCodes: string[]; urlCount: number; charCount: number };
  scorer: { score: number; riskLevel: RiskLevel };
  explainer: { flagCount: number };
  advisor: { actionCount: number; similarCount: number };
}

export interface Rule {
  code: string;
  weight: number;
  /** 'red' = scam signal (shown as red flag), 'trust' = legitimacy signal (shown as trust signal, negative weight) */
  kind?: 'red' | 'trust';
  patterns: RegExp[];
  labelEn: string;
  labelHi: string;
  detailEn: string;
  detailHi: string;
}

// prettier-ignore
const RULES: Rule[] = [
  {
    // TRUST SIGNAL: genuine OTP delivery messages always warn "do not share".
    // Scammers asking for OTP never include this warning. Negative weight.
    code: 'legit_otp', weight: -45, kind: 'trust',
    patterns: [
      /\botp\b.{0,60}(do not share|never share|do not disclose|keep (it |this )?confidential)/i,
      /(do not share|never share|do not disclose).{0,60}\botp\b/i,
      /ओटीपी.{0,40}(साझा न करें|किसी को न बताएं)/i,
      /(साझा न करें|किसी को न बताएं).{0,40}ओटीपी/i,
    ],
    labelEn: 'Genuine OTP delivery format',
    labelHi: 'असली OTP डिलीवरी फॉर्मेट',
    detailEn: 'Real OTP messages always warn you NOT to share the code. This is the standard format used by banks and services.',
    detailHi: 'असली OTP मैसेज हमेशा कोड साझा न करने की चेतावनी देते हैं। यह बैंकों और सेवाओं का मानक फॉर्मेट है।',
  },
  {
    code: 'otp_secret', weight: 30,
    patterns: [
      /\botp\b/i, /one[\s-]*time[\s-]*password/i, /ओटीपी/, /\bcvv\b/i, /upi\s*pin/i,
      /\bpin\b.*(share|bata|bhejo|bhej|enter|daal)/i,
      /(share|send|batao|bhejo|bhej\s*dijiye|बताएं|भेजें|tell\s*us).{0,30}\botp\b/i,
      /\botp\b.{0,30}(share|send|batao|bhejo|बताएं|भेजें)/i,
      /(tell|give|provide).{0,30}(one[\s-]*time[\s-]*password|\botp\b)/i,
      /वन[-\s]?टाइम\s*पासवर्ड/i, /(enter|daalein|डालें).{0,30}\botp\b/i,
    ],
    labelEn: 'Asks for OTP / PIN / CVV',
    labelHi: 'OTP / PIN / CVV माँग रहा है',
    detailEn: 'No real bank, UPI app or government office ever asks for your OTP, UPI PIN or CVV. Anyone asking is almost certainly a scammer.',
    detailHi: 'कोई असली बैंक, UPI ऐप या सरकारी दफ्तर कभी OTP, UPI PIN या CVV नहीं माँगता। जो माँगे, वह लगभग पक्का ठग है।',
  },
  {
    code: 'digital_arrest', weight: 45,
    patterns: [
      /digital\s*arrest/i, /arrest\s*warrant/i, /(you\s*will|will)\s*be\s*arrested/i,
      /गिरफ्तार/i, /वारंट/i, /डिजिटल\s*अरेस्ट/i, /cbi\s*(case|officer|enquiry)/i,
      /narcotics/i, /money\s*laundering\s*case/i, /court\s*(order|notice|case)/i,
      /skype\s*(call|video)/i, /video\s*call.*(police|cbi|officer)/i,
    ],
    labelEn: '"Digital arrest" / fake police threat',
    labelHi: '"डिजिटल अरेस्ट" / फर्जी पुलिस धमकी',
    detailEn: '"Digital arrest" is a famous Indian scam. Real police never arrest over video call or demand money to cancel a case. Disconnect immediately.',
    detailHi: '"डिजिटल अरेस्ट" भारत का मशहूर ठगी तरीका है। असली पुलिस वीडियो कॉल पर गिरफ्तार नहीं करती और केस रद्द करने के पैसे नहीं माँगती। तुरंत कॉल काट दें।',
  },
  {
    code: 'impersonation', weight: 15,
    patterns: [
      /bank\s*manager/i, /\brbi\b/i, /\bcbi\b/i, /income\s*tax\s*(department|officer)/i, /customs/i,
      /kyc\s*(update|verify|verification|expire|suspend)/i, /केवाईसी/i,
      /(police|cyber\s*cell|cybercrime)\s*(officer|department)/i,
      /sbi|hdfc|icici|axis|kotak|paytm|phonepe/i,
      /customer\s*care/i, /toll[\s-]*free/i,
    ],
    labelEn: 'Impersonates a bank / authority',
    labelHi: 'बैंक / अधिकारी बनकर बात कर रहा है',
    detailEn: 'Scammers pretend to be bank staff, RBI, police or KYC officers. Always verify through the official app or website — never via the number in the message.',
    detailHi: 'ठग बैंक कर्मचारी, RBI, पुलिस या KYC अधिकारी बनते हैं। हमेशा आधिकारिक ऐप/वेबसाइट से जाँचें — मैसेज में दिए नंबर पर कभी भरोसा न करें।',
  },
  {
    code: 'upi_collect', weight: 30,
    patterns: [
      /collect\s*request/i, /approve.{0,40}(collect|request)/i,
      /कलेक्ट\s*रिक्वेस्ट/i,
    ],
    labelEn: 'UPI collect request — approving SENDS money',
    labelHi: 'UPI collect request — approve करने से पैसे जाते हैं',
    detailEn: 'A UPI "collect request" ASKS YOU for money. Approving it sends money FROM your account — it never receives money. Scammers lie that approving will credit you.',
    detailHi: 'UPI "collect request" आपसे पैसे माँगता है। इसे approve करने से आपके खाते से पैसे जाते हैं — कभी आते नहीं। ठग झूठ बोलते हैं कि approve करने से पैसे आएँगे।',
  },
  {
    code: 'upi_deception', weight: 30,
    patterns: [
      /approve.{0,30}to\s*receive/i, /(receive|get).{0,20}money.{0,30}(approve|accept)/i,
      /approve\s*करने\s*से.{0,20}पैसे\s*(आएँगे|मिलेंगे)/i,
    ],
    labelEn: '"Approve to receive money" — the classic UPI lie',
    labelHi: '"पैसे पाने के लिए approve करें" — क्लासिक UPI झूठ',
    detailEn: 'This is the exact lie used in UPI fraud: approving a collect request NEVER credits money — it always debits. If you did not expect this request, decline and block the sender.',
    detailHi: 'यह UPI ठगी में इस्तेमाल होने वाला exact झूठ है: collect request approve करने से कभी पैसे नहीं आते — हमेशा कटते हैं। अगर यह request अप्रत्याशित है, तो decline करें और भेजने वाले को ब्लॉक करें।',
  },
  {
    code: 'money_request', weight: 15,
    patterns: [
      /(send|transfer|pay).{0,25}(money|amount|rs\.?|₹|inr|rupees|lakh|crore|पैसे|\d{4,})/i,
      /collect\s*request/i, /pay\s*(a\s*)?(fee|charge|advance|deposit)/i,
      /(scan|scan\s*the)\s*(qr|code)/i, /पैसे\s*भेजें/i, /रुपये\s*भेजें/i,
      /एडवांस\s*(पेमेंट|भुगतान)/i, /upi\s*(id|collect)/i,
    ],
    labelEn: 'Requests money / UPI payment',
    labelHi: 'पैसे / UPI पेमेंट माँग रहा है',
    detailEn: 'Unexpected payment requests — especially UPI collect requests or QR scans — are the #1 UPI fraud method in India. Approving a collect request SENDS money, it does not receive it.',
    detailHi: 'अचानक पेमेंट माँगना — खासकर UPI collect request या QR स्कैन — भारत में UPI ठगी का सबसे आम तरीका है। Collect request approve करने से पैसे जाते हैं, आते नहीं।',
  },
  {
    code: 'urgency', weight: 15,
    patterns: [
      /\burgent\b/i, /immediately/i, /within\s*24\s*hours/i, /act\s*now/i,
      /account\s*(will\s*be\s*)?(blocked|suspended|frozen|closed|deactivat)/i,
      /तुरंत/i, /जल्दी/i, /24\s*घंटे/i, /खाता\s*(बंद|ब्लॉक|सस्पेंड)/i,
      /last\s*(chance|warning|date)/i, /आखिरी\s*(मौका|चेतावनी)/i,
    ],
    labelEn: 'Creates panic / urgency',
    labelHi: 'डर / जल्दबाज़ी पैदा कर रहा है',
    detailEn: 'Scammers rush you so you cannot think. Real banks give notice periods and never freeze accounts over one SMS.',
    detailHi: 'ठग जल्दबाज़ी कराते हैं ताकि आप सोच न सकें। असली बैंक नोटिस देते हैं, एक SMS पर खाता बंद नहीं करते।',
  },
  {
    code: 'lottery', weight: 15,
    patterns: [
      /lottery/i, /you\s*(have|ve)\s*won/i, /congratulations.*(won|winner|selected)/i,
      /\bprize\b/i, /लॉटरी/i, /इनाम\s*जीता/i, /बधाई.*(जीत|चुने गए)/i,
      /kbc.*(winner|lottery)/i, /claim\s*(your|the)\s*(prize|reward|amount)/i,
    ],
    labelEn: 'Fake lottery / prize claim',
    labelHi: 'फर्जी लॉटरी / इनाम का दावा',
    detailEn: 'You cannot win a lottery you never entered. "Pay a fee to claim your prize" is always a scam.',
    detailHi: 'जिस लॉटरी में हिस्सा ही नहीं लिया, वह जीत नहीं सकते। "इनाम पाने के लिए फीस दें" हमेशा ठगी है।',
  },
  {
    code: 'advance_fee', weight: 35,
    patterns: [
      /(pay|deposit|transfer).{0,50}(registration|joining|processing|verification|activation)\s*(fee|charge)/i,
      /(fee|deposit).{0,40}to\s*(get|receive|claim|unlock|start)/i,
      /पैसे\s*जमा\s*कर.{0,20}(फीस|रजिस्ट्रेशन)/i,
    ],
    labelEn: 'Advance fee demanded upfront',
    labelHi: 'पहले ही एडवांस फीस माँगी जा रही है',
    detailEn: 'Demanding fees before giving a job, prize or loan is the classic advance-fee scam. Real employers and lotteries never ask for money upfront.',
    detailHi: 'नौकरी, इनाम या लोन देने से पहले फीस माँगना क्लासिक एडवांस-फीस ठगी है। असली नियोक्ता और लॉटरी कभी पहले पैसे नहीं माँगते।',
  },
  {
    code: 'job_fee', weight: 20,
    patterns: [
      /job\s*offer/i, /registration\s*fee/i, /(joining|training|verification)\s*fee/i,
      /pay.{0,40}(to\s*get|for).{0,20}(job|offer|interview)/i,
      /(pay|deposit).{0,30}(registration|joining)/i,
      /work\s*from\s*home.{0,40}(fee|deposit|investment|pay)/i,
      /नौकरी.{0,20}(फीस|पैसे)/i, /(selected|shortlisted).{0,40}(fee|pay)/i,
      /earn.{0,20}(per\s*day|\d+\s*(rs|₹|inr))/i,
      /(fee|deposit).{0,30}(earn|\d+\s*(rs|₹))/i,
    ],
    labelEn: 'Job offer asking for fees',
    labelHi: 'नौकरी के नाम पर फीस माँग रहा है',
    detailEn: 'Real employers never ask candidates to pay registration, training or "verification" fees. Work-from-home offers asking for deposits are scams.',
    detailHi: 'असली नियोक्ता कभी रजिस्ट्रेशन या "वेरिफिकेशन" फीस नहीं माँगते। डिपॉज़िट माँगने वाले work-from-home ऑफर ठगी हैं।',
  },
  {
    code: 'crypto_double', weight: 30,
    patterns: [
      /double\s*(your|the)\s*(bitcoin|\bbtc\b|\beth\b|ethereum|crypto)/i,
      /(crypto|bitcoin|\bbtc\b|ethereum|\beth\b).{0,30}(double|giveaway|free|2x)/i,
      /send.{0,30}(btc|bitcoin|eth).{0,30}(get|receive|back|double)/i,
    ],
    labelEn: 'Crypto doubling scam',
    labelHi: 'क्रिप्टो दोगुना करने की ठगी',
    detailEn: '"Send crypto, get double back" is always a scam — no exchange or trader doubles deposits. Once sent, crypto cannot be recovered.',
    detailHi: '"क्रिप्टो भेजो, दोगुना पाओ" हमेशा ठगी है — कोई एक्सचेंज जमा दोगुना नहीं करता। एक बार भेजने पर क्रिप्टो वापस नहीं मिलता।',
  },
  {
    code: 'too_good', weight: 12,
    patterns: [
      /double\s*(your|the)\s*(money|investment|amount)/i,
      /guaranteed\s*returns/i,
      /investment.{0,30}(double|triple|10x)/i, /risk[\s-]*free\s*(profit|returns|investment)/i,
      /घर\s*बैठे\s*कमाएं/i, /दोगुना\s*पैसा/i,
    ],
    labelEn: 'Too-good-to-be-true returns',
    labelHi: 'अविश्वसनीय मुनाफे का लालच',
    detailEn: 'Guaranteed doubling of money does not exist. These are Ponzi-style traps — early "profits" are bait.',
    detailHi: 'पैसा दोगुना करने की गारंटी कहीं नहीं होती। ये पोंज़ी जैसे जाल हैं — शुरुआती "मुनाफा" सिर्फ चारा है।',
  },
  {
    code: 'threat', weight: 12,
    patterns: [
      /legal\s*action/i, /case\s*(has\s*been|will\s*be)\s*filed/i,
      /sim\s*(will\s*be\s*)?(blocked|deactivat)/i, /electricity\s*(will\s*be\s*)?cut/i,
      /पुलिस\s*केस/i, /कानूनी\s*कार्रवाई/i,
    ],
    labelEn: 'Threatens legal / service action',
    labelHi: 'कानूनी कार्रवाई की धमकी',
    detailEn: 'Threats of arrest, SIM blocking or power cuts over SMS are pressure tactics. Genuine notices come on official letterheads, not random SMS.',
    detailHi: 'SMS पर गिरफ्तारी या SIM बंद करने की धमकी दबाव बनाने का तरीका है। असली नोटिस आधिकारिक लेटरहेड पर आते हैं, रैंडम SMS पर नहीं।',
  },
  {
    code: 'lottery_win', weight: 30,
    patterns: [
      /kbc.{0,30}(lottery|winner|won)/i, /(lottery|kbc).{0,30}(won|winner)/i,
      /(won|winner).{0,30}(lottery|kbc)/i, /केबीसी.{0,20}(लॉटरी|विजेता)/i,
    ],
    labelEn: 'Fake KBC / lottery win claim',
    labelHi: 'फर्जी KBC / लॉटरी जीतने का दावा',
    detailEn: 'KBC never notifies winners by random SMS/WhatsApp. Real KBC winners are announced on TV and contacted officially — never asked to call a random number.',
    detailHi: 'KBC रैंडम SMS/WhatsApp पर विजेताओं को सूचित नहीं करता। असली विजेताओं की घोषणा TV पर होती है — कभी रैंडम नंबर पर कॉल करने को नहीं कहा जाता।',
  },
  {
    code: 'shortener_in_text', weight: 15,
    patterns: [
      /bit\.ly|tinyurl|t\.co|goo\.gl|rb\.gy|cutt\.ly|is\.gd|short\.link/i,
    ],
    labelEn: 'Shortened link hides destination',
    labelHi: 'छोटा लिंक असली पता छिपा रहा है',
    detailEn: 'URL shorteners hide where a link really goes — a favorite trick in parcel, KYC and prize scams. Ask the sender for the full link.',
    detailHi: 'URL shortener असली पता छिपाते हैं — पार्सल, KYC और इनाम वाली ठगी में पसंदीदा चाल। भेजने वाले से पूरा लिंक माँगें।',
  },
  {
    code: 'link_present', weight: 8,
    patterns: [
      /https?:\/\/\S+/i, /www\.\S+\.\w+/i, /bit\.ly|tinyurl|t\.co|goo\.gl|rb\.gy|cutt\.ly/i,
      /click\s*(here|the\s*link|below)/i, /लिंक\s*(पर\s*)?क्लिक/i,
    ],
    labelEn: 'Contains a link to click',
    labelHi: 'क्लिक करने वाला लिंक है',
    detailEn: 'Scam links lead to fake bank/login pages that steal credentials. Type the official website address yourself instead of clicking.',
    detailHi: 'ठगी वाले लिंक नकली बैंक/लॉगिन पेज पर ले जाते हैं जो आपकी जानकारी चुराते हैं। क्लिक करने के बजाय खुद आधिकारिक वेबसाइट का पता लिखें।',
  },
];

const URL_IN_TEXT = /https?:\/\/\S+|www\.\S+\.\w+/i;

const EXPLANATIONS: Record<RiskLevel, { en: string; hi: string }> = {
  dangerous: {
    en: 'This message matches multiple known scam patterns. Treat it as fraud: do not reply, do not click links, do not share OTP/PIN, and do not send money.',
    hi: 'यह मैसेज कई ज्ञात ठगी पैटर्न से मेल खाता है। इसे धोखाधड़ी मानें: जवाब न दें, लिंक न खोलें, OTP/PIN न बताएँ और पैसे न भेजें।',
  },
  suspicious: {
    en: 'This message shows some scam-like signals. Be cautious: verify the sender through the official app or website before taking any action.',
    hi: 'इस मैसेज में ठगी जैसे कुछ संकेत हैं। सावधान रहें: कोई कदम उठाने से पहले आधिकारिक ऐप या वेबसाइट से प्रेषक की पुष्टि करें।',
  },
  safe: {
    en: 'No strong scam signals detected. It still pays to stay alert — scammers constantly invent new scripts.',
    hi: 'कोई मज़बूत ठगी संकेत नहीं मिले। फिर भी सतर्क रहें — ठग लगातार नए तरीके ईजाद करते हैं।',
  },
};

const ACTIONS: Record<RiskLevel, { en: string[]; hi: string[] }> = {
  dangerous: {
    en: [
      'Do NOT click any link or download attachments',
      'Do NOT share OTP, UPI PIN or CVV with anyone',
      'Do NOT send money or approve UPI collect requests',
      'Block the sender and delete the message',
      'Report at https://cybercrime.gov.in',
      'Call the cyber helpline 1930 immediately',
    ],
    hi: [
      'किसी लिंक पर क्लिक न करें, कोई फाइल डाउनलोड न करें',
      'OTP, UPI PIN या CVV किसी को न बताएँ',
      'पैसे न भेजें, UPI collect request approve न करें',
      'भेजने वाले को ब्लॉक करें और मैसेज डिलीट करें',
      'https://cybercrime.gov.in पर रिपोर्ट करें',
      'तुरंत साइबर हेल्पलाइन 1930 पर कॉल करें',
    ],
  },
  suspicious: {
    en: [
      'Do NOT act in a hurry — pause and verify',
      'Verify the sender via the official app/website (type the address yourself)',
      'Never share OTP or PIN to "verify" anything',
      'If in doubt, call 1930 for guidance',
    ],
    hi: [
      'जल्दबाज़ी में कोई कदम न उठाएँ — रुककर जाँचें',
      'आधिकारिक ऐप/वेबसाइट से प्रेषक की पुष्टि करें (पता खुद लिखें)',
      '"वेरिफाई" करने के नाम पर OTP/PIN कभी न बताएँ',
      'शक हो तो मार्गदर्शन के लिए 1930 पर कॉल करें',
    ],
  },
  safe: {
    en: [
      'Looks okay, but stay alert to new scam scripts',
      'Remember: banks never ask for OTP or PIN',
    ],
    hi: [
      'ठीक लग रहा है, लेकिन नई ठगी स्क्रिप्ट से सतर्क रहें',
      'याद रखें: बैंक कभी OTP या PIN नहीं माँगते',
    ],
  },
};

/** Stage 1 — Extractor: find which rules match the text. */
export function matchRules(rawText: string): Rule[] {
  // Normalize Unicode homoglyphs (Cyrillic/Greek lookalikes) so scammers
  // can't evade detection with "ассоunt" (Cyrillic а) instead of "account".
  // Also expand Indian-English abbreviations ("a/c" -> "account").
  const text = normalizeAbbreviations(normalizeHomoglyphs(rawText));
  const matched = RULES.filter((rule) => rule.patterns.some((re) => re.test(text)));
  // A message that ASKS for the OTP can never be a genuine OTP delivery,
  // even if it parrots "do not share" to sound legitimate (scammers do this).
  if (OTP_REQUEST.test(text)) {
    return matched.filter((r) => r.code !== 'legit_otp');
  }
  return matched;
}

// Cyrillic + Greek characters that look identical to Latin letters.
const HOMOGLYPHS: Record<string, string> = {
  'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'ј': 'j', 'о': 'o', 'р': 'p',
  'ѕ': 's', 'х': 'x', 'у': 'y', 'ԛ': 'q', 'һ': 'h', 'ո': 'n', 'ԝ': 'w',
  'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
  'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X',
  'Ү': 'Y', 'Ζ': 'Z', 'α': 'a', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u',
  'χ': 'x', 'κ': 'k', 'ν': 'v', 'η': 'n', 'μ': 'm', 'Ο': 'O',
};

export function normalizeHomoglyphs(s: string): string {
  return s.normalize('NFKC').replace(/[а-яА-ЯёЁα-ωΑ-Ω]/g, (c) => HOMOGLYPHS[c] ?? c);
}

/** Normalize common Indian-English abbreviations scammers use to dodge filters. */
export function normalizeAbbreviations(s: string): string {
  return s
    .replace(/\ba\/c\b/gi, 'account')
    .replace(/\bw\/o\b/gi, 'without')
    .replace(/\bupdation\b/gi, 'update');
}

// Active solicitation of the OTP — disqualifies the legit_otp trust signal.
const OTP_REQUEST = /(share|send|batao|bhejo|bhej\s*dijiye|बताएं|भेजें).{0,30}\botp\b/i;

export function extractUrls(rawText: string): string[] {
  return [...rawText.matchAll(/https?:\/\/\S+|www\.\S+\.\w+/gi)].map((m) => m[0]);
}

/** Stage 2 — Scorer: weighted sum of matched rules, floored at 0, capped at 100. */
export function scoreOf(matched: Rule[]): number {
  return Math.max(0, Math.min(100, matched.reduce((s, r) => s + r.weight, 0)));
}

export function riskOf(score: number): RiskLevel {
  return score >= 60 ? 'dangerous' : score >= 30 ? 'suspicious' : 'safe';
}

/** Stage 3 — Explainer: localized flags + plain-language explanation. */
export function buildFlags(matched: Rule[], lang: Lang): RedFlag[] {
  return matched
    .filter((r) => (r.kind ?? 'red') === 'red')
    .slice()
    .sort((a, b) => b.weight - a.weight)
    .map((rule) => ({
      code: rule.code,
      label: lang === 'hi' ? rule.labelHi : rule.labelEn,
      detail: lang === 'hi' ? rule.detailHi : rule.detailEn,
      weight: rule.weight,
    }));
}

/** Trust signals: legitimacy indicators (negative-weight rules), shown in green. */
export function buildTrustSignals(matched: Rule[], lang: Lang): RedFlag[] {
  return matched
    .filter((r) => r.kind === 'trust')
    .map((rule) => ({
      code: rule.code,
      label: lang === 'hi' ? rule.labelHi : rule.labelEn,
      detail: lang === 'hi' ? rule.detailHi : rule.detailEn,
      weight: rule.weight,
    }));
}

export function buildExplanation(riskLevel: RiskLevel, lang: Lang): string {
  return lang === 'hi' ? EXPLANATIONS[riskLevel].hi : EXPLANATIONS[riskLevel].en;
}

/** Stage 4 — Advisor: recommended actions. */
export function buildActions(riskLevel: RiskLevel, lang: Lang): string[] {
  return lang === 'hi' ? ACTIONS[riskLevel].hi : ACTIONS[riskLevel].en;
}

export function analyzeText(rawText: string, lang: Lang = 'en'): TextAnalysis {
  const text = rawText.slice(0, 5000);
  const matched = matchRules(text);
  const score = scoreOf(matched);
  const riskLevel = riskOf(score);
  const redFlags = buildFlags(matched, lang);
  const trustSignals = buildTrustSignals(matched, lang);

  return {
    score,
    riskLevel,
    redFlags,
    trustSignals,
    explanation: buildExplanation(riskLevel, lang),
    recommendedActions: buildActions(riskLevel, lang),
    similarKnownScams: [],
    engine: 'rule-based',
    demo: process.env.SCAMSHIELD_DEMO !== '0',
    lang,
  };
}

export function hasUrl(text: string): boolean {
  return URL_IN_TEXT.test(text);
}
