/**
 * Static scam-pattern library — common fraud scripts seen in India.
 * Served by GET /api/scam-patterns. Content is educational, not exhaustive.
 */

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

export const SCAM_PATTERNS: ScamPattern[] = [
  {
    id: 'upi-collect',
    icon: '💸',
    titleEn: 'UPI Collect-Request Fraud',
    titleHi: 'UPI Collect Request ठगी',
    summaryEn: 'You get a "collect request" in your UPI app from a stranger. Approving it SENDS money from your account — scammers claim it will "receive" payment.',
    summaryHi: 'अजनबी से UPI ऐप में "collect request" आती है। इसे approve करने से आपके खाते से पैसे जाते हैं — ठग कहते हैं इससे पेमेंट "मिलेगा"।',
    spotEn: [
      'Unexpected collect request from an unknown UPI ID',
      'Seller asks YOU to enter your UPI PIN to "receive" money',
      'QR code sent to "receive payment"',
    ],
    spotHi: [
      'अनजान UPI ID से अचानक collect request',
      'विक्रेता पैसे "पाने" के लिए आपसे UPI PIN डालने को कहे',
      '"पेमेंट पाने" के लिए QR कोड भेजा जाए',
    ],
    doEn: [
      'NEVER enter your UPI PIN to receive money — receiving needs no PIN',
      'Decline and report the collect request in your UPI app',
      'Verify the seller on a trusted platform before paying',
    ],
    doHi: [
      'पैसे पाने के लिए कभी UPI PIN न डालें — पैसे आने में PIN नहीं लगता',
      'UPI ऐप में collect request decline करके रिपोर्ट करें',
      'पेमेंट से पहले विक्रेता की भरोसेमंद प्लेटफॉर्म पर पुष्टि करें',
    ],
    exampleEn: '"Sir, I am sending ₹5,000 for your OLX ad. Just approve the collect request and enter your UPI PIN to receive it."',
    exampleHi: '"सर, आपके OLX विज्ञापन के लिए ₹5,000 भेज रहा हूँ। बस collect request approve करके पैसे पाने के लिए UPI PIN डालें।"',
  },
  {
    id: 'otp-share',
    icon: '🔑',
    titleEn: 'OTP Sharing Scam',
    titleHi: 'OTP बताने वाली ठगी',
    summaryEn: 'A caller pretends to be bank staff and asks for the OTP "to verify" your account, block a transaction, or deliver a prize. The OTP authorises a theft in progress.',
    summaryHi: 'कॉलर बैंक कर्मचारी बनकर खाता "वेरिफाई" करने, ट्रांज़ैक्शन रोकने या इनाम देने के नाम पर OTP माँगता है। वह OTP चल रही चोरी को अधिकृत करता है।',
    spotEn: [
      'Anyone asks for OTP, CVV or UPI PIN — ever',
      'Caller creates urgency: "your account will be blocked in 10 minutes"',
      'SMS says "do not share this OTP" while the caller asks for it',
    ],
    spotHi: [
      'कोई भी OTP, CVV या UPI PIN माँगे — कभी भी',
      'कॉलर जल्दबाज़ी कराए: "10 मिनट में खाता बंद हो जाएगा"',
      'SMS में "यह OTP किसी को न बताएँ" लिखा हो और कॉलर वही माँग रहा हो',
    ],
    doEn: [
      'Cut the call. Banks NEVER ask for OTP',
      'Call your bank on the official number printed on your card',
      'If you shared an OTP, freeze your card/UPI in the app immediately and call 1930',
    ],
    doHi: [
      'कॉल काट दें। बैंक कभी OTP नहीं माँगते',
      'कार्ड पर छपे आधिकारिक नंबर पर बैंक को कॉल करें',
      'अगर OTP बता दिया है तो ऐप में तुरंत कार्ड/UPI फ्रीज़ करें और 1930 पर कॉल करें',
    ],
    exampleEn: '"I am calling from SBI head office. Your account is blocked. Please share the OTP I just sent to unblock it."',
    exampleHi: '"मैं SBI हेड ऑफिस से बोल रहा हूँ। आपका खाता ब्लॉक है। अनब्लॉक करने के लिए अभी भेजा OTP बताएँ।"',
  },
  {
    id: 'kyc-fraud',
    icon: '🏦',
    titleEn: 'Fake KYC Update Scam',
    titleHi: 'फर्जी KYC अपडेट ठगी',
    summaryEn: 'SMS claims your bank KYC expired and your account will be frozen. The link opens a fake bank page or installs a screen-sharing app like AnyDesk to steal OTPs.',
    summaryHi: 'SMS आता है कि बैंक KYC एक्सपायर हो गया, खाता फ्रीज़ होगा। लिंक नकली बैंक पेज खोलता है या AnyDesk जैसा स्क्रीन-शेयरिंग ऐप इंस्टॉल कराता है ताकि OTP चुराए जा सकें।',
    spotEn: [
      'SMS about "KYC expired" with a link to click',
      'Asked to install AnyDesk / TeamViewer / "support app"',
      'Sender ID looks odd or message has spelling mistakes',
    ],
    spotHi: [
      '"KYC एक्सपायर" वाला SMS जिसमें क्लिक करने वाला लिंक हो',
      'AnyDesk / TeamViewer / "सपोर्ट ऐप" इंस्टॉल करने को कहा जाए',
      'भेजने वाले का नाम अजीब हो या मैसेज में वर्तनी की गलतियाँ हों',
    ],
    doEn: [
      'Do not click the link — do KYC only inside your bank\'s official app or branch',
      'Never install screen-sharing apps on a stranger\'s request',
      'Forward the SMS to 1930 (report phishing)',
    ],
    doHi: [
      'लिंक पर क्लिक न करें — KYC सिर्फ बैंक के आधिकारिक ऐप या ब्रांच में करें',
      'अजनबी के कहने पर स्क्रीन-शेयरिंग ऐप कभी इंस्टॉल न करें',
      'SMS को 1930 पर फॉरवर्ड करके रिपोर्ट करें',
    ],
    exampleEn: '"Dear customer, your SBI KYC is suspended. Update within 24 hrs to avoid account freeze: http://sbi-kyc-verify.tk"',
    exampleHi: '"प्रिय ग्राहक, आपका SBI KYC सस्पेंड है। खाता फ्रीज़ से बचने के लिए 24 घंटे में अपडेट करें: http://sbi-kyc-verify.tk"',
  },
  {
    id: 'job-fee',
    icon: '💼',
    titleEn: 'Fake Job Offer Fee Scam',
    titleHi: 'फर्जी नौकरी फीस ठगी',
    summaryEn: 'You get a job offer over WhatsApp/Telegram asking for "registration", "training" or "verification" fees — or a work-from-home task job asking for a deposit first.',
    summaryHi: 'WhatsApp/Telegram पर नौकरी का ऑफर आता है जिसमें "रजिस्ट्रेशन", "ट्रेनिंग" या "वेरिफिकेशन" फीस माँगी जाती है — या work-from-home टास्क जॉब के लिए पहले डिपॉज़िट माँगा जाता है।',
    spotEn: [
      'Job offer without any interview, via WhatsApp/Telegram',
      'Any fee demanded: registration, training, uniform, verification',
      'Salary sounds far too high for simple tasks (liking videos, rating products)',
    ],
    spotHi: [
      'बिना इंटरव्यू WhatsApp/Telegram पर नौकरी का ऑफर',
      'किसी भी तरह की फीस माँगी जाए: रजिस्ट्रेशन, ट्रेनिंग, यूनिफॉर्म, वेरिफिकेशन',
      'आसान काम के लिए बहुत ज़्यादा सैलरी का वादा (वीडियो लाइक करना, रेटिंग देना)',
    ],
    doEn: [
      'Real employers never charge candidates — walk away from any fee demand',
      'Verify the company on its official website and LinkedIn',
      'Never pay "to unlock" tasks or higher earnings',
    ],
    doHi: [
      'असली नियोक्ता उम्मीदवारों से पैसे नहीं लेते — फीस माँगने पर तुरंत हट जाएँ',
      'कंपनी की आधिकारिक वेबसाइट और LinkedIn पर पुष्टि करें',
      'टास्क "अनलॉक" करने या ज़्यादा कमाई के लिए कभी पैसे न दें',
    ],
    exampleEn: '"Congratulations! You are selected for a work-from-home data entry job, ₹45,000/month. Pay ₹1,500 registration fee to start."',
    exampleHi: '"बधाई! आप work-from-home डेटा एंट्री जॉब के लिए चुने गए हैं, ₹45,000/माह। शुरू करने के लिए ₹1,500 रजिस्ट्रेशन फीस दें।"',
  },
  {
    id: 'digital-arrest',
    icon: '🚔',
    titleEn: '"Digital Arrest" Scam',
    titleHi: '"डिजिटल अरेस्ट" ठगी',
    summaryEn: 'Callers posing as CBI/police/customs claim you are involved in money laundering or a parcel with drugs. They keep you on video call ("digital arrest") and demand money to "close the case".',
    summaryHi: 'CBI/पुलिस/कस्टम बनकर कॉलर कहते हैं आप मनी लॉन्ड्रिंग या ड्रग्स वाले पार्सल में फँसे हैं। वे आपको वीडियो कॉल पर रखते हैं ("डिजिटल अरेस्ट") और केस "बंद" करने के पैसे माँगते हैं।',
    spotEn: [
      'Threat of arrest over a phone/video call',
      'Told not to disconnect or tell anyone',
      'Asked to transfer money to "verify" funds or pay a "fine"/"bail"',
    ],
    spotHi: [
      'फोन/वीडियो कॉल पर गिरफ्तारी की धमकी',
      'कॉल न काटने और किसी को न बताने को कहा जाए',
      'रकम "वेरिफाई" करने या "जुर्माना"/"ज़मानत" के नाम पर पैसे ट्रांसफर करने को कहा जाए',
    ],
    doEn: [
      'Disconnect immediately — real police never arrest over video call',
      'Do not transfer any money, whatever the threat',
      'Report the number at https://cybercrime.gov.in and call 1930',
    ],
    doHi: [
      'तुरंत कॉल काट दें — असली पुलिस वीडियो कॉल पर गिरफ्तार नहीं करती',
      'धमकी चाहे जो हो, कोई पैसे ट्रांसफर न करें',
      'नंबर की https://cybercrime.gov.in पर रिपोर्ट करें और 1930 पर कॉल करें',
    ],
    exampleEn: '"This is CBI officer Sharma. Your Aadhaar is linked to a money-laundering case. Stay on video call — you are under digital arrest. Transfer ₹2 lakh for verification."',
    exampleHi: '"मैं CBI अधिकारी शर्मा बोल रहा हूँ। आपका आधार मनी लॉन्ड्रिंग केस से जुड़ा है। वीडियो कॉल पर रहें — आप डिजिटल अरेस्ट में हैं। वेरिफिकेशन के लिए ₹2 लाख ट्रांसफर करें।"',
  },
  {
    id: 'lottery',
    icon: '🎰',
    titleEn: 'Lottery / Prize Fee Scam',
    titleHi: 'लॉटरी / इनाम फीस ठगी',
    summaryEn: 'SMS/WhatsApp says you won a lottery, KBC prize or lucky-draw. To "claim" it you must pay tax, processing or courier fees first — the prize does not exist.',
    summaryHi: 'SMS/WhatsApp आता है कि आपने लॉटरी, KBC इनाम या लकी-ड्रॉ जीता है। "क्लेम" करने के लिए पहले टैक्स, प्रोसेसिंग या कूरियर फीस देनी होगी — इनाम असल में है ही नहीं।',
    spotEn: [
      'You "won" a contest you never entered',
      'Asked to pay any fee/tax to receive the prize',
      'Prize is huge (car, crores) from an unknown organiser',
    ],
    spotHi: [
      'ऐसी प्रतियोगिता "जीत" ली जिसमें हिस्सा ही नहीं लिया',
      'इनाम पाने के लिए कोई फीस/टैक्स देने को कहा जाए',
      'अनजान आयोजक से बहुत बड़ा इनाम (कार, करोड़ों)',
    ],
    doEn: [
      'Delete the message — you cannot win a lottery you never entered',
      'Never pay to receive a prize',
      'Check KBC/official lottery sites directly if unsure',
    ],
    doHi: [
      'मैसेज डिलीट करें — जिस लॉटरी में हिस्सा नहीं लिया, वह जीत नहीं सकते',
      'इनाम पाने के लिए कभी पैसे न दें',
      'शक हो तो KBC/आधिकारिक लॉटरी साइट पर खुद जाँचें',
    ],
    exampleEn: '"CONGRATULATIONS! Your mobile number won ₹25,00,000 in the KBC lucky draw. Pay ₹12,500 processing fee to claim: http://kbc-winner-claim.tk"',
    exampleHi: '"बधाई! आपके मोबाइल नंबर ने KBC लकी ड्रॉ में ₹25,00,000 जीते हैं। क्लेम करने के लिए ₹12,500 प्रोसेसिंग फीस दें: http://kbc-winner-claim.tk"',
  },
];
