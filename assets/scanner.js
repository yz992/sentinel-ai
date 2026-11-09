/* Sentinel AI — local threat analysis engine
 * Detects phishing infrastructure, credential theft, social engineering,
 * malicious metadata, embedded payloads and QR/OCR content.
 */
(function () {
  'use strict';

  const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  const LEVELS = [
    {
      key: 'low',
      label: 'Low risk',
      short: 'LOW',
      range: '0–19',
      description: 'No meaningful threat indicators detected.',
      color: '#54e6ae',
    },
    {
      key: 'moderate',
      label: 'Moderate risk',
      short: 'MODERATE',
      range: '20–44',
      description: 'Suspicious characteristics warrant caution.',
      color: '#f5c451',
    },
    {
      key: 'high',
      label: 'High risk',
      short: 'HIGH',
      range: '45–69',
      description: 'Multiple strong indicators of malicious intent.',
      color: '#ff9257',
    },
    {
      key: 'critical',
      label: 'Critical threat',
      short: 'CRITICAL',
      range: '70–100',
      description: 'Active compromise risk. Do not interact.',
      color: '#ff5f70',
    },
  ];

  /* Each brand lists every domain it actually operates. Regional storefronts,
     country domains and separately registered service domains must be included,
     otherwise a legitimate local site (for example amazon.co.uk) looks like
     brand impersonation because only the .com was trusted. */
  const BRANDS = [
    { name: 'PayPal', token: 'paypal', domain: 'paypal.com', domains: [
      'paypal.co.uk', 'paypal.de', 'paypal.fr', 'paypal.it', 'paypal.es',
      'paypal.ca', 'paypal.com.au', 'paypal.nl', 'paypal.se', 'paypal.pl',
      'paypal.com.br', 'paypal.com.mx', 'paypal.com.ar', 'paypal.be',
      'paypal.at', 'paypal.ch', 'paypal.dk', 'paypal.no', 'paypal.fi',
      'paypal.ie', 'paypal.pt', 'paypal.com.sg', 'paypal.com.hk',
    ] },
    { name: 'Apple', token: 'apple', domain: 'apple.com', domains: ['apple.co.uk'] },
    { name: 'Microsoft', token: 'microsoft', domain: 'microsoft.com', domains: [
      'microsoft.co.uk', 'microsoftonline.com', 'microsoftstore.com',
    ] },
    { name: 'Google', token: 'google', domain: 'google.com', domains: [
      'google.co.uk', 'google.de', 'google.fr', 'google.it', 'google.es',
      'google.ca', 'google.com.au', 'google.co.jp', 'google.com.br',
      'google.co.in', 'google.com.mx', 'google.nl', 'google.se', 'google.pl',
      'google.com.sg', 'google.ae', 'google.com.tr', 'google.co.za',
      'google.co.nz', 'google.ie', 'google.pt', 'google.be', 'google.ch',
      'google.at', 'google.dk', 'google.no', 'google.fi', 'google.cz',
      'google.gr', 'google.hu', 'google.ro', 'gmail.com', 'googlemail.com',
      'youtube.com',
    ] },
    { name: 'Amazon', token: 'amazon', domain: 'amazon.com', domains: [
      'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es',
      'amazon.ca', 'amazon.com.au', 'amazon.co.jp', 'amazon.in',
      'amazon.com.br', 'amazon.com.mx', 'amazon.nl', 'amazon.se',
      'amazon.pl', 'amazon.sg', 'amazon.ae', 'amazon.sa', 'amazon.com.tr',
      'amazon.eg', 'amazon.com.be', 'amazon.ie',
    ] },
    { name: 'Netflix', token: 'netflix', domain: 'netflix.com' },
    { name: 'Facebook', token: 'facebook', domain: 'facebook.com', domains: ['fb.com'] },
    { name: 'Instagram', token: 'instagram', domain: 'instagram.com' },
    { name: 'WhatsApp', token: 'whatsapp', domain: 'whatsapp.com', domains: [
      'wa.me', 'whatsapp.net',
    ] },
    { name: 'LinkedIn', token: 'linkedin', domain: 'linkedin.com' },
    { name: 'GitHub', token: 'github', domain: 'github.com' },
    { name: 'Dropbox', token: 'dropbox', domain: 'dropbox.com', domains: [
      'dropboxusercontent.com',
    ] },
    { name: 'Coinbase', token: 'coinbase', domain: 'coinbase.com' },
    { name: 'Binance', token: 'binance', domain: 'binance.com', domains: ['binance.us'] },
    { name: 'Chase', token: 'chase', domain: 'chase.com', domains: ['chase.co.uk'] },
    { name: 'Bank of America', token: 'bankofamerica', domain: 'bankofamerica.com', domains: ['bofa.com'] },
    { name: 'DHL', token: 'dhl', domain: 'dhl.com', domains: ['dhl.de', 'dhl.co.uk'] },
    { name: 'FedEx', token: 'fedex', domain: 'fedex.com', domains: [
      'fedex.co.uk', 'fedex.de', 'fedex.fr',
    ] },
    { name: 'UPS', token: 'ups', domain: 'ups.com' },
    { name: 'USPS', token: 'usps', domain: 'usps.com' },
    { name: 'Steam', token: 'steam', domain: 'steampowered.com' },
    { name: 'Steam Community', token: 'steamcommunity', domain: 'steamcommunity.com' },
    { name: 'Discord', token: 'discord', domain: 'discord.com', domains: [
      'discord.gg', 'discordapp.com',
    ] },
    { name: 'Telegram', token: 'telegram', domain: 'telegram.org', domains: [
      't.me', 'telegram.me',
    ] },
    { name: 'TikTok', token: 'tiktok', domain: 'tiktok.com', domains: ['tiktokv.com'] },
    { name: 'X', token: 'twitter', domain: 'x.com', domains: ['twitter.com'] },
    { name: 'Outlook', token: 'outlook', domain: 'outlook.com', domains: [
      'live.com', 'office.com',
    ] },
    { name: 'Adobe', token: 'adobe', domain: 'adobe.com' },
    { name: 'DocuSign', token: 'docusign', domain: 'docusign.com', domains: ['docusign.net'] },
    { name: 'Zoom', token: 'zoom', domain: 'zoom.us', domains: ['zoom.com'] },
    { name: 'Spotify', token: 'spotify', domain: 'spotify.com' },
    { name: 'Airbnb', token: 'airbnb', domain: 'airbnb.com', domains: ['airbnb.co.uk'] },
    { name: 'Uber', token: 'uber', domain: 'uber.com' },
    { name: 'Walmart', token: 'walmart', domain: 'walmart.com' },
    { name: 'IRS', token: 'irs', domain: 'irs.gov' },
    { name: 'HMRC', token: 'hmrc', domain: 'gov.uk' },
    { name: 'Revolut', token: 'revolut', domain: 'revolut.com' },
    { name: 'Wise', token: 'wise', domain: 'wise.com' },
  ];

  function brandDomains(brand) {
    return [brand.domain].concat(brand.domains || []);
  }

  const TRUSTED_DOMAINS = new Set(BRANDS.reduce((all, brand) => all.concat(brandDomains(brand)), []));

  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'cutt.ly', 'shorturl.at', 'rebrand.ly', 'rb.gy', 'tiny.cc', 'lnkd.in',
    't.ly', 's.id', 'v.gd', 'short.gy', 'shorte.st', 'adf.ly', 'bl.ink',
    'clck.ru', 'u.to', 'x.co', 'q.link', 'shorturl.gg',
  ]);

  const HIGH_ABUSE_TLDS = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'click', 'link', 'work',
    'rest', 'cam', 'surf', 'monster', 'buzz', 'fit', 'icu', 'cyou', 'sbs',
    'cfd', 'quest', 'loan', 'download', 'stream', 'gdn', 'bid', 'win',
    'review', 'date', 'party', 'trade', 'webcam', 'zip', 'mov', 'country',
    'kim', 'science', 'racing', 'accountant', 'faith', 'cricket', 'men',
  ]);

  const SUSPICIOUS_TLDS_MEDIUM = new Set([
    'online', 'site', 'website', 'space', 'store', 'shop', 'life', 'live',
    'pro', 'info', 'biz', 'support', 'help', 'services', 'digital', 'email',
    'gift', 'deals', 'offer', 'discount', 'claims', 'finance', 'capital',
  ]);

  const MULTI_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
    'co.nz', 'co.jp', 'com.br', 'co.za', 'com.mx', 'co.in', 'com.sg',
    'com.hk', 'co.kr', 'com.tr', 'com.cn', 'com.tw', 'co.il', 'com.ar',
    'com.co', 'com.pe', 'com.ph', 'com.my', 'com.vn', 'co.id', 'com.ng',
  ]);

  const DANGEROUS_EXTENSIONS = new Set([
    'exe', 'scr', 'msi', 'bat', 'cmd', 'com', 'ps1', 'vbs', 'vbe', 'js',
    'jse', 'wsf', 'wsh', 'hta', 'jar', 'apk', 'dmg', 'pkg', 'deb', 'app',
    'run', 'bin', 'lnk',
  ]);

  const ARCHIVE_EXTENSIONS = new Set([
    'zip', 'rar', '7z', 'iso', 'img', 'vhd', 'vhdx', 'cab', 'tar', 'gz',
  ]);

  const STRONG_URL_KEYWORDS = [
    'verify-account', 'account-verify', 'account-suspended', 'account-locked',
    'secure-login', 'login-secure', 'signin-secure', 'password-reset',
    'reset-password', 'confirm-identity', 'identity-verify', 'unlock-account',
    'billing-update', 'update-billing', 'wallet-connect', 'wallet-verify',
    'seed-phrase', 'recovery-phrase', 'private-key', 'claim-reward',
    'claim-prize', 'airdrop-claim', 'validate-account', 'reactivate-account',
    'security-alert', 'unusual-activity', 'session-expired', 'reauthenticate',
    'invoice-payment', 'payment-required', 'document-shared', 'shared-document',
    'docusign', 'e-signature', 'parcel-redelivery', 'delivery-failed',
  ];

  const GENERAL_URL_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'security',
    'account', 'update', 'confirm', 'password', 'billing', 'payment',
    'invoice', 'wallet', 'unlock', 'recover', 'support', 'helpdesk',
    'refund', 'claim', 'bonus', 'prize', 'gift', 'airdrop', 'kyc', 'mfa',
    '2fa', 'otp', 'session', 'authenticate', 'webscr', 'cmd',
  ];

  const PHISHING_TEXT_RULES = [
    {
      id: 'text-seed-phrase',
      re: /\b(send|share|enter|provide|submit|verify|confirm|type)\b[^.!?\n]{0,60}\b(seed phrase|recovery phrase|private key|secret phrase)\b/i,
      title: 'Seed phrase or private key requested',
      desc: 'No legitimate service will ever ask for a wallet recovery phrase or private key.',
      severity: 'critical', points: 50, category: 'credential',
    },
    {
      id: 'text-otp',
      re: /\b(send|share|tell|provide|give|read|forward|reply|respond|repeat|revert|confirm)\b[^.!?\n]{0,60}\b(otp|one[- ]time (?:code|password|pin)|verification code|security code|2fa code|authentication code|(?:6|six)[- ]digit code)\b/i,
      guard: /\b(never|do not|don't|won'?t|will not|no one|nobody|not)\b[^.!?\n]{0,40}$/i,
      title: 'One-time security code requested',
      desc: 'A request for a verification code is a classic account-takeover pattern.',
      severity: 'critical', points: 40, category: 'credential',
    },
    {
      id: 'text-otp-relay',
      re: /\b(send|share|tell|give|read|forward|reply|respond|repeat|revert|text|message)\b[^.!?\n]{0,45}\b(code|otp|passcode|pin)\b/i,
      guard: /\b(never|do not|don't|won'?t|will not|no one|nobody|not)\b[^.!?\n]{0,40}$/i,
      title: 'Security code relay request',
      desc: 'Someone is asking for a security code to be passed to them. One-time codes are the last line of defence against account takeover and should never be relayed.',
      severity: 'critical', points: 38, category: 'credential',
    },
    {
      id: 'text-otp-provenance',
      re: /\b(code|otp|passcode|pin)\b[^.!?\n]{0,35}\b(you (?:just )?(?:received|got)|sent to your (?:phone|mobile|email)|texted to you)\b[^.!?\n]{0,45}\b(send|share|tell|give|read|forward|reply|respond|repeat|revert|text|message)\b/i,
      guard: /\b(never|do not|don't|won'?t|will not|no one|nobody|not)\b[^.!?\n]{0,40}$/i,
      title: 'Request to forward a received code',
      desc: 'The message refers to a code delivered to your device and asks you to pass it on. Legitimate support staff never need the code that was sent to you.',
      severity: 'critical', points: 38, category: 'credential',
    },
    {
      id: 'text-otp-question',
      re: /\b(what(?:'s| is)|which is|i need|i want|require|let me know)\b[^.!?\n]{0,35}\b(?:the\s+)?(code|otp|passcode|pin)\b[^.!?\n]{0,35}\b(you|sent|received|texted|phone|mobile|email|message)\b/i,
      title: 'Indirect request for a one-time code',
      desc: 'The sender is fishing for a code delivered to you without using an obvious command. This is the same account-takeover pattern in softer language.',
      severity: 'high', points: 34, category: 'credential',
    },
    {
      id: 'text-gift-card',
      re: /\b(gift cards?|itunes cards?|apple cards?|google play cards?|steam cards?|amazon cards?)\b/i,
      title: 'Gift-card payment pattern',
      desc: 'Gift cards are irreversible and heavily used in impersonation fraud.',
      severity: 'critical', points: 38, category: 'financial',
    },
    {
      id: 'text-executive-impersonation',
      re: /\b(this is|i am|from) (the )?(ceo|cfo|coo|cto|founder|president|director|executive)\b/i,
      title: 'Executive impersonation pattern',
      desc: 'The sender claims executive authority to pressure the recipient into an unusual request. Verify identity through a separate channel.',
      severity: 'high', points: 22, category: 'social',
    },
    {
      id: 'text-wire',
      re: /\b(wire transfer|bank transfer|routing number|account number|beneficiary|western union|moneygram)\b/i,
      title: 'Sensitive payment transfer language',
      desc: 'The message attempts to move funds or collect banking details.',
      severity: 'high', points: 24, category: 'financial',
    },
    {
      id: 'text-crypto',
      re: /\b(bitcoin|btc|ethereum|eth|usdt|trc20|crypto wallet|binance|coinbase wallet)\b/i,
      title: 'Cryptocurrency payment channel',
      desc: 'Cryptocurrency transfers are irreversible and commonly used for extortion or fake investment scams.',
      severity: 'high', points: 20, category: 'financial',
    },
    {
      id: 'text-urgency',
      re: /\b(act now|act immediately|urgent(ly)?|immediately|within (12|24|48|72) hours|final (notice|warning)|last chance|expires? (today|soon)|time[- ]sensitive|don't delay)\b/i,
      title: 'Artificial urgency',
      desc: 'Pressure to act quickly is a core social-engineering tactic used to bypass careful thought.',
      severity: 'medium', points: 15, category: 'social',
    },
    {
      id: 'text-threat',
      re: /\b(suspended|terminated|deactivated|locked|disabled|permanently closed|legal action|lawsuit|arrest|police|fine|penalty|account closure|unauthori[sz]ed (login|access|transaction))\b/i,
      title: 'Threat or account-loss pressure',
      desc: 'The sender uses fear of loss or legal consequences to force a response.',
      severity: 'medium', points: 16, category: 'social',
    },
    {
      id: 'text-credentials',
      re: /\b(password|passcode|otp|one[- ]time code|verification code|2fa|two[- ]factor|security code|pin|login|sign in|authenticate|verify your identity|confirm your account)\b/i,
      title: 'Credential or identity request',
      desc: 'The message steers the recipient toward authentication or identity-verification actions.',
      severity: 'low', points: 7, category: 'credential',
    },
    {
      id: 'text-secrecy',
      re: /\b(do not (?:tell|inform)\b[^.!?\n]{0,30}\b(?:anyone|anybody|others|your (?:boss|manager|family|colleagues))|keep (?:this|it) (?:confidential|secret)|between us|don't tell (?:anyone|anybody)|confidential matter)\b/i,
      title: 'Request for secrecy',
      desc: 'Asking the recipient to hide the request isolates them from people who might spot the fraud.',
      severity: 'high', points: 21, category: 'social',
    },
    {
      id: 'text-generic-greeting',
      re: /\b(dear (customer|user|client|member|account holder|sir\/madam)|valued customer)\b/i,
      title: 'Generic, non-personal greeting',
      desc: 'Bulk phishing frequently uses impersonal greetings because the sender does not know the recipient.',
      severity: 'low', points: 7, category: 'social',
    },
    {
      id: 'text-off-platform',
      re: /\b(whatsapp|telegram|signal)\b[^.!?\n]{0,40}\b(number|contact|message|chat)\b/i,
      title: 'Push to an off-platform channel',
      desc: 'Moving the conversation to a private messenger is common in fraud and impersonation attempts.',
      severity: 'medium', points: 13, category: 'social',
    },
    {
      id: 'text-lottery',
      re: /\b(congratulations|you (have )?won|winner|lottery|jackpot|prize|claim your|free (gift|iphone|trip))\b/i,
      title: 'Unsolicited prize or reward',
      desc: 'Unexpected winnings are used to bait victims into paying fees or sharing personal data.',
      severity: 'medium', points: 15, category: 'social',
    },
    {
      id: 'text-investment',
      re: /\b(guaranteed (returns?|profit)|risk[- ]free (investment|profit)|double your (money|investment)|passive income|forex signals?|investment opportunity)\b/i,
      title: 'High-return investment pitch',
      desc: 'Guaranteed or risk-free returns are a hallmark of investment fraud.',
      severity: 'high', points: 22, category: 'financial',
    },
    {
      id: 'text-impersonation',
      re: /\b(microsoft|apple|paypal|amazon|google|netflix|irs|internal revenue|social security|bank of america|chase|dhl|fedex|ups|usps)\b[^.!?\n]{0,50}\b(security|support|team|service|alert|account|department)\b/i,
      title: 'Brand impersonation language',
      desc: 'A trusted company is named in a way that resembles an official security or support notice.',
      severity: 'medium', points: 15, category: 'social',
    },
    {
      id: 'text-personal-data',
      re: /\b(social security|ssn|date of birth|mother's maiden|passport (number|scan)|driver'?s licen[cs]e|home address|card number|cvv|expiry date)\b/i,
      title: 'Sensitive personal data requested',
      desc: 'The message asks for identity or financial data that can enable fraud.',
      severity: 'high', points: 24, category: 'credential',
    },
    {
      id: 'text-click-here',
      re: /\b(click here|tap here|follow this link|open the link|access your account)\b/i,
      title: 'Call-to-action link language',
      desc: 'The message is engineered to make the recipient click an embedded destination.',
      severity: 'low', points: 8, category: 'link',
    },
    {
      id: 'text-attachment',
      re: /\b[^\s]+\.(exe|scr|msi|bat|cmd|ps1|vbs|js|jse|hta|jar|apk|iso|img|zip|rar|7z)\b/i,
      title: 'Potentially dangerous attachment',
      desc: 'An executable or archive is referenced in the message. These are common malware delivery formats.',
      severity: 'high', points: 26, category: 'payload',
    },
    {
      id: 'text-kindly',
      re: /\bkindly\b/i,
      title: 'Unusual business phrasing',
      desc: '“Kindly” is disproportionately common in business-email compromise and advance-fee fraud.',
      severity: 'low', points: 5, category: 'social',
    },
    {
      id: 'text-wallet',
      re: /\b(0x[a-fA-F0-9]{40}|bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/,
      title: 'Cryptocurrency wallet address',
      desc: 'A wallet address is embedded in the message. Verify the recipient using an independent source before sending funds.',
      severity: 'high', points: 22, category: 'financial',
    },
  ];

  const AI_METADATA_MARKERS = [
    'midjourney', 'dall-e', 'dall·e', 'openai', 'stable diffusion', 'stablediffusion',
    'comfyui', 'automatic1111', 'a1111', 'novelai', 'adobe firefly', 'generative fill',
    'firefly', 'leonardo.ai', 'leonardo ai', 'runwayml', 'runway ml', 'sora',
    'imagen', 'flux.1', 'black forest labs', 'invokeai', 'fooocus', 'dreamstudio',
    'bing image creator', 'copilot image creator',
  ];

  const EDITOR_MARKERS = [
    'photoshop', 'lightroom', 'gimp', 'affinity photo', 'pixelmator', 'canva',
    'snapseed', 'facetune', 'picsart', 'afterlight', 'vsco',
  ];

  const SCRIPT_MARKERS = [
    '<script', 'javascript:', 'vbscript:', 'onerror=', 'onload=', 'onclick=',
    'powershell', 'cmd.exe', 'mshta', 'wscript', 'activexobject', 'eval(',
    'document.cookie', 'foreignobject', 'xlink:href="data:text/html',
  ];

  const EMBEDDED_SIGNATURES = [
    { name: 'Windows executable', bytes: [0x4d, 0x5a], label: 'MZ' },
    { name: 'ZIP archive', bytes: [0x50, 0x4b, 0x03, 0x04], label: 'PK' },
    { name: 'PDF document', bytes: [0x25, 0x50, 0x44, 0x46], label: '%PDF' },
    { name: 'RAR archive', bytes: [0x52, 0x61, 0x72, 0x21], label: 'Rar!' },
    { name: '7-Zip archive', bytes: [0x37, 0x7a, 0xbc, 0xaf], label: '7z' },
    { name: 'ELF executable', bytes: [0x7f, 0x45, 0x4c, 0x46], label: 'ELF' },
  ];

  function uid() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') {
      return window.crypto.randomUUID();
    }
    return 'scn_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function safeDecode(value) {
    try {
      return decodeURIComponent(value);
    } catch (_) {
      return value;
    }
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function levenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    if (Math.abs(a.length - b.length) > 2) return 3;

    let prev = new Array(b.length + 1);
    let curr = new Array(b.length + 1);
    for (let j = 0; j <= b.length; j += 1) prev[j] = j;

    for (let i = 1; i <= a.length; i += 1) {
      curr[0] = i;
      for (let j = 1; j <= b.length; j += 1) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
      }
      const swap = prev;
      prev = curr;
      curr = swap;
    }
    return prev[b.length];
  }

  function deLeet(value) {
    const cyrillic = {
      'а': 'a', 'в': 'b', 'е': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o',
      'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j',
      'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ⅼ': 'l', 'ο': 'o', 'α': 'a', 'ν': 'v',
    };
    return String(value)
      .toLowerCase()
      .replace(/[а-яіјѕԁɡⅼοαν]/g, (ch) => cyrillic[ch] || ch)
      .replace(/rn/g, 'm')
      .replace(/vv/g, 'w')
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/\$/g, 's')
      .replace(/@/g, 'a');
  }

  function getRegistrableDomain(hostname) {
    if (!hostname) return '';
    const host = hostname.toLowerCase().replace(/\.$/, '');
    if (isIp(host)) return host;
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.has(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return lastTwo;
  }

  function isIp(host) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');
  }

  function isPrivateIp(host) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
    const octets = host.split('.').map(Number);
    if (octets.some((n) => n > 255)) return false;
    if (octets[0] === 10 || octets[0] === 127 || octets[0] === 0) return true;
    if (octets[0] === 192 && octets[1] === 168) return true;
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
    if (octets[0] === 169 && octets[1] === 254) return true;
    return false;
  }

  function getTld(hostname) {
    const parts = String(hostname).toLowerCase().replace(/\.$/, '').split('.');
    return parts.length > 0 ? parts[parts.length - 1] : '';
  }

  function scoreToLevel(score) {
    return LEVELS.find((level) => score <= (level.key === 'low' ? 19 : level.key === 'moderate' ? 44 : level.key === 'high' ? 69 : 100)) || LEVELS[0];
  }

  function makeSignal(id, title, description, severity, points, category, evidence) {
    return { id, title, description, severity, points, category, evidence: evidence || '' };
  }

  function aggregate(signals) {
    const unique = [];
    const seen = new Set();
    signals.forEach((signal) => {
      if (!signal || seen.has(signal.id)) return;
      seen.add(signal.id);
      unique.push(signal);
    });

    const raw = unique.reduce((sum, signal) => sum + signal.points, 0);
    let score = raw === 0 ? 0 : Math.round(100 * (1 - Math.exp(-raw / 42)));
    if (unique.some((s) => s.severity === 'critical')) score = Math.max(score, 74);
    else if (unique.some((s) => s.severity === 'high')) score = Math.max(score, 54);
    else if (unique.some((s) => s.severity === 'medium')) score = Math.max(score, 28);
    else if (unique.some((s) => s.severity === 'low')) score = Math.max(score, 10);
    return {
      signals: unique.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || b.points - a.points),
      score: clamp(score, 0, 99),
      raw,
    };
  }

  function buildCategories(signals, defs) {
    return defs.map((def) => {
      const weight = signals
        .filter((signal) => signal.category === def.key)
        .reduce((sum, signal) => sum + signal.points, 0);
      const score = weight === 0 ? 0 : clamp(Math.round(100 * (1 - Math.exp(-weight / 22))), 0, 100);
      return { ...def, score };
    });
  }

  function confidenceFor(signals, positives, hasExternal) {
    const base = hasExternal ? 78 : 84;
    const value = base + Math.min(10, signals.length * 2) + Math.min(4, (positives || []).length);
    return clamp(Math.round(value), 62, 98);
  }

  function levelAdvice(level, type) {
    const noun = type === 'url' ? 'link' : type === 'image' ? 'file' : 'message';
    if (level === 'critical') {
      return `Do not open, click, download, or reply to this ${noun}. Isolate it and report it to your security team.`;
    }
    if (level === 'high') {
      return `Avoid interacting with this ${noun} until the source is independently verified through an official channel.`;
    }
    if (level === 'moderate') {
      return `Treat this ${noun} with caution. Verify the sender or destination using a channel you already trust.`;
    }
    return 'No immediate action required. Continue normal security hygiene.';
  }

  function buildRecommendations(type, level, signals, details) {
    const out = [levelAdvice(level, type)];
    const ids = new Set(signals.map((s) => s.id));

    if (type === 'url') {
      if (level !== 'low') out.push('Navigate to the organization’s website directly instead of using this link.');
      if (ids.has('url-brand') || ids.has('url-lookalike') || ids.has('url-punycode')) {
        out.push('Confirm the official domain in a separate browser tab before entering credentials.');
      }
      if (ids.has('url-executable') || ids.has('url-archive')) {
        out.push('Do not download or run the linked file. Scan it with endpoint protection first.');
      }
      if (ids.has('url-shortener') || ids.has('url-redirect')) {
        out.push('Expand the redirect chain with a link preview service before visiting the destination.');
      }
      if (ids.has('url-credentials')) {
        out.push('If credentials were entered, change the password and revoke active sessions immediately.');
      }
      if (ids.has('url-http')) out.push('Avoid submitting any data over an unencrypted HTTP connection.');
    }

    if (type === 'message') {
      if (ids.has('text-otp') || ids.has('text-seed-phrase')) {
        out.push('Never share one-time codes, recovery phrases, or private keys — even with someone claiming to be support.');
      }
      if (ids.has('text-gift-card') || ids.has('text-wire') || ids.has('text-wallet')) {
        out.push('Verify any payment request by calling the person or organization using a known-good number.');
      }
      if (ids.has('text-impersonation')) {
        out.push('Contact the named organization through its official app or website, not the contact details in this message.');
      }
      if (ids.has('text-attachment')) out.push('Do not open the referenced attachment; report it to your email administrator.');
      if (ids.has('text-link-risk') || ids.has('text-click-here')) {
        out.push('Hover or long-press the link to inspect the true destination before tapping it.');
      }
      if (ids.has('text-personal-data')) out.push('Do not provide identity documents, card numbers, or security codes.');
      if (level !== 'low') out.push('Report the message as phishing and block the sender.');
    }

    if (type === 'image') {
      if (ids.has('img-qr-risk')) out.push('Do not scan or open the QR destination outside an isolated link-analysis tool.');
      if (ids.has('img-ocr-risk')) out.push('The visible text contains phishing patterns. Do not act on instructions in the image.');
      if (ids.has('img-script') || ids.has('img-executable') || ids.has('img-trailing')) {
        out.push('Quarantine the file and run an endpoint malware scan before opening it again.');
      }
      if (ids.has('img-gps')) out.push('Remove EXIF/GPS metadata before sharing this photo publicly.');
      if (ids.has('img-ai') || ids.has('img-editor')) {
        out.push('Treat the image as potentially synthetic. Verify provenance with the original source.');
      }
      if (ids.has('img-mismatch')) out.push('The file extension does not match its real file signature. Rename it only after inspection.');
      out.push('Open images from unknown senders in a restricted or preview-only environment.');
    }

    if (level === 'low' && details && details.qr) out.push('The embedded QR code was decoded and its destination passed structural checks.');
    return Array.from(new Set(out)).slice(0, 6);
  }

  function buildSummary(type, level, signals, details) {
    const top = signals[0];
    const second = signals[1];
    const noun = type === 'url' ? 'link' : type === 'image' ? 'image' : 'message';
    if (!signals.length) {
      if (type === 'url') {
        return details && details.trusted
          ? 'The destination belongs to a recognized organization and no structural phishing indicators were detected.'
          : 'No meaningful phishing or malware indicators were detected. Sentinel could not verify live domain reputation, so apply normal caution to unsolicited links.';
      }
      if (type === 'image') {
        return 'No malicious metadata, embedded payloads, QR threats, or visible phishing language were detected.';
      }
      return 'No credential theft, payment fraud, coercion, or high-risk language patterns were detected in this message.';
    }
    if (level === 'critical') {
      return `Critical-risk ${noun} detected. ${top.title}${second ? ' and ' + second.title.toLowerCase() : ''} create a high-confidence path to compromise.`;
    }
    if (level === 'high') {
      return `This ${noun} exhibits several converging threat indicators, led by ${top.title.toLowerCase()}${second ? ' and ' + second.title.toLowerCase() : ''}.`;
    }
    if (level === 'moderate') {
      return `Some suspicious traits were found, including ${top.title.toLowerCase()}. They are not conclusive on their own, but warrant verification.`;
    }
    return `Only minor risk indicators were present (${top.title.toLowerCase()}). No active compromise path was identified.`;
  }

  function buildReport(type, displayTarget, signals, positives, details, options) {
    const aggregateResult = aggregate(signals);
    const level = scoreToLevel(aggregateResult.score);
    const categories = buildCategories(aggregateResult.signals, options.categories);
    const report = {
      id: uid(),
      type,
      target: displayTarget,
      displayTarget,
      score: aggregateResult.score,
      level,
      confidence: confidenceFor(aggregateResult.signals, positives, Boolean(options.hasExternal)),
      summary: buildSummary(type, level.key, aggregateResult.signals, details),
      signals: aggregateResult.signals,
      positives: positives || [],
      categories,
      recommendations: buildRecommendations(type, level.key, aggregateResult.signals, details),
      details: details || {},
      timestamp: Date.now(),
      engine: 'Sentinel Heuristic Engine',
      engineVersion: '2.5.0',
    };
    return report;
  }

  function normalizeInputUrl(input) {
    let value = String(input || '').trim();
    if (!value) return value;
    if (/[\s]/.test(value) && !/^data:/i.test(value)) {
      value = value.split(/\s+/)[0];
    }
    if (/^(javascript|data|vbscript|file|blob):/i.test(value)) return value;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = 'https://' + value;
    return value;
  }

  function analyzeUrl(input) {
    const original = String(input || '').trim();
    if (!original) throw new Error('Enter a link to analyze.');

    const normalized = normalizeInputUrl(original);
    const dangerousProtocol = normalized.match(/^(javascript|data|vbscript|file|blob):/i);
    if (dangerousProtocol) {
      const scheme = dangerousProtocol[1].toLowerCase();
      const signals = [makeSignal(
        'url-dangerous-protocol',
        `${scheme}: payload detected`,
        'This is executable or embedded content, not a normal web address. Opening it can execute code or render a credential-harvesting page.',
        'critical',
        60,
        'payload',
        normalized.slice(0, 100),
      )];
      return buildReport('url', normalized.slice(0, 120), signals, [], {
        scheme,
        normalized,
        raw: original,
        trusted: false,
      }, {
        categories: [
          { key: 'identity', label: 'Identity', max: 100 },
          { key: 'infrastructure', label: 'Infrastructure', max: 100 },
          { key: 'intent', label: 'Intent', max: 100 },
          { key: 'payload', label: 'Payload', max: 100 },
        ],
      });
    }

    let url;
    try {
      url = new URL(normalized);
    } catch (_) {
      throw new Error('That does not look like a valid URL. Example: https://example.com/login');
    }

    if (!/^https?:$/.test(url.protocol)) {
      throw new Error('Only HTTP, HTTPS, and embedded-payload schemes can be analyzed.');
    }
    if (!url.hostname) throw new Error('The URL is missing a hostname.');

    const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
    const registrable = getRegistrableDomain(hostname);
    const tld = getTld(hostname);
    const path = safeDecode(url.pathname || '');
    const query = safeDecode(url.search || '');
    const fullPath = path + query;
    const trusted = TRUSTED_DOMAINS.has(registrable) || Array.from(TRUSTED_DOMAINS).some((domain) => hostname === domain || hostname.endsWith('.' + domain));
    const signals = [];
    const positives = [];

    if (trusted) {
      const brand = BRANDS.find((b) => brandDomains(b).includes(registrable) || brandDomains(b).some((domain) => hostname === domain || hostname.endsWith('.' + domain)));
      positives.push(`Recognized organization domain — ${brand ? brand.name : registrable}`);
    }
    if (url.protocol === 'https:') positives.push('Encrypted HTTPS connection');
    if (!url.username && !url.password) positives.push('No embedded credentials in the URL');
    if (!/%[0-9a-f]{2}/i.test(url.href)) positives.push('No encoded payload characters detected');
    if (!SHORTENERS.has(registrable)) positives.push('Destination is not a known link shortener');

    // Protocol and transport.
    if (url.protocol === 'http:') {
      signals.push(makeSignal(
        'url-http', 'Unencrypted HTTP connection',
        'Data sent to this destination can be intercepted or modified in transit. Credential pages should always use HTTPS.',
        'low', 8, 'infrastructure', url.protocol,
      ));
    }

    // Credentials embedded in URL.
    if (url.username || url.password) {
      signals.push(makeSignal(
        'url-userinfo', 'Credentials embedded before the hostname',
        'Text before the @ symbol can disguise the real destination. Browsers may hide the true host from a casual reader.',
        'high', 28, 'identity', `${url.username || 'user'}:***@${hostname}`,
      ));
    }
    if (/@/.test(original.split('?')[0]) && !url.username) {
      signals.push(makeSignal(
        'url-at-obfuscation', 'At-sign obfuscation',
        'The link contains an @ character in the authority section, a common way to visually spoof a trusted domain.',
        'high', 24, 'identity', original.slice(0, 100),
      ));
    }

    // IP literal.
    if (isIp(hostname)) {
      const privateHost = isPrivateIp(hostname);
      signals.push(makeSignal(
        privateHost ? 'url-private-ip' : 'url-ip-literal',
        privateHost ? 'Private network address as destination' : 'Raw IP address used instead of a domain',
        privateHost
          ? 'The link targets a device on a local network. This can be used for router or internal-service attacks.'
          : 'Phishing and malware infrastructure frequently uses bare IP addresses to avoid domain reputation systems.',
        privateHost ? 'medium' : 'high',
        privateHost ? 15 : 24,
        'infrastructure', hostname,
      ));
    }

    // Internationalized / homograph domains.
    if (/^xn--/i.test(hostname) || hostname.includes('.xn--')) {
      signals.push(makeSignal(
        'url-punycode', 'Internationalized lookalike domain',
        'The hostname uses Punycode, which can render as a near-identical copy of a well-known brand using characters from another alphabet.',
        'critical', 36, 'identity', hostname,
      ));
    }
    if (/[^\x00-\x7F]/.test(original.split('/')[0] || '')) {
      signals.push(makeSignal(
        'url-unicode', 'Non-Latin characters in hostname',
        'Mixed-alphabet or Unicode hostnames are frequently used in homograph attacks to impersonate trusted brands.',
        'high', 26, 'identity', hostname,
      ));
    }

    // Registrable domain and brand analysis.
    const hostLabels = hostname.split('.');
    const domainLabel = registrable.split('.')[0] || '';
    const normalizedDomainLabel = deLeet(domainLabel);
    let impersonated = null;

    if (!trusted) {
      for (const brand of BRANDS) {
        if (brand.token.length < 3) continue;
        const distance = levenshtein(normalizedDomainLabel, brand.token);
        if (distance === 0 && normalizedDomainLabel !== domainLabel) {
          impersonated = brand;
          signals.push(makeSignal(
            'url-lookalike', `Lookalike domain impersonating ${brand.name}`,
            `The domain “${registrable}” resolves to the same characters as ${brand.domain} after common character substitutions. It is not the official domain.`,
            'critical', 38, 'identity', `${registrable} → ${brand.domain}`,
          ));
          break;
        }
        if (distance === 1 && domainLabel.length >= 4) {
          impersonated = brand;
          signals.push(makeSignal(
            'url-lookalike', `Typo-squatted domain targeting ${brand.name}`,
            `The domain “${registrable}” differs from ${brand.domain} by one character — a common phishing technique.`,
            'critical', 34, 'identity', `${registrable} ≈ ${brand.domain}`,
          ));
          break;
        }
      }
    }

    if (!trusted && !impersonated) {
      const matchedBrand = BRANDS.find((brand) => {
        return hostLabels.some((label) => {
          const normalized = deLeet(label);
          if (normalized === brand.token) return true;
          if (normalized.startsWith(brand.token + '-') || normalized.endsWith('-' + brand.token)) return true;
          if (brand.token.length < 4) return false;
          return normalized.includes(brand.token) || (brand.token.length >= 5 && brand.token.includes(normalized) && normalized.length >= 4);
        });
      });
      if (matchedBrand) {
        signals.push(makeSignal(
          'url-brand', `Trusted brand “${matchedBrand.name}” embedded in untrusted domain`,
          `The official domain is ${matchedBrand.domain}, but this link is hosted on ${registrable}. Brand names in subdomains or hyphenated hosts are a strong phishing indicator.`,
          'critical', 32, 'identity', `${hostname}`,
        ));
      }
    }

    // High-abuse TLDs.
    if (HIGH_ABUSE_TLDS.has(tld)) {
      signals.push(makeSignal(
        'url-tld-high', `High-abuse top-level domain (.${tld})`,
        'This TLD is disproportionately used for low-cost phishing, malware distribution, and disposable scam infrastructure.',
        'medium', 16, 'infrastructure', `.${tld}`,
      ));
    } else if (SUSPICIOUS_TLDS_MEDIUM.has(tld)) {
      signals.push(makeSignal(
        'url-tld-medium', `Frequently abused TLD (.${tld})`,
        'This top-level domain is commonly used for promotional scams and low-trust landing pages.',
        'low', 8, 'infrastructure', `.${tld}`,
      ));
    }

    if (SHORTENERS.has(registrable)) {
      signals.push(makeSignal(
        'url-shortener', 'Link shortener hides the destination',
        'The visible link does not reveal where it actually goes. Shorteners are routinely used to bypass URL filters and conceal phishing pages.',
        'medium', 22, 'infrastructure', registrable,
      ));
    }

    // Suspicious host composition.
    if (!isIp(hostname)) {
      const meaningfulLabels = hostLabels.filter((label) => label !== 'www');
      if (meaningfulLabels.length >= 5) {
        signals.push(makeSignal(
          'url-subdomain-depth', 'Excessive subdomain nesting',
          'Deeply nested subdomains can make the true registrable domain hard to see and are common in credential-harvesting URLs.',
          'medium', 12, 'infrastructure', `${meaningfulLabels.length} subdomain labels`,
        ));
      }
      const hyphens = (hostname.match(/-/g) || []).length;
      if (hyphens >= 3) {
        signals.push(makeSignal(
          'url-hyphen', 'Hyphen-heavy hostname',
          'Long chains of hyphenated keywords are a common pattern in throwaway phishing domains.',
          'low', 7, 'infrastructure', `${hyphens} hyphens`,
        ));
      }
      if (/([a-z0-9]{18,})/i.test(domainLabel) && !/[aeiou]{3,}/i.test(domainLabel)) {
        signals.push(makeSignal(
          'url-random-host', 'Algorithmically generated-looking domain',
          'The domain label is unusually long and lacks natural vowel patterns, which can indicate automated registration.',
          'medium', 12, 'infrastructure', domainLabel,
        ));
      }
    }

    // Non-standard ports.
    if (url.port && !['80', '443', '8080', '8443'].includes(url.port)) {
      signals.push(makeSignal(
        'url-port', `Unusual network port :${url.port}`,
        'A non-standard port can be used to bypass network monitoring or point to an ad-hoc malicious service.',
        'high', 18, 'infrastructure', `:${url.port}`,
      ));
    }

    // Path and query intent analysis.
    const lowerPath = fullPath.toLowerCase();
    const strongHits = STRONG_URL_KEYWORDS.filter((word) => lowerPath.includes(word));
    const generalHits = GENERAL_URL_KEYWORDS.filter((word) => lowerPath.includes(word));
    if (!trusted && strongHits.length) {
      signals.push(makeSignal(
        'url-credentials', 'Credential-theft path language',
        `The URL path contains phrases associated with account takeover (${strongHits.slice(0, 3).join(', ')}). This is typical of cloned login and verification pages.`,
        'high', 20, 'intent', strongHits.slice(0, 3).join(', '),
      ));
    } else if (!trusted && generalHits.length >= 2) {
      signals.push(makeSignal(
        'url-keywords', 'Multiple account or payment keywords',
        `The path combines several high-risk terms (${generalHits.slice(0, 4).join(', ')}), which is characteristic of phishing landing pages.`,
        'medium', 12, 'intent', generalHits.slice(0, 4).join(', '),
      ));
    }

    // Executable / archive downloads.
    const downloadMatch = path.match(/\.([a-z0-9]{2,5})(?:$|[?#])/i);
    const fileExt = (downloadMatch ? downloadMatch[1] : '').toLowerCase();
    if (DANGEROUS_EXTENSIONS.has(fileExt)) {
      signals.push(makeSignal(
        'url-executable', `Executable file download (.${fileExt})`,
        'The link directly references an executable file. Malware is commonly delivered as installers, scripts, or disk images from unfamiliar domains.',
        trusted ? 'high' : 'critical', trusted ? 24 : 38, 'payload', `.${fileExt}`,
      ));
    } else if (ARCHIVE_EXTENSIONS.has(fileExt)) {
      signals.push(makeSignal(
        'url-archive', `Archive file download (.${fileExt})`,
        'Archives are often used to package malware or password-protected payloads that evade security scanners.',
        'high', 20, 'payload', `.${fileExt}`,
      ));
    }
    if (/\.(jpg|jpeg|png|gif|webp|svg)\.(exe|scr|js|bat|cmd|msi)$/i.test(path)) {
      signals.push(makeSignal(
        'url-double-extension', 'Deceptive double file extension',
        'A file is disguised as an image but carries an executable extension at the end.',
        'critical', 34, 'payload', path.slice(-32),
      ));
    }

    // Encoded or redirect-style payloads.
    const percentCount = (url.search.match(/%[0-9a-f]{2}/gi) || []).length + (url.pathname.match(/%[0-9a-f]{2}/gi) || []).length;
    if (percentCount >= 10 || /%25[0-9a-f]{2}/i.test(url.href)) {
      signals.push(makeSignal(
        'url-encoded', 'Heavily encoded URL payload',
        'Large amounts of percent-encoding and double encoding can obscure malicious parameters and evade simplistic filters.',
        'medium', 12, 'payload', `${percentCount} encoded octets`,
      ));
    }

    const redirectKeys = ['url', 'next', 'redirect', 'return', 'returnurl', 'continue', 'target', 'dest', 'destination', 'go', 'out', 'view', 'r', 'u'];
    try {
      for (const [key, value] of url.searchParams.entries()) {
        if (!redirectKeys.includes(key.toLowerCase())) continue;
        const decodedValue = safeDecode(value);
        const embedded = decodedValue.match(/https?:\/\/[^&\s]+/i);
        if (embedded) {
          let embeddedHost = '';
          try { embeddedHost = new URL(embedded[0]).hostname; } catch (_) { /* ignore */ }
          if (embeddedHost && embeddedHost !== hostname && !embeddedHost.endsWith('.' + registrable)) {
            signals.push(makeSignal(
              'url-redirect', 'Open redirect or cloaked destination',
              `The “${key}” parameter redirects to a different domain (${embeddedHost}). This is commonly used to disguise the final phishing page.`,
              'high', 18, 'payload', `${key}=${embeddedHost}`,
            ));
            break;
          }
        }
      }
    } catch (_) { /* malformed query parameters are handled below */ }

    // Long URL and opaque tokens.
    if (url.href.length > 300) {
      signals.push(makeSignal(
        'url-long', 'Extremely long URL',
        'Excessive length can hide the true destination from address bars, emails, and security tooling.',
        'medium', 14, 'payload', `${url.href.length} characters`,
      ));
    } else if (url.href.length > 160) {
      signals.push(makeSignal(
        'url-long', 'Unusually long URL',
        'Long URLs are often used to bury tracking, redirect, or credential-harvesting parameters.',
        'low', 7, 'payload', `${url.href.length} characters`,
      ));
    }
    if (/[a-z0-9_-]{40,}/i.test(path) && !trusted) {
      signals.push(makeSignal(
        'url-token', 'Long opaque path token',
        'A long random-looking token can indicate a per-victim tracking link used to personalize a phishing campaign.',
        'low', 7, 'intent', path.slice(0, 52) + '…',
      ));
    }

    // Free hosting / tunnel services.
    const freeHostPattern = /(000webhostapp\.com|weeblysite\.com|web\.app|pages\.dev|glitch\.me|replit\.app|ngrok\.(io|app)|trycloudflare\.com|serveo\.net|localtunnel\.me|github\.io)$/i;
    if (freeHostPattern.test(registrable) && !trusted) {
      signals.push(makeSignal(
        'url-free-host', 'Low-cost or tunneled hosting provider',
        'The destination is hosted on a free page builder or tunnel service frequently abused for short-lived phishing campaigns.',
        'medium', 13, 'infrastructure', registrable,
      ));
    }

    // Link-to-link combos.
    if (!trusted && strongHits.length && (SHORTENERS.has(registrable) || HIGH_ABUSE_TLDS.has(tld))) {
      signals.push(makeSignal(
        'url-combo', 'Coordinated phishing infrastructure',
        'Credential-theft keywords coincide with disposable hosting or URL obfuscation. The combination sharply increases confidence that this is a phishing link.',
        'critical', 22, 'intent', 'credential path + untrusted infrastructure',
      ));
    }

    const displayTarget = original.length > 140 ? original.slice(0, 137) + '…' : original;
    return buildReport('url', displayTarget, signals, positives, {
      raw: original,
      normalized,
      scheme: url.protocol.replace(':', ''),
      hostname,
      registrable,
      tld,
      path,
      query,
      port: url.port,
      trusted,
      redirectedTo: (() => {
        try {
          const entries = Array.from(url.searchParams.entries());
          const found = entries.find(([key, value]) => redirectKeys.includes(key.toLowerCase()) && /^https?:\/\//i.test(safeDecode(value)));
          return found ? safeDecode(found[1]) : null;
        } catch (_) { return null; }
      })(),
    }, {
      hasExternal: false,
      categories: [
        { key: 'identity', label: 'Identity spoofing' },
        { key: 'infrastructure', label: 'Infrastructure' },
        { key: 'intent', label: 'Malicious intent' },
        { key: 'payload', label: 'Payload risk' },
      ],
    });
  }

  function extractUrls(text) {
    const matches = String(text).match(/(?:https?:\/\/|www\.)[^\s<>"'`]+/gi) || [];
    return Array.from(new Set(matches.map((value) => value.replace(/[),.;!?]+$/g, ''))));
  }

  function analyzeMessage(input) {
    const text = String(input || '').trim();
    if (!text) throw new Error('Paste a message or email to analyze.');
    if (text.length > 50000) throw new Error('Message is too long. Limit the analysis to 50,000 characters.');

    const signals = [];
    const positives = [];
    const lower = text.toLowerCase();
    const links = extractUrls(text);

    PHISHING_TEXT_RULES.forEach((rule) => {
      const match = text.match(rule.re);
      if (!match) return;
      if (rule.guard) {
        const matchIndex = text.search(rule.re);
        const before = matchIndex > 0 ? text.slice(Math.max(0, matchIndex - 80), matchIndex) : '';
        if (rule.guard.test(before)) return;
      }
      signals.push(makeSignal(
        rule.id,
        rule.title,
        rule.desc,
        rule.severity,
        rule.points,
        rule.category,
        match[0].slice(0, 100),
      ));
    });

    // Several OTP rules can describe the same request. Keep only the strongest
    // one so the same evidence is never counted twice.
    const OTP_RULE_IDS = ['text-otp', 'text-otp-relay', 'text-otp-provenance', 'text-otp-question'];
    const otpHits = signals.filter((signal) => OTP_RULE_IDS.includes(signal.id));
    if (otpHits.length > 1) {
      const strongest = otpHits.reduce((best, signal) => (signal.points > best.points ? signal : best), otpHits[0]);
      for (let i = signals.length - 1; i >= 0; i--) {
        if (OTP_RULE_IDS.includes(signals[i].id) && signals[i] !== strongest) signals.splice(i, 1);
      }
    }

    // Compound language patterns.
    const hasUrgency = signals.some((s) => s.id === 'text-urgency');
    const hasThreat = signals.some((s) => s.id === 'text-threat');
    const hasCredential = signals.some((s) => s.category === 'credential');
    const hasFinancial = signals.some((s) => s.category === 'financial');
    const hasImpersonation = signals.some((s) => s.id === 'text-impersonation');

    if (hasUrgency && hasThreat) {
      signals.push(makeSignal(
        'text-fear-combo', 'Fear + urgency persuasion chain',
        'The sender combines an imminent deadline with loss of access or legal consequences — a high-confidence social-engineering pattern.',
        'high', 18, 'social', 'urgency + threat',
      ));
    }
    if (hasUrgency && hasFinancial) {
      signals.push(makeSignal(
        'text-payment-pressure', 'Time-pressured payment request',
        'Financial action is being demanded under artificial time pressure, reducing the opportunity for verification.',
        'high', 20, 'financial', 'urgency + payment',
      ));
    }
    if (hasThreat && hasCredential) {
      signals.push(makeSignal(
        'text-account-takeover', 'Account-takeover narrative',
        'The message claims the account is at risk and simultaneously prompts authentication — the classic structure of a credential-phishing email.',
        'high', 20, 'credential', 'threat + credential request',
      ));
    }
    if (hasImpersonation && (hasCredential || hasFinancial)) {
      signals.push(makeSignal(
        'text-brand-combo', 'Brand impersonation with a request',
        'A trusted brand is invoked alongside a sensitive request. Legitimate organizations rarely ask for credentials or payment through an unsolicited message.',
        'high', 17, 'social', 'brand + sensitive request',
      ));
    }

    // Stylistic anomalies.
    const letters = text.replace(/[^a-z]/gi, '');
    const uppercase = text.replace(/[^A-Z]/g, '');
    if (letters.length > 60 && uppercase.length / letters.length > 0.62) {
      signals.push(makeSignal(
        'text-caps', 'Aggressive all-caps formatting',
        'Heavy capitalization is used to amplify urgency and emotional pressure.',
        'low', 6, 'social', `${Math.round((uppercase.length / letters.length) * 100)}% uppercase`,
      ));
    }
    if ((text.match(/!/g) || []).length >= 5) {
      signals.push(makeSignal(
        'text-punctuation', 'Excessive exclamation marks',
        'Repeated exclamation marks are typical of bulk scam messaging and pressure tactics.',
        'low', 4, 'social', `${(text.match(/!/g) || []).length} exclamation marks`,
      ));
    }
    if (/\b(?:[a-z]+[\u0400-\u04FF]|[\u0400-\u04FF]+[a-z]+)\b/i.test(text)) {
      signals.push(makeSignal(
        'text-mixed-script', 'Mixed-alphabet obfuscation',
        'Latin and Cyrillic characters are mixed within the same word, which can evade keyword filters and impersonate familiar text.',
        'medium', 12, 'social', 'mixed script detected',
      ));
    }

    // Analyze embedded links and merge their structural threat.
    const linkFindings = [];
    links.slice(0, 5).forEach((link) => {
      try {
        const report = analyzeUrl(link);
        linkFindings.push({ url: link, score: report.score, level: report.level.key, report });
      } catch (_) { /* ignore malformed links */ }
    });
    const riskiest = linkFindings.slice().sort((a, b) => b.score - a.score)[0];
    if (riskiest) {
      if (riskiest.score >= 70) {
        signals.push(makeSignal(
          'text-link-risk', 'Critical-risk embedded link',
          `The message contains a link that scores ${riskiest.score}/100 for phishing or malware indicators: ${riskiest.url}`,
          'critical', 32, 'link', riskiest.url.slice(0, 120),
        ));
      } else if (riskiest.score >= 45) {
        signals.push(makeSignal(
          'text-link-risk', 'High-risk embedded link',
          `The message contains a structurally dangerous link scoring ${riskiest.score}/100: ${riskiest.url}`,
          'high', 22, 'link', riskiest.url.slice(0, 120),
        ));
      } else if (riskiest.score >= 20) {
        signals.push(makeSignal(
          'text-link-risk', 'Suspicious embedded link',
          `An embedded link shows suspicious characteristics and scores ${riskiest.score}/100: ${riskiest.url}`,
          'medium', 12, 'link', riskiest.url.slice(0, 120),
        ));
      } else {
        positives.push('Embedded links show no strong structural threat indicators');
      }
    } else if (lower.includes('http')) {
      positives.push('No parseable embedded links detected');
    }

    if (!links.length) positives.push('No embedded links detected');
    if (!signals.some((s) => s.category === 'credential')) positives.push('No credential-harvesting language detected');
    if (!signals.some((s) => s.category === 'financial')) positives.push('No payment or financial data request detected');
    if (text.length > 30) positives.push('Natural-language intent analysis completed');

    const displayTarget = text.length > 140 ? text.slice(0, 137).replace(/\s+/g, ' ') + '…' : text.replace(/\s+/g, ' ');
    return buildReport('message', displayTarget, signals, positives, {
      rawLength: text.length,
      linkCount: links.length,
      links: linkFindings.map((link) => ({ url: link.url, score: link.score, level: link.level })),
      preview: text.slice(0, 500),
    }, {
      hasExternal: false,
      categories: [
        { key: 'social', label: 'Social engineering' },
        { key: 'credential', label: 'Credential risk' },
        { key: 'financial', label: 'Financial risk' },
        { key: 'link', label: 'Link risk' },
        { key: 'payload', label: 'Attachment risk' },
      ],
    });
  }

  function readBytes(buffer, offset, length, littleEndian) {
    let value = 0;
    if (littleEndian) {
      for (let i = length - 1; i >= 0; i -= 1) value = value * 256 + buffer[offset + i];
    } else {
      for (let i = 0; i < length; i += 1) value = value * 256 + buffer[offset + i];
    }
    return value;
  }

  function readAscii(buffer, offset, length) {
    let out = '';
    const end = Math.min(buffer.length, offset + length);
    for (let i = offset; i < end; i += 1) out += String.fromCharCode(buffer[i]);
    return out.replace(/\0+$/, '');
  }

  function readUtf8(buffer, offset, length) {
    try {
      return new TextDecoder('utf-8').decode(buffer.slice(offset, Math.min(buffer.length, offset + length))).replace(/\0+$/, '');
    } catch (_) {
      return readAscii(buffer, offset, length);
    }
  }

  function readExifValue(buffer, tiffStart, entryOffset, littleEndian) {
    const type = readBytes(buffer, entryOffset + 2, 2, littleEndian);
    const count = readBytes(buffer, entryOffset + 4, 4, littleEndian);
    const typeSizes = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 2, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 };
    const size = typeSizes[type] || 0;
    if (!size) return null;
    const byteLength = size * count;
    const valueOffset = byteLength <= 4 ? entryOffset + 8 : tiffStart + readBytes(buffer, entryOffset + 8, 4, littleEndian);
    if (valueOffset < 0 || valueOffset + Math.min(byteLength, 65536) > buffer.length) return null;

    if (type === 2 || type === 7) {
      const raw = buffer.slice(valueOffset, valueOffset + Math.min(byteLength, 4096));
      if (type === 7) {
        const prefix = readAscii(buffer, valueOffset, Math.min(8, byteLength));
        if (/^(ASCII|UNICODE|JIS)\0/i.test(prefix)) {
          return readUtf8(buffer, valueOffset + 8, Math.min(byteLength - 8, 4096));
        }
      }
      return readUtf8(raw, 0, raw.length).replace(/\0+$/, '').trim();
    }
    if (type === 3) return readBytes(buffer, valueOffset, 2, littleEndian);
    if (type === 4) return readBytes(buffer, valueOffset, 4, littleEndian);
    if (type === 5) return readBytes(buffer, valueOffset, 4, littleEndian) / (readBytes(buffer, valueOffset + 4, 4, littleEndian) || 1);
    if (type === 9) return readBytes(buffer, valueOffset, 4, littleEndian);
    if (type === 10) {
      const num = readBytes(buffer, valueOffset, 4, littleEndian);
      const den = readBytes(buffer, valueOffset + 4, 4, littleEndian);
      return num / (den || 1);
    }
    return null;
  }

  function parseExif(buffer, start) {
    if (readAscii(buffer, start, 6) !== 'Exif\0\0') return null;
    const tiffStart = start + 6;
    if (tiffStart + 8 > buffer.length) return null;
    const endianMark = readAscii(buffer, tiffStart, 2);
    if (endianMark !== 'II' && endianMark !== 'MM') return null;
    const littleEndian = endianMark === 'II';
    if (readBytes(buffer, tiffStart + 2, 2, littleEndian) !== 42) return null;
    const ifd0 = tiffStart + readBytes(buffer, tiffStart + 4, 4, littleEndian);
    if (ifd0 + 2 > buffer.length) return null;

    const tags = {
      0x010e: 'ImageDescription',
      0x010f: 'Make',
      0x0110: 'Model',
      0x0131: 'Software',
      0x0132: 'DateTime',
      0x013b: 'Artist',
      0x8298: 'Copyright',
      0x9003: 'DateTimeOriginal',
      0x9286: 'UserComment',
    };
    const metadata = { GPS: null };
    const gps = {};

    function readIfd(offset, handlers) {
      if (offset <= 0 || offset + 2 > buffer.length) return;
      const count = readBytes(buffer, offset, 2, littleEndian);
      if (count > 300) return;
      for (let i = 0; i < count; i += 1) {
        const entry = offset + 2 + i * 12;
        if (entry + 12 > buffer.length) break;
        const tag = readBytes(buffer, entry, 2, littleEndian);
        const handler = handlers[tag];
        if (handler) {
          try {
            const value = readExifValue(buffer, tiffStart, entry, littleEndian);
            if (value !== null && value !== '') handler(value);
          } catch (_) { /* skip malformed entry */ }
        }
      }
    }

    const subIfd = {};
    readIfd(ifd0, {
      ...Object.fromEntries(Object.entries(tags).map(([tag, name]) => [Number(tag), (value) => { metadata[name] = String(value).slice(0, 4000); }])),
      0x8769: (value) => { subIfd.exif = tiffStart + value; },
      0x8825: (value) => { subIfd.gps = tiffStart + value; },
    });

    if (subIfd.exif) {
      readIfd(subIfd.exif, {
        0x9003: (value) => { metadata.DateTimeOriginal = String(value).slice(0, 200); },
        0x9286: (value) => { metadata.UserComment = String(value).slice(0, 8000); },
        0xa002: (value) => { metadata.PixelXDimension = value; },
        0xa003: (value) => { metadata.PixelYDimension = value; },
      });
    }

    if (subIfd.gps) {
      readIfd(subIfd.gps, {
        1: (value) => { gps.latRef = String(value); },
        2: (value) => { gps.lat = value; },
        3: (value) => { gps.lonRef = String(value); },
        4: (value) => { gps.lon = value; },
      });
      if (gps.lat !== undefined && gps.lon !== undefined) {
        metadata.GPS = { latitude: gps.lat, longitude: gps.lon, latRef: gps.latRef, lonRef: gps.lonRef };
      }
    }

    return metadata;
  }

  function parseJpegMetadata(buffer) {
    const metadata = {};
    let offset = 2;
    while (offset + 4 < buffer.length) {
      if (buffer[offset] !== 0xff) { offset += 1; continue; }
      const marker = buffer[offset + 1];
      if (marker === 0xda || marker === 0xd9) break;
      if (marker >= 0xd0 && marker <= 0xd7) { offset += 2; continue; }
      if (offset + 4 > buffer.length) break;
      const length = (buffer[offset + 2] << 8) | buffer[offset + 3];
      if (length < 2 || offset + 2 + length > buffer.length) break;
      if (marker === 0xe1 && readAscii(buffer, offset + 4, 6) === 'Exif\0\0') {
        try {
          const exif = parseExif(buffer, offset + 4);
          if (exif) Object.assign(metadata, exif);
        } catch (_) { /* ignore malformed EXIF */ }
      }
      if (marker === 0xe1) {
        const xmp = readAscii(buffer, offset + 4, Math.min(length - 2, 2048));
        const xmpMatch = xmp.match(/<x:xmpmeta[\s\S]*<\/x:xmpmeta>/i);
        if (xmpMatch) metadata.XMP = xmpMatch[0].slice(0, 4000);
      }
      offset += 2 + length;
    }
    return metadata;
  }

  function parsePngMetadata(buffer) {
    const metadata = {};
    const chunks = [];
    let offset = 8;
    let iend = -1;
    while (offset + 12 <= buffer.length) {
      const length = readBytes(buffer, offset, 4, false);
      if (length < 0 || offset + 12 + length > buffer.length) break;
      const type = readAscii(buffer, offset + 4, 4);
      const dataStart = offset + 8;
      if (type === 'IHDR' && length >= 8) {
        metadata.PixelXDimension = readBytes(buffer, dataStart, 4, false);
        metadata.PixelYDimension = readBytes(buffer, dataStart + 4, 4, false);
      }
      if (type === 'tEXt') {
        const raw = buffer.slice(dataStart, dataStart + Math.min(length, 4000));
        const split = raw.indexOf(0);
        if (split > 0) {
          const key = readAscii(raw, 0, split);
          metadata[key] = readUtf8(raw, split + 1, raw.length - split - 1);
        }
      }
      if (type === 'iTXt') {
        const raw = buffer.slice(dataStart, dataStart + Math.min(length, 8000));
        const keywordEnd = raw.indexOf(0);
        if (keywordEnd > 0) {
          const key = readAscii(raw, 0, keywordEnd);
          const compressionFlag = raw[keywordEnd + 1];
          let textStart = keywordEnd + 3;
          const langEnd = raw.indexOf(0, textStart);
          if (langEnd > -1) textStart = langEnd + 1;
          const transEnd = raw.indexOf(0, textStart);
          if (transEnd > -1) textStart = transEnd + 1;
          if (compressionFlag === 0) {
            metadata[key] = readUtf8(raw, textStart, raw.length - textStart);
          } else {
            metadata[key] = '[compressed text metadata]';
          }
        }
      }
      if (type === 'eXIf' && length >= 4) {
        try {
          const exif = parseExif(buffer, dataStart);
          if (exif) Object.assign(metadata, exif);
        } catch (_) { /* ignore */ }
      }
      chunks.push({ type, length });
      if (type === 'IEND') { iend = offset + 12; break; }
      offset += 12 + length;
    }
    metadata._chunks = chunks;
    metadata._endOffset = iend > -1 ? iend : offset;
    return metadata;
  }

  function parseWebpMetadata(buffer) {
    const metadata = {};
    const text = readAscii(buffer, 0, Math.min(buffer.length, 4096));
    if (!text.startsWith('RIFF') || text.slice(8, 12) !== 'WEBP') return metadata;
    // WebP metadata is chunk-based; look for EXIF/XMP in printable strings as a fallback.
    const full = readAscii(buffer, 0, Math.min(buffer.length, 512 * 1024));
    const xmp = full.match(/<x:xmpmeta[\s\S]*<\/x:xmpmeta>/i);
    if (xmp) metadata.XMP = xmp[0].slice(0, 4000);
    return metadata;
  }

  function detectFileType(buffer) {
    if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
      return { type: 'jpeg', mime: 'image/jpeg', ext: 'jpg', label: 'JPEG image' };
    }
    if (buffer.length >= 8 && readAscii(buffer, 0, 8) === '\x89PNG\r\n\x1a\n') {
      return { type: 'png', mime: 'image/png', ext: 'png', label: 'PNG image' };
    }
    if (buffer.length >= 6 && /^GIF8[79]a$/.test(readAscii(buffer, 0, 6))) {
      return { type: 'gif', mime: 'image/gif', ext: 'gif', label: 'GIF image' };
    }
    if (buffer.length >= 12 && readAscii(buffer, 0, 4) === 'RIFF' && readAscii(buffer, 8, 4) === 'WEBP') {
      return { type: 'webp', mime: 'image/webp', ext: 'webp', label: 'WebP image' };
    }
    if (buffer.length >= 12 && readAscii(buffer, 4, 4) === 'ftyp') {
      const brand = readAscii(buffer, 8, 4).toLowerCase();
      if (['heic', 'heix', 'hevc', 'hevx', 'mif1', 'msf1'].includes(brand)) {
        return { type: 'heic', mime: 'image/heic', ext: 'heic', label: 'HEIC image' };
      }
      if (['avif', 'avis'].includes(brand)) {
        return { type: 'avif', mime: 'image/avif', ext: 'avif', label: 'AVIF image' };
      }
    }
    if (buffer.length >= 2 && buffer[0] === 0x42 && buffer[1] === 0x4d) {
      return { type: 'bmp', mime: 'image/bmp', ext: 'bmp', label: 'BMP image' };
    }
    if (buffer.length >= 4 && ((buffer[0] === 0x49 && buffer[1] === 0x49) || (buffer[0] === 0x4d && buffer[1] === 0x4d)) && buffer[2] === 0x2a) {
      return { type: 'tiff', mime: 'image/tiff', ext: 'tif', label: 'TIFF image' };
    }
    const head = readAscii(buffer, 0, Math.min(buffer.length, 512)).trim().toLowerCase();
    if (head.startsWith('<svg') || (head.startsWith('<?xml') && head.includes('<svg'))) {
      return { type: 'svg', mime: 'image/svg+xml', ext: 'svg', label: 'SVG vector image' };
    }
    return null;
  }

  function extractPrintableStrings(buffer, maxBytes) {
    const view = buffer.slice(0, Math.min(buffer.length, maxBytes || 8 * 1024 * 1024));
    let ascii = '';
    try {
      ascii = new TextDecoder('latin1').decode(view);
    } catch (_) {
      return '';
    }
    const matches = ascii.match(/[ -~]{6,}/g) || [];
    return matches.slice(0, 4000).join('\n');
  }

  function findEmbeddedSignatures(buffer, startOffset) {
    const found = [];
    const start = Math.max(0, startOffset || 0);
    for (let i = start; i < Math.min(buffer.length - 4, start + 2 * 1024 * 1024); i += 1) {
      for (const sig of EMBEDDED_SIGNATURES) {
        let match = true;
        for (let j = 0; j < sig.bytes.length; j += 1) {
          if (buffer[i + j] !== sig.bytes[j]) { match = false; break; }
        }
        if (match) found.push({ name: sig.name, label: sig.label, offset: i });
      }
    }
    return found;
  }

  function getMetadataValues(metadata) {
    const values = [];
    Object.entries(metadata || {}).forEach(([key, value]) => {
      if (key.startsWith('_')) return;
      if (value === null || value === undefined) return;
      if (typeof value === 'object') {
        values.push({ key, value: JSON.stringify(value) });
      } else {
        values.push({ key, value: String(value) });
      }
    });
    return values;
  }

  async function decodeQr(file) {
    if (typeof window.jsQR !== 'function') return { supported: false };
    const objectUrl = URL.createObjectURL(file);
    try {
      const img = await new Promise((resolve, reject) => {
        const image = new Image();
        image.onload = () => resolve(image);
        image.onerror = () => reject(new Error('Could not render image for QR analysis.'));
        image.src = objectUrl;
      });
      const maxDim = 1800;
      const scale = Math.min(1, maxDim / Math.max(img.naturalWidth || 1, img.naturalHeight || 1));
      const width = Math.max(1, Math.round((img.naturalWidth || 1) * scale));
      const height = Math.max(1, Math.round((img.naturalHeight || 1) * scale));
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(img, 0, 0, width, height);
      const imageData = ctx.getImageData(0, 0, width, height);
      const result = window.jsQR(imageData.data, width, height, { inversionAttempts: 'attemptBoth' });
      return {
        supported: true,
        found: Boolean(result),
        data: result ? result.data : null,
        width,
        height,
      };
    } catch (_) {
      return { supported: true, found: false, error: true };
    } finally {
      URL.revokeObjectURL(objectUrl);
    }
  }

  let ocrWorker = null;
  let ocrLoading = null;

  async function getOcrWorker(onProgress) {
    if (ocrWorker) return ocrWorker;
    if (!window.Tesseract || typeof window.Tesseract.createWorker !== 'function') return null;
    if (ocrLoading) return ocrLoading;
    const viteBase = new URL('./', window.location.href).href;
    ocrLoading = window.Tesseract.createWorker('eng', 1, {
      workerPath: new URL('assets/vendor/tesseract/worker.min.js', viteBase).href,
      corePath: new URL('assets/vendor/tesseract/', viteBase).href,
      langPath: new URL('assets/ocr', viteBase).href,
      gzip: true,
      logger: (message) => {
        if (onProgress && message && typeof message.progress === 'number') {
          onProgress(message.progress, message.status || 'OCR');
        }
      },
    }).then((worker) => {
      ocrWorker = worker;
      return worker;
    }).catch(() => null).finally(() => {
      ocrLoading = null;
    });
    return ocrLoading;
  }

  async function runOcr(file, onProgress) {
    try {
      if (file.size > 18 * 1024 * 1024) return { supported: true, skipped: true, reason: 'File too large for on-device OCR' };
      const worker = await getOcrWorker(onProgress);
      if (!worker) return { supported: false };
      if (onProgress) onProgress(0.08, 'OCR engine ready');
      const result = await worker.recognize(file);
      const data = result && result.data ? result.data : {};
      return {
        supported: true,
        text: String(data.text || '').replace(/\s+/g, ' ').trim(),
        confidence: typeof data.confidence === 'number' ? Math.round(data.confidence) : null,
      };
    } catch (_) {
      return { supported: true, failed: true };
    }
  }

  function analyzeVisibleText(text, source) {
    if (!text || text.length < 8) return null;
    try {
      const report = analyzeMessage(text);
      if (report.score >= 18) {
        return { report, source };
      }
    } catch (_) { /* ignore */ }
    return null;
  }

  async function analyzeImage(file, options) {
    options = options || {};
    if (!file) throw new Error('Choose an image to analyze.');
    if (file.size === 0) throw new Error('That file is empty.');
    if (file.size > 40 * 1024 * 1024) throw new Error('Image is larger than 40 MB. Use a smaller file.');

    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const fileType = detectFileType(bytes);
    const signals = [];
    const positives = [];
    const metadata = {};
    let imageEnd = bytes.length;
    const extension = (file.name.split('.').pop() || '').toLowerCase();
    const reportedMime = file.type || '';

    if (!fileType) {
      throw new Error('Unsupported file. Sentinel analyzes JPEG, PNG, WebP, GIF, HEIC/AVIF, TIFF, BMP, and SVG images.');
    }

    // File signature and extension consistency.
    const extensionMatches = fileType.type !== 'jpeg' || ['jpg', 'jpeg', 'jpe', 'jfif'].includes(extension);
    const expectedExtensions = {
      jpeg: ['jpg', 'jpeg', 'jpe', 'jfif'], png: ['png'], gif: ['gif'], webp: ['webp'],
      heic: ['heic', 'heif'], avif: ['avif'], bmp: ['bmp'], tiff: ['tif', 'tiff'], svg: ['svg'],
    };
    if (extension && !expectedExtensions[fileType.type].includes(extension)) {
      signals.push(makeSignal(
        'img-mismatch', 'File extension does not match content',
        `The file is named .${extension} but its binary signature identifies it as ${fileType.label}. Mismatched extensions are used to smuggle payloads past users and filters.`,
        'high', 26, 'payload', `.${extension} → ${fileType.type}`,
      ));
    }
    if (reportedMime && fileType.mime && reportedMime !== fileType.mime && !(fileType.type === 'jpeg' && reportedMime === 'image/jpg')) {
      if (!(fileType.type === 'heic' && reportedMime === 'image/heif')) {
        signals.push(makeSignal(
          'img-mime-mismatch', 'Declared MIME type is inconsistent',
          `The browser reported ${reportedMime}, but the file bytes are ${fileType.mime}. This can indicate deliberate type confusion.`,
          'medium', 12, 'payload', `${reportedMime} → ${fileType.mime}`,
        ));
      }
    }
    if (fileType.label) positives.push(`Valid ${fileType.label} signature`);
    if (fileType.type !== 'jpeg' || extensionMatches) positives.push('Filename and file signature are consistent');

    // Parse metadata by format.
    try {
      if (fileType.type === 'jpeg') {
        Object.assign(metadata, parseJpegMetadata(bytes));
        for (let i = 0; i < bytes.length - 1; i += 1) {
          if (bytes[i] === 0xff && bytes[i + 1] === 0xd9) { imageEnd = i + 2; break; }
        }
      } else if (fileType.type === 'png') {
        Object.assign(metadata, parsePngMetadata(bytes));
        imageEnd = metadata._endOffset || bytes.length;
      } else if (fileType.type === 'webp') {
        Object.assign(metadata, parseWebpMetadata(bytes));
      }
    } catch (_) { /* metadata failure is non-fatal */ }

    const metadataValues = getMetadataValues(metadata);
    const metadataText = metadataValues.map((entry) => `${entry.key}: ${entry.value}`).join('\n');
    const allStrings = extractPrintableStrings(bytes, 10 * 1024 * 1024) + '\n' + metadataText;
    const lowerStrings = allStrings.toLowerCase();
    const scriptsFound = SCRIPT_MARKERS.filter((marker) => lowerStrings.includes(marker));
    if (scriptsFound.length) {
      signals.push(makeSignal(
        'img-script', 'Executable script content embedded in image',
        `The file contains active script markers (${scriptsFound.slice(0, 3).join(', ')}). This is characteristic of a malicious SVG or a polyglot image designed to execute code.`,
        'critical', 42, 'payload', scriptsFound.slice(0, 3).join(', '),
      ));
    }

    // SVG-specific active-content checks.
    if (fileType.type === 'svg') {
      const svgText = readAscii(bytes, 0, Math.min(bytes.length, 2 * 1024 * 1024));
      if (/<script|onload\s*=|onclick\s*=|javascript:/i.test(svgText)) {
        signals.push(makeSignal(
          'img-svg-active', 'Active content in SVG',
          'SVG files can contain JavaScript and event handlers. This image is not safe to open as a passive picture.',
          'critical', 40, 'payload', 'script/event handler',
        ));
      }
      if (/<foreignObject|xlink:href\s*=\s*["']https?:/i.test(svgText)) {
        signals.push(makeSignal(
          'img-svg-external', 'External resource embedded in SVG',
          'The SVG loads foreign content or remote resources, which can be used for tracking or secondary payload delivery.',
          'high', 20, 'payload', 'foreignObject / remote href',
        ));
      }
    }

    // Detect embedded URLs in metadata and printable content.
    const urlMatches = Array.from(new Set((allStrings.match(/https?:\/\/[^\s"'<>\]\)]+/gi) || []).map((u) => u.replace(/[.,;]+$/, '')))).slice(0, 8);
    const linkFindings = [];
    urlMatches.forEach((link) => {
      try {
        const report = analyzeUrl(link);
        linkFindings.push({ url: link, score: report.score, level: report.level.key, report });
      } catch (_) { /* ignore */ }
    });
    const riskiestLink = linkFindings.slice().sort((a, b) => b.score - a.score)[0];
    if (riskiestLink && riskiestLink.score >= 18) {
      const severity = riskiestLink.score >= 70 ? 'critical' : riskiestLink.score >= 45 ? 'high' : 'medium';
      signals.push(makeSignal(
        'img-metadata-url', 'Dangerous URL concealed in file metadata',
        `A URL embedded in the image metadata scores ${riskiestLink.score}/100 for phishing or malware indicators: ${riskiestLink.url}.`,
        severity,
        severity === 'critical' ? 30 : severity === 'high' ? 20 : 12,
        'payload',
        riskiestLink.url.slice(0, 120),
      ));
    } else if (urlMatches.length) {
      positives.push('Embedded URLs passed structural analysis');
    }

    // QR code.
    const qr = await decodeQr(file);
    if (qr.found && qr.data) {
      const payload = qr.data;
      positives.push('QR code decoded and inspected');
      let qrFinding = null;
      if (/^https?:\/\//i.test(payload) || /^www\./i.test(payload)) {
        try {
          const report = analyzeUrl(payload);
          qrFinding = { type: 'url', report };
          if (report.score >= 70) {
            signals.push(makeSignal(
              'img-qr-risk', 'QR code opens a critical-risk destination',
              `The QR payload resolves to ${payload}, which scores ${report.score}/100 for phishing or malware indicators.`,
              'critical', 32, 'qr', payload.slice(0, 140),
            ));
          } else if (report.score >= 45) {
            signals.push(makeSignal(
              'img-qr-risk', 'QR code opens a high-risk destination',
              `The QR payload resolves to a link with a ${report.score}/100 threat score.`,
              'high', 22, 'qr', payload.slice(0, 140),
            ));
          } else if (report.score >= 20) {
            signals.push(makeSignal(
              'img-qr-risk', 'QR code opens a suspicious destination',
              `The encoded link has some risky characteristics (${report.score}/100). Verify it before visiting.`,
              'medium', 12, 'qr', payload.slice(0, 140),
            ));
          }
        } catch (_) { /* malformed QR URL */ }
      } else if (/^(bitcoin|ethereum|solana|upi):/i.test(payload) || /\b(0x[a-fA-F0-9]{40}|bc1[a-zA-HJ-NP-Z0-9]{25,62})\b/.test(payload)) {
        signals.push(makeSignal(
          'img-qr-payment', 'QR code contains a payment address',
          'The QR code encodes a cryptocurrency or direct-payment destination. Verify the recipient independently before paying.',
          'high', 24, 'qr', payload.slice(0, 140),
        ));
        qrFinding = { type: 'payment', report: null };
      } else {
        const visibleRisk = analyzeVisibleText(payload, 'QR text');
        if (visibleRisk && visibleRisk.report.score >= 20) {
          qrFinding = { type: 'message', report: visibleRisk.report };
          signals.push(makeSignal(
            'img-qr-text-risk', 'QR code contains social-engineering text',
            `The QR payload contains high-risk language and scores ${visibleRisk.report.score}/100: ${payload.slice(0, 140)}`,
            visibleRisk.report.score >= 70 ? 'critical' : visibleRisk.report.score >= 45 ? 'high' : 'medium',
            visibleRisk.report.score >= 70 ? 26 : visibleRisk.report.score >= 45 ? 18 : 10,
            'qr', payload.slice(0, 140),
          ));
        } else {
          qrFinding = { type: 'text', report: null };
        }
      }
      qr.report = qrFinding && qrFinding.report ? qrFinding.report : null;
      qr.payloadType = qrFinding ? qrFinding.type : 'text';
    }

    // OCR / visible text analysis.
    const ocr = await runOcr(file, options.onProgress);
    if (ocr && ocr.text) {
      const visibleRisk = analyzeVisibleText(ocr.text, 'OCR text');
      if (visibleRisk) {
        const score = visibleRisk.report.score;
        signals.push(makeSignal(
          'img-ocr-risk', 'Visible text contains phishing language',
          `On-device OCR found high-risk language in the image (${score}/100): “${ocr.text.slice(0, 180)}${ocr.text.length > 180 ? '…' : ''}”`,
          score >= 70 ? 'critical' : score >= 45 ? 'high' : 'medium',
          score >= 70 ? 32 : score >= 45 ? 22 : 12,
          'visual',
          ocr.text.slice(0, 180),
        ));
        ocr.report = visibleRisk.report;
      } else if (ocr.text.length >= 10) {
        positives.push('Visible text passed phishing-language analysis');
      }
    }

    // Metadata provenance.
    const aiMarker = AI_METADATA_MARKERS.find((marker) => lowerStrings.includes(marker));
    if (aiMarker) {
      signals.push(makeSignal(
        'img-ai', 'Synthetic-media provenance marker',
        `Metadata references an AI image-generation tool (${aiMarker}). The visual content may be synthetic or materially altered.`,
        'medium', 14, 'metadata', aiMarker,
      ));
    }
    const editorMarker = EDITOR_MARKERS.find((marker) => lowerStrings.includes(marker));
    if (editorMarker && !aiMarker) {
      signals.push(makeSignal(
        'img-editor', 'Editing-software provenance marker',
        `The file was processed with ${editorMarker}. This is not malicious by itself, but it weakens assumptions about authenticity.`,
        'low', 6, 'metadata', editorMarker,
      ));
    }

    if (metadata.GPS && metadata.GPS.latitude !== undefined) {
      signals.push(makeSignal(
        'img-gps', 'Precise GPS location embedded',
        'The image contains geolocation metadata. Sharing it publicly can expose a home, workplace, or travel pattern.',
        'low', 8, 'privacy', formatGps(metadata.GPS),
      ));
    }

    const dateStrings = [metadata.DateTimeOriginal, metadata.DateTime].filter(Boolean);
    if (dateStrings.length) {
      const parsed = Date.parse(dateStrings[0].replace(/^(\d{4}):(\d{2}):(\d{2})/, '$1-$2-$3'));
      if (!Number.isNaN(parsed) && parsed > Date.now() + 24 * 60 * 60 * 1000) {
        signals.push(makeSignal(
          'img-future-date', 'Impossible capture timestamp',
          'The metadata claims the image was captured in the future, which suggests manual tampering or a manipulated clock.',
          'medium', 12, 'metadata', dateStrings[0],
        ));
      }
    }

    const oversizedComment = metadataValues.find((entry) => /comment|description/i.test(entry.key) && entry.value.length > 1500);
    if (oversizedComment) {
      signals.push(makeSignal(
        'img-metadata-size', 'Oversized metadata field',
        'A metadata comment field is unusually large. Oversized fields can conceal tracking identifiers or encoded payloads.',
        'medium', 10, 'metadata', `${oversizedComment.value.length} characters`,
      ));
    }

    // Trailing data after logical image end.
    const trailingLength = Math.max(0, bytes.length - imageEnd);
    if (trailingLength > 512) {
      const trailing = bytes.slice(imageEnd, Math.min(bytes.length, imageEnd + 4 * 1024 * 1024));
      const embedded = findEmbeddedSignatures(trailing, 0);
      if (embedded.length) {
        signals.push(makeSignal(
          'img-executable', 'Embedded executable payload after image data',
          `A ${embedded[0].name} signature appears in data appended after the end of the image. This is a malware polyglot or steganographic carrier.`,
          'critical', 46, 'payload', `${embedded[0].name} at trailing offset ${embedded[0].offset}`,
        ));
      } else {
        signals.push(makeSignal(
          'img-trailing', 'Appended data after image end',
          `The file contains ${(trailingLength / 1024).toFixed(1)} KB of data beyond the logical end of the image. Legitimate exports rarely append data here; it can conceal a payload.`,
          'high', 24, 'payload', `${trailingLength} trailing bytes`,
        ));
      }
    } else if (trailingLength > 0) {
      positives.push('No substantial data appended after image end');
    }

    // Metadata parse success.
    if (metadataValues.length) positives.push(`${metadataValues.length} metadata field${metadataValues.length === 1 ? '' : 's'} inspected`);
    else positives.push('No identifying metadata exposed');
    if (ocr && ocr.supported && !ocr.failed && !ocr.skipped) positives.push('Visible text inspected with on-device OCR');
    if (qr.supported) positives.push('QR payload analysis completed');
    if (!scriptsFound.length) positives.push('No executable script markers detected');

    // Dimensions from image decoding.
    let dimensions = null;
    try {
      const bitmap = await createImageBitmap(file);
      dimensions = { width: bitmap.width, height: bitmap.height };
      bitmap.close();
    } catch (_) { /* browser may not decode HEIC */ }

    const cleanMetadata = { ...metadata };
    delete cleanMetadata._chunks;
    delete cleanMetadata._endOffset;

    const details = {
      fileName: file.name,
      fileSize: file.size,
      mime: fileType.mime,
      fileType: fileType.label,
      extension,
      dimensions,
      metadata: cleanMetadata,
      metadataCount: metadataValues.length,
      urls: linkFindings.map((link) => ({ url: link.url, score: link.score, level: link.level })),
      qr: qr.found ? { data: qr.data, payloadType: qr.payloadType, report: qr.report } : null,
      qrSupported: qr.supported,
      ocr: ocr && ocr.text ? {
        text: ocr.text.slice(0, 4000),
        confidence: ocr.confidence,
        report: ocr.report || null,
      } : null,
      ocrSupported: ocr ? ocr.supported : false,
      ocrFailed: ocr ? Boolean(ocr.failed || ocr.skipped) : false,
      trailingBytes: trailingLength,
      imageEnd,
      hashes: await computeHashes(file),
    };

    return buildReport('image', file.name, signals, positives, details, {
      hasExternal: false,
      categories: [
        { key: 'payload', label: 'Embedded payload' },
        { key: 'qr', label: 'QR threat' },
        { key: 'visual', label: 'Visual phishing' },
        { key: 'metadata', label: 'Metadata / provenance' },
        { key: 'privacy', label: 'Privacy exposure' },
      ],
    });
  }

  function formatGps(gps) {
    if (!gps) return '';
    const lat = Number(gps.latitude);
    const lon = Number(gps.longitude);
    if (Number.isFinite(lat) && Number.isFinite(lon)) {
      return `${Math.abs(lat).toFixed(5)}° ${gps.latRef === 'S' ? 'S' : 'N'}, ${Math.abs(lon).toFixed(5)}° ${gps.lonRef === 'W' ? 'W' : 'E'}`;
    }
    return 'GPS coordinates present';
  }

  async function computeHashes(file) {
    const out = {};
    try {
      if (window.crypto && window.crypto.subtle && file.size < 64 * 1024 * 1024) {
        const buffer = await file.arrayBuffer();
        const digest = await window.crypto.subtle.digest('SHA-256', buffer);
        out.sha256 = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
      }
    } catch (_) { /* hashing is optional */ }
    return out;
  }

  function isProbablyUrl(text) {
    const value = String(text || '').trim();
    if (!value || /\s/.test(value)) return false;
    return /^(https?:\/\/|www\.|javascript:|data:|[a-z0-9-]+\.[a-z]{2,}(\/|$))/i.test(value);
  }

  window.SentinelEngine = {
    analyzeUrl,
    analyzeMessage,
    analyzeImage,
    isProbablyUrl,
    extractUrls,
    levelForScore: scoreToLevel,
    levels: LEVELS,
    escapeHtml,
    _internals: {
      getRegistrableDomain,
      deLeet,
      levenshtein,
      detectFileType,
      parseJpegMetadata,
      parsePngMetadata,
      aggregate,
    },
  };
})();
