/* Sentinel AI — platform controller
 * Local-first SOC workspace: section routing, scanner UI, indicator ledger,
 * investigations, analytics, reports and privacy controls.
 */
(function () {
  'use strict';

  const $ = (selector, root) => (root || document).querySelector(selector);
  const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));
  const engine = window.SentinelEngine;
  const intel = window.SentinelIntel;
  const reportBuilder = window.SentinelReport;

  const STORAGE_KEY = 'sentinel.ai.history.v1';
  const VIEW_KEY = 'sentinel.ai.view.v1';
  const SECTION_KEY = 'sentinel.ai.section.v1';
  const INVESTIGATION_KEY = 'sentinel.ai.investigations.v1';
  const INDICATOR_KEY = 'sentinel.ai.indicators.v1';
  const INDICATOR_SEED_KEY = 'sentinel.ai.indicators.seeded.v1';

  const MAX_HISTORY = 50;
  const MAX_INVESTIGATIONS = 100;
  const MAX_INDICATORS = 500;
  const MAX_OBSERVATIONS = 12;
  const FLAG_THRESHOLD = 20;

  const SECTIONS = {
    overview: 'Overview',
    intel: 'Threat intelligence',
    scanner: 'Scanner',
    investigations: 'Investigations',
    analytics: 'Detection analytics',
    history: 'Scan history',
    settings: 'Settings & privacy',
  };

  const STATUSES = ['Open', 'Investigating', 'Contained', 'Resolved'];
  const SEVERITIES = ['critical', 'high', 'moderate', 'low'];

  const TEST_CASES = [
    {
      id: 'url-phishing-brand',
      name: 'Brand-lookalike login URL',
      type: 'url',
      label: 'malicious',
      note: 'Bundled scanner sample',
      input: 'https://paypa1-secure-login.verify-account.top/session/confirm?token=8f3a',
    },
    {
      id: 'url-legacy-github',
      name: 'Known service login',
      type: 'url',
      label: 'benign',
      note: 'Bundled scanner sample',
      input: 'https://github.com/login',
    },
    {
      id: 'url-private-router',
      name: 'Private-address credential page',
      type: 'url',
      label: 'malicious',
      note: 'Bundled scanner sample',
      input: 'http://192.168.1.1/router-login',
    },
    {
      id: 'url-embedded-payload',
      name: 'Embedded HTML payload URL',
      type: 'url',
      label: 'malicious',
      note: 'Bundled scanner sample',
      input: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    },
    {
      id: 'url-safe-reference',
      name: 'Public reference site',
      type: 'url',
      label: 'benign',
      note: 'Additional benign case',
      input: 'https://www.wikipedia.org/',
    },
    {
      id: 'url-credential-page',
      name: 'Unbranded account-verification page',
      type: 'url',
      label: 'malicious',
      note: 'Additional malicious case',
      input: 'https://secure-account-verification.top/login/confirm',
    },
    {
      id: 'url-amazon-uk',
      name: 'Regional Amazon storefront',
      type: 'url',
      label: 'benign',
      note: 'Unseen validation case. Regional domains must be trusted, not treated as impersonation.',
      input: 'https://www.amazon.co.uk/ap/signin',
    },
    {
      id: 'url-amazon-uk-lookalike',
      name: 'Amazon name inside an attacker domain',
      type: 'url',
      label: 'malicious',
      note: 'Unseen validation case. The brand appears in a subdomain of an unrelated registrable domain.',
      input: 'https://amazon.co.uk.evil.com/login',
    },
    {
      id: 'msg-fake-alert',
      name: 'Fake Apple account alert',
      type: 'message',
      label: 'malicious',
      note: 'Bundled scanner sample',
      input: 'URGENT: Your Apple ID has been locked due to unauthorized access. You must verify your identity within 24 hours or your account will be permanently suspended. Verify now: http://apple-id-verify.secure-login.top',
    },
    {
      id: 'msg-legitimate-lunch',
      name: 'Ordinary lunch message',
      type: 'message',
      label: 'benign',
      note: 'Bundled scanner sample',
      input: 'Hi, are we still meeting for lunch tomorrow at 1? I can book the corner table.',
    },
    {
      id: 'msg-gift-card',
      name: 'Executive gift-card fraud',
      type: 'message',
      label: 'malicious',
      note: 'Bundled scanner sample',
      input: 'Hi, this is the CFO. I need you to buy four $500 Apple gift cards for a client incentive today. Keep this confidential and send me the codes. Do not tell anyone.',
    },
    {
      id: 'msg-seed-phrase',
      name: 'Wallet seed-phrase theft',
      type: 'message',
      label: 'malicious',
      note: 'Bundled scanner sample',
      input: 'Final warning: your Bitcoin wallet is being deactivated. Send your 12-word seed phrase to our support team immediately to restore access.',
    },
    {
      id: 'msg-otp-request',
      name: 'One-time code request',
      type: 'message',
      label: 'malicious',
      note: 'Additional malicious case',
      input: 'This is account security. Please share the verification code you just received with our support agent so we can restore access immediately.',
    },
    {
      id: 'msg-otp-paraphrase',
      name: 'Paraphrased one-time code request',
      type: 'message',
      label: 'malicious',
      note: 'Unseen validation case. Uses “reply with the 6-digit code” instead of “share the code”.',
      input: 'Hi, this is support. To secure your account, reply with the 6-digit code we just sent to your phone.',
    },
    {
      id: 'msg-otp-readback',
      name: 'Request to read back a received code',
      type: 'message',
      label: 'malicious',
      note: 'Unseen validation case. The request reverses the usual word order.',
      input: 'The code you received — send it to me now.',
    },
    {
      id: 'msg-code-notification',
      name: 'Legitimate verification-code notification',
      type: 'message',
      label: 'benign',
      note: 'Unseen validation case. A code notification plus a “do not share” warning is protective, not a request.',
      input: 'Your Amazon verification code is 481920. Do not share it with anyone.',
    },
    {
      id: 'msg-anti-fraud-warning',
      name: 'Bank anti-fraud warning',
      type: 'message',
      label: 'benign',
      note: 'Unseen validation case. Negated advice (“never share a one-time code”) must not be read as a request.',
      input: 'We will never ask you to share your one-time code. If someone requests it, hang up and call us.',
    },
    {
      id: 'msg-invoice-attachment',
      name: 'Executable invoice attachment',
      type: 'message',
      label: 'malicious',
      note: 'Additional malicious case',
      input: 'Please review the attached invoice_2026.pdf.exe and confirm the payment details before the end of the day.',
    },
    {
      id: 'msg-project-update',
      name: 'Routine project update',
      type: 'message',
      label: 'benign',
      note: 'Additional benign case',
      input: 'Hi team, the project update meeting is moved to Thursday at 10:00 in room 4. Please review the agenda beforehand.',
    },
    {
      id: 'img-phishing-screenshot',
      name: 'Phishing screenshot',
      type: 'image',
      label: 'malicious',
      note: 'Bundled sample fixture',
      sample: 'assets/samples/phishing-screenshot.png',
    },
    {
      id: 'img-malicious-qr',
      name: 'Malicious QR code',
      type: 'image',
      label: 'malicious',
      note: 'Bundled sample fixture',
      sample: 'assets/samples/malicious-qr.png',
    },
    {
      id: 'img-hidden-payload',
      name: 'Hidden payload image',
      type: 'image',
      label: 'malicious',
      note: 'Bundled sample fixture',
      sample: 'assets/samples/hidden-payload.jpg',
    },
    {
      id: 'img-ai-metadata',
      name: 'AI provenance metadata',
      type: 'image',
      label: 'benign',
      note: 'Bundled sample fixture. A provenance warning is not malware; it can register as a false positive under a malware-only label.',
      sample: 'assets/samples/ai-metadata.png',
    },
    {
      id: 'img-clean',
      name: 'Clean image',
      type: 'image',
      label: 'benign',
      note: 'Bundled sample fixture',
      sample: 'assets/samples/clean.png',
    },
  ];

  const state = {
    mode: 'url',
    view: 'simple',
    section: 'overview',
    file: null,
    previewUrl: null,
    previewReportId: null,
    result: null,
    history: [],
    investigations: [],
    indicators: [],
    scanning: false,
    scanTimers: [],
    scanInterval: null,
    toastTimer: null,
    sidebarOpen: false,
    lastFocus: null,
    modalConfirm: null,
    activeInvestigation: null,
    graphData: null,
    graphSelected: null,
    intelAnalysis: null,
    testRunning: false,
    testResults: [],
    testMetrics: null,
  };

  const refs = {
    sidebar: $('#sidebar'),
    mobileMenu: $('#mobileMenu'),
    crumbCurrent: $('#crumbCurrent'),
    commandTrigger: $('#commandTrigger'),
    tabs: $$('.mode-tab'),
    panels: $$('.mode-panel'),
    urlInput: $('#urlInput'),
    urlField: $('#urlField'),
    clearUrl: $('#clearUrl'),
    pasteUrl: $('#pasteUrl'),
    messageInput: $('#messageInput'),
    charCount: $('#charCount'),
    imageInput: $('#imageInput'),
    dropzone: $('#dropzone'),
    filePreview: $('#filePreview'),
    previewImage: $('#previewImage'),
    fileName: $('#fileName'),
    fileDetails: $('#fileDetails'),
    removeFile: $('#removeFile'),
    scanButton: $('#scanButton'),
    scanButtonText: $('#scanButtonText'),
    verdictState: $('#verdictState'),
    verdictIdle: $('#verdictIdle'),
    verdictScanning: $('#verdictScanning'),
    verdictResult: $('#verdictResult'),
    verdictScroll: $('#verdictScroll'),
    scanningTitle: $('#scanningTitle'),
    scanningSubtitle: $('#scanningSubtitle'),
    scanSteps: $('#scanSteps'),
    scanProgressBar: $('#scanProgressBar'),
    historyList: $('#historyList'),
    navHistoryCount: $('#navHistoryCount'),
    navIntelCount: $('#navIntelCount'),
    navInvCount: $('#navInvCount'),
    historyPanelCount: $('#historyPanelCount'),
    clearHistory: $('#clearHistory'),
    statScans: $('#statScans'),
    statThreats: $('#statThreats'),
    toast: $('#toast'),
    toastText: $('#toastText'),
    modalBackdrop: $('#modalBackdrop'),
    modalTitle: $('#modalTitle'),
    modalKicker: $('#modalKicker'),
    modalBody: $('#modalBody'),
    modalFooter: $('#modalFooter'),
    modalIcon: $('#modalIcon'),
    modalClose: $('#modalClose'),
    overviewStatus: $('#overviewStatus'),
    overviewMetrics: $('#overviewMetrics'),
    severityChartMeta: $('#severityChartMeta'),
    severityChart: $('#severityChart'),
    categoryChart: $('#categoryChart'),
    recentActivity: $('#recentActivity'),
    recentInvestigations: $('#recentInvestigations'),
    latestIndicators: $('#latestIndicators'),
    intelInput: $('#intelInput'),
    intelAnalyze: $('#intelAnalyze'),
    intelResult: $('#intelResult'),
    indicatorCount: $('#indicatorCount'),
    indicatorSearch: $('#indicatorSearch'),
    indicatorTypeFilter: $('#indicatorTypeFilter'),
    indicatorList: $('#indicatorList'),
    graphMeta: $('#graphMeta'),
    refreshGraph: $('#refreshGraph'),
    graphStage: $('#graphStage'),
    graphDetails: $('#graphDetails'),
    newInvestigation: $('#newInvestigation'),
    investigationSummary: $('#investigationSummary'),
    invSearch: $('#invSearch'),
    invStatusFilter: $('#invStatusFilter'),
    invSeverityFilter: $('#invSeverityFilter'),
    investigationCount: $('#investigationCount'),
    investigationList: $('#investigationList'),
    investigationListView: $('#investigationListView'),
    investigationDetailView: $('#investigationDetailView'),
    runTests: $('#runTests'),
    analyticsSummary: $('#analyticsSummary'),
    analyticsProgress: $('#analyticsProgress'),
    analyticsProgressLabel: $('#analyticsProgressLabel'),
    analyticsProgressCount: $('#analyticsProgressCount'),
    analyticsProgressBar: $('#analyticsProgressBar'),
    analyticsResults: $('#analyticsResults'),
    clearHistoryFull: $('#clearHistoryFull'),
    historySearch: $('#historySearch'),
    historyTypeFilter: $('#historyTypeFilter'),
    historySeverityFilter: $('#historySeverityFilter'),
    historyFullCount: $('#historyFullCount'),
    historyFullList: $('#historyFullList'),
    settingsStorageSize: $('#settingsStorageSize'),
    settingsStorageCounts: $('#settingsStorageCounts'),
  };

  /* ────────────────────────────────────────────────────────────────────────
     Utilities
     ──────────────────────────────────────────────────────────────────────── */

  function escape(value) {
    if (engine && typeof engine.escapeHtml === 'function') return engine.escapeHtml(value);
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function icon(id, className) {
    return '<svg class="icon ' + (className || '') + '"><use href="#' + id + '"></use></svg>';
  }

  function readStore(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      if (raw === null) return fallback;
      return JSON.parse(raw);
    } catch (_) {
      return fallback;
    }
  }

  function writeStore(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (_) {
      return false;
    }
  }

  function readText(key, fallback) {
    try {
      const value = localStorage.getItem(key);
      return value === null ? fallback : value;
    } catch (_) {
      return fallback;
    }
  }

  function persistHistory() {
    writeStore(STORAGE_KEY, state.history.slice(0, MAX_HISTORY).map(compactReport));
  }

  function persistInvestigations() {
    writeStore(INVESTIGATION_KEY, state.investigations.slice(0, MAX_INVESTIGATIONS));
  }

  function persistIndicators() {
    const trimmed = state.indicators.slice(0, MAX_INDICATORS).map((item) => {
      const copy = Object.assign({}, item);
      copy.observations = (copy.observations || []).slice(0, MAX_OBSERVATIONS);
      return copy;
    });
    writeStore(INDICATOR_KEY, trimmed);
  }

  function compactReport(report) {
    const clone = JSON.parse(JSON.stringify(report));
    if (clone.details) {
      delete clone.details.metadata;
      delete clone.details.hashes;
      if (clone.details.ocr) clone.details.ocr.text = String(clone.details.ocr.text || '').slice(0, 400);
      if (clone.details.qr && clone.details.qr.report) {
        clone.details.qr.report = {
          score: clone.details.qr.report.score,
          level: clone.details.qr.report.level,
          summary: clone.details.qr.report.summary,
        };
      }
    }
    return clone;
  }

  function loadHistory() {
    const parsed = readStore(STORAGE_KEY, []);
    return Array.isArray(parsed)
      ? parsed.filter((item) => item && item.id && typeof item.score === 'number')
      : [];
  }

  function loadInvestigations() {
    const parsed = readStore(INVESTIGATION_KEY, []);
    return Array.isArray(parsed)
      ? parsed.filter((item) => item && item.id && item.title && STATUSES.includes(item.status))
      : [];
  }

  function loadIndicators() {
    const parsed = readStore(INDICATOR_KEY, []);
    return Array.isArray(parsed)
      ? parsed.filter((item) => item && item.key && item.type && item.normalized)
      : [];
  }

  function relativeTime(timestamp) {
    const seconds = Math.max(0, Math.floor((Date.now() - Number(timestamp || 0)) / 1000));
    if (seconds < 10) return 'just now';
    if (seconds < 60) return seconds + 's ago';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + 'm ago';
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return hours + 'h ago';
    const days = Math.floor(hours / 24);
    if (days < 7) return days + 'd ago';
    return new Date(timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  function formatDate(timestamp) {
    const date = new Date(Number(timestamp) || Date.now());
    return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
  }

  function formatDateTime(timestamp) {
    const date = new Date(Number(timestamp) || Date.now());
    return date.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    });
  }

  function plural(count, singular, pluralForm) {
    return count === 1 ? singular : (pluralForm || singular + 's');
  }

  function levelFor(score) {
    if (engine && typeof engine.levelForScore === 'function') return engine.levelForScore(Number(score) || 0);
    if (score >= 70) return { key: 'critical', label: 'Critical threat', short: 'CRITICAL' };
    if (score >= 45) return { key: 'high', label: 'High risk', short: 'HIGH' };
    if (score >= 20) return { key: 'moderate', label: 'Moderate risk', short: 'MODERATE' };
    return { key: 'low', label: 'Low risk', short: 'LOW' };
  }

  function riskColor(level) {
    if (level === 'critical') return '#ff5f70';
    if (level === 'high') return '#ff9257';
    if (level === 'moderate') return '#f5c451';
    return '#54e6ae';
  }

  function typeLabel(type) {
    if (type === 'url') return 'Link analysis';
    if (type === 'image') return 'Image analysis';
    if (type === 'message') return 'Message analysis';
    if (type === 'manual') return 'Manual analysis';
    return 'Analysis';
  }

  function simpleTypeLabel(type) {
    if (type === 'url') return 'Link';
    if (type === 'image') return 'Photo';
    if (type === 'message') return 'Message';
    return 'Indicator';
  }

  function typeIcon(type, className) {
    const id = type === 'url' ? 'i-link' : type === 'image' ? 'i-image' : type === 'message' ? 'i-message' : 'i-target';
    return icon(id, className);
  }

  function verdictWord(level) {
    if (level === 'critical') return 'DANGER';
    if (level === 'high') return 'RISKY';
    if (level === 'moderate') return 'CAUTION';
    return 'SAFE';
  }

  function simpleHeadline(level) {
    if (level === 'critical') return 'Very likely a scam';
    if (level === 'high') return 'Several warning signs';
    if (level === 'moderate') return 'Some things look off';
    return 'No warning signs found';
  }

  function truncate(value, length) {
    const text = String(value === null || value === undefined ? '' : value);
    if (text.length <= length) return text;
    return text.slice(0, Math.max(0, length - 1)) + '…';
  }

  function emptyState(iconId, title, text, compact) {
    return [
      '<div class="inline-empty' + (compact ? ' compact' : '') + '">',
      '<span class="inline-empty-icon">' + icon(iconId) + '</span>',
      '<div><strong>' + escape(title) + '</strong><span>' + escape(text) + '</span></div>',
      '</div>',
    ].join('');
  }

  function scoreText(score) {
    return typeof score === 'number' ? String(score) : 'UNKNOWN';
  }

  function severityChip(severity) {
    const key = SEVERITIES.includes(severity) ? severity : 'low';
    return '<span class="severity-chip ' + key + '">' + escape(String(severity || key).toUpperCase()) + '</span>';
  }

  function statusChip(status) {
    const key = STATUSES.includes(status) ? status.toLowerCase() : 'open';
    return '<span class="status-chip ' + key + '"><span></span>' + escape(status || 'Open') + '</span>';
  }

  function reportScoreBadge(report) {
    const level = report && report.level && report.level.key ? report.level.key : levelFor(report ? report.score : 0).key;
    return '<span class="score-badge ' + level + '"><strong>' + scoreText(report ? report.score : null) + '</strong><span>/100</span></span>';
  }

  function indicatorLevel(score) {
    return typeof score === 'number' ? levelFor(score) : null;
  }

  function storageBytes() {
    const keys = [STORAGE_KEY, INVESTIGATION_KEY, INDICATOR_KEY, VIEW_KEY, SECTION_KEY];
    return keys.reduce((total, key) => {
      let value = '';
      try { value = localStorage.getItem(key) || ''; } catch (_) { value = ''; }
      return total + key.length + value.length;
    }, 0);
  }

  function storageSizeLabel() {
    const bytes = storageBytes();
    if (bytes < 1024) return bytes + ' B';
    return (bytes / 1024).toFixed(bytes < 10240 ? 1 : 0) + ' KB';
  }

  /* ────────────────────────────────────────────────────────────────────────
     Indicator ledger ingestion
     ──────────────────────────────────────────────────────────────────────── */

  function ingestReport(report, options) {
    if (!report || !intel) return [];
    var extracted = [];
    try {
      extracted = intel.extractIndicators(report);
    } catch (_) {
      extracted = [];
    }
    mergeIndicators(extracted, options);
    return extracted;
  }

  function mergeIndicators(items, options) {
    if (!Array.isArray(items) || !items.length) return;
    const persist = !options || options.persist !== false;
    const now = Date.now();
    items.forEach((item) => {
      if (!item || !item.type || !item.normalized) return;
      const key = item.key || intel.keyFor(item.type, item.normalized);
      let record = state.indicators.find((candidate) => candidate.key === key);
      if (!record) {
        record = {
          id: item.id || intel.idFor(item.type, item.normalized),
          key: key,
          type: item.type,
          normalized: item.normalized,
          value: item.value || item.normalized,
          category: item.category || intel.categoryForType(item.type),
          score: typeof item.score === 'number' ? item.score : null,
          confidence: typeof item.confidence === 'number' ? item.confidence : null,
          reputation: 'UNKNOWN',
          firstSeen: Number(item.observedAt) || now,
          lastSeen: Number(item.observedAt) || now,
          observations: [],
        };
        state.indicators.push(record);
      }
      record.lastSeen = Math.max(Number(record.lastSeen) || 0, Number(item.observedAt) || now);
      record.firstSeen = Math.min(Number(record.firstSeen) || now, Number(item.observedAt) || now);
      if (item.category) record.category = item.category;
      if (typeof item.score === 'number') {
        record.score = typeof record.score === 'number' ? Math.max(record.score, item.score) : item.score;
      }
      if (typeof item.confidence === 'number') {
        record.confidence = Math.max(Number(record.confidence) || 0, item.confidence);
      }
      const observationKey = item.sourceScanId || ('manual:' + item.normalized + ':' + (item.observedAt || now));
      const existing = record.observations.find((observation) => observation.key === observationKey);
      const observation = {
        key: observationKey,
        scanId: item.sourceScanId || null,
        sourceType: item.sourceScanType || 'manual',
        sourceTarget: item.sourceTarget || 'Manual analysis',
        score: typeof item.score === 'number' ? item.score : null,
        level: item.sourceLevel || (typeof item.score === 'number' ? levelFor(item.score).key : null),
        evidence: item.evidence || '',
        observedAt: Number(item.observedAt) || now,
      };
      if (existing) {
        existing.score = observation.score;
        existing.level = observation.level;
        existing.evidence = observation.evidence || existing.evidence;
        existing.observedAt = Math.min(existing.observedAt || now, observation.observedAt);
      } else {
        record.observations.push(observation);
      }
      record.observations.sort((a, b) => b.observedAt - a.observedAt);
      record.observations = record.observations.slice(0, MAX_OBSERVATIONS);
    });
    state.indicators.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
    if (state.indicators.length > MAX_INDICATORS) state.indicators = state.indicators.slice(0, MAX_INDICATORS);
    if (persist) persistIndicators();
    updateCounters();
  }

  function seedIndicatorsFromHistory() {
    if (readStore(INDICATOR_SEED_KEY, false) === true) return;
    state.history.slice().reverse().forEach((report) => ingestReport(report, { persist: false }));
    persistIndicators();
    writeStore(INDICATOR_SEED_KEY, true);
  }

  /* ────────────────────────────────────────────────────────────────────────
     Counters / shared small renderers
     ──────────────────────────────────────────────────────────────────────── */

  function updateCounters() {
    if (refs.navHistoryCount) refs.navHistoryCount.textContent = String(state.history.length);
    if (refs.navIntelCount) refs.navIntelCount.textContent = String(state.indicators.length);
    const openCount = state.investigations.filter((item) => item.status === 'Open' || item.status === 'Investigating').length;
    if (refs.navInvCount) refs.navInvCount.textContent = String(openCount);
    if (refs.historyPanelCount) {
      const noun = state.view === 'simple' ? 'check' : 'scan';
      refs.historyPanelCount.textContent = state.history.length + ' ' + plural(state.history.length, noun);
    }
    if (refs.statScans) refs.statScans.textContent = String(state.history.length);
    if (refs.statThreats) refs.statThreats.textContent = String(state.history.filter((item) => item.score >= 45).length);
    if (refs.clearHistory) refs.clearHistory.hidden = state.history.length === 0;
  }

  /* ────────────────────────────────────────────────────────────────────────
     Section router
     ──────────────────────────────────────────────────────────────────────── */

  function routeTo(section, options) {
    const target = SECTIONS[section] ? section : 'overview';
    state.section = target;
    $$('.section-panel').forEach((panel) => {
      const active = panel.dataset.sectionPanel === target;
      panel.hidden = !active;
      panel.classList.toggle('active', active);
    });
    $$('.nav-item[data-route]').forEach((button) => {
      const active = button.dataset.route === target;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    });
    if (refs.crumbCurrent) refs.crumbCurrent.textContent = SECTIONS[target];
    writeStore(SECTION_KEY, target);
    if (!options || options.updateHash !== false) {
      try { history.replaceState(null, '', '#/' + target); } catch (_) { /* ignore */ }
    }
    if (window.innerWidth < 1070) closeSidebar();

    if (target === 'overview') renderOverview();
    if (target === 'intel') renderIntelPage();
    if (target === 'investigations') renderInvestigations();
    if (target === 'analytics') renderAnalytics();
    if (target === 'history') renderHistoryPage();
    if (target === 'settings') renderSettings();
    if (target === 'scanner') updateCounters();

    if (!options || options.scroll !== false) {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }

  function currentSectionFromHash() {
    const match = String(location.hash || '').match(/^#\/([a-z]+)$/);
    return match && SECTIONS[match[1]] ? match[1] : null;
  }

  /* ────────────────────────────────────────────────────────────────────────
     Overview
     ──────────────────────────────────────────────────────────────────────── */

  function metricCard(label, value, note, iconId, tone) {
    return [
      '<article class="metric-card' + (tone ? ' tone-' + tone : '') + '">',
      '<div class="metric-card-top"><span>' + escape(label) + '</span><span class="metric-card-icon">' + icon(iconId) + '</span></div>',
      '<strong>' + escape(value) + '</strong>',
      '<p>' + escape(note) + '</p>',
      '</article>',
    ].join('');
  }

  function renderOverview() {
    const scans = state.history;
    const openInvestigations = state.investigations.filter((item) => item.status === 'Open' || item.status === 'Investigating');
    const highScans = scans.filter((item) => item.score >= 45);
    const lastScan = scans[0];

    if (refs.overviewMetrics) {
      refs.overviewMetrics.innerHTML = [
        metricCard('Scans analysed', String(scans.length), 'Stored in this browser', 'i-radar', 'blue'),
        metricCard('High / critical', String(highScans.length), 'Verdicts at 45 or above', 'i-alert', highScans.length ? 'red' : 'mint'),
        metricCard('Open investigations', String(openInvestigations.length), state.investigations.length + ' total ' + plural(state.investigations.length, 'investigation'), 'i-shield', 'violet'),
        metricCard('Tracked indicators', String(state.indicators.length), 'Unique local observations', 'i-globe', 'amber'),
      ].join('');
    }

    if (refs.overviewStatus) {
      if (!scans.length && !state.investigations.length && !state.indicators.length) {
        refs.overviewStatus.className = 'status-banner empty';
        refs.overviewStatus.innerHTML = [
          '<span class="status-banner-icon">' + icon('i-database') + '</span>',
          '<div><strong>Workspace is empty</strong><span>Run a scan or analyze an indicator. Dashboard metrics and charts stay blank until real local data exists.</span></div>',
          '<button class="secondary-button compact" data-route="scanner">' + icon('i-radar') + 'Start a scan</button>',
        ].join('');
      } else {
        refs.overviewStatus.className = 'status-banner active';
        refs.overviewStatus.innerHTML = [
          '<span class="status-banner-icon">' + icon('i-activity') + '</span>',
          '<div><strong>Local workspace active</strong><span>' +
            escape(scans.length + ' ' + plural(scans.length, 'scan') + ' · ' + state.indicators.length + ' ' + plural(state.indicators.length, 'indicator') + ' · ' + state.investigations.length + ' ' + plural(state.investigations.length, 'investigation')) +
            (lastScan ? ' · Last verdict ' + escape(formatDateTime(lastScan.timestamp)) : '') +
          '</span></div>',
          '<button class="secondary-button compact" data-route="history">' + icon('i-history') + 'Open ledger</button>',
        ].join('');
      }
    }

    renderSeverityChart();
    renderCategoryChart();
    renderRecentActivity();
    renderRecentInvestigations();
    renderLatestIndicators();
    updateCounters();
  }

  function renderSeverityChart() {
    if (!refs.severityChart) return;
    const order = ['critical', 'high', 'moderate', 'low'];
    const labels = { critical: 'Critical', high: 'High', moderate: 'Moderate', low: 'Low' };
    const counts = { critical: 0, high: 0, moderate: 0, low: 0 };
    state.history.forEach((report) => {
      const key = report.level && report.level.key ? report.level.key : levelFor(report.score).key;
      if (counts[key] === undefined) counts[key] = 0;
      counts[key] += 1;
    });
    const total = state.history.length;
    if (refs.severityChartMeta) refs.severityChartMeta.textContent = total + ' ' + plural(total, 'scan');
    if (!total) {
      refs.severityChart.innerHTML = emptyState('i-activity', 'No verdicts recorded', 'Severity distribution appears after your first stored scan.');
      return;
    }
    const max = Math.max.apply(null, order.map((key) => counts[key]));
    refs.severityChart.innerHTML = order.map((key) => {
      const count = counts[key];
      const width = max ? Math.max(count ? 4 : 0, Math.round((count / max) * 100)) : 0;
      const percent = Math.round((count / total) * 100);
      return [
        '<div class="chart-row">',
        '<div class="chart-row-label"><span class="dot ' + key + '"></span>' + labels[key] + '</div>',
        '<div class="chart-track"><span class="chart-fill ' + key + '" style="width:' + width + '%"></span></div>',
        '<div class="chart-value"><strong>' + count + '</strong><span>' + percent + '%</span></div>',
        '</div>',
      ].join('');
    }).join('');
  }

  function renderCategoryChart() {
    if (!refs.categoryChart) return;
    const counts = new Map();
    state.history.forEach((report) => {
      (report.categories || []).forEach((category) => {
        if (!category || !category.score) return;
        const key = category.label || category.key || 'Other';
        counts.set(key, (counts.get(key) || 0) + 1);
      });
    });
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);
    if (!entries.length) {
      refs.categoryChart.innerHTML = emptyState('i-pulse', 'No categories fired', 'Detection categories appear when stored scans produce signals.');
      return;
    }
    const max = entries[0][1];
    refs.categoryChart.innerHTML = entries.map((entry) => {
      const width = Math.max(4, Math.round((entry[1] / max) * 100));
      return [
        '<div class="chart-row category">',
        '<div class="chart-row-label">' + escape(entry[0]) + '</div>',
        '<div class="chart-track"><span class="chart-fill category" style="width:' + width + '%"></span></div>',
        '<div class="chart-value"><strong>' + entry[1] + '</strong><span>scans</span></div>',
        '</div>',
      ].join('');
    }).join('');
  }

  function renderRecentActivity() {
    if (!refs.recentActivity) return;
    if (!state.history.length) {
      refs.recentActivity.innerHTML = emptyState('i-history', 'No scan activity', 'Your recent local analyses will be listed here.', true);
      return;
    }
    refs.recentActivity.innerHTML = '<div class="compact-list">' + state.history.slice(0, 5).map((report) => {
      const level = report.level && report.level.key ? report.level.key : levelFor(report.score).key;
      return [
        '<button class="compact-row" data-open-scan="' + escape(report.id) + '">',
        '<span class="compact-icon ' + level + '">' + typeIcon(report.type) + '</span>',
        '<span class="compact-main"><strong>' + escape(report.displayTarget || report.target || 'Untitled scan') + '</strong>',
        '<span>' + escape(typeLabel(report.type)) + ' · ' + escape(relativeTime(report.timestamp)) + '</span></span>',
        reportScoreBadge(report),
        '</button>',
      ].join('');
    }).join('') + '</div>';
  }

  function renderRecentInvestigations() {
    if (!refs.recentInvestigations) return;
    const list = state.investigations.slice().sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0)).slice(0, 4);
    if (!list.length) {
      refs.recentInvestigations.innerHTML = emptyState('i-shield', 'No investigations yet', 'Create an incident from a scan or open the workspace to begin.', true);
      return;
    }
    refs.recentInvestigations.innerHTML = '<div class="compact-list">' + list.map((investigation) => [
      '<button class="compact-row" data-open-inv="' + escape(investigation.id) + '">',
      '<span class="compact-icon ' + escape(investigation.severity) + '">' + icon('i-shield') + '</span>',
      '<span class="compact-main"><strong>' + escape(investigation.title) + '</strong>',
      '<span>' + escape(investigation.id) + ' · ' + escape(relativeTime(investigation.updatedAt)) + '</span></span>',
      statusChip(investigation.status),
      '</button>',
    ].join('')).join('') + '</div>';
  }

  function renderLatestIndicators() {
    if (!refs.latestIndicators) return;
    const list = state.indicators.slice().sort((a, b) => {
      const scoreA = typeof a.score === 'number' ? a.score : -1;
      const scoreB = typeof b.score === 'number' ? b.score : -1;
      return scoreB - scoreA || (b.lastSeen || 0) - (a.lastSeen || 0);
    }).slice(0, 5);
    if (!list.length) {
      refs.latestIndicators.innerHTML = emptyState('i-globe', 'No indicators observed', 'Indicators are extracted from stored scans and manual analysis.', true);
      return;
    }
    refs.latestIndicators.innerHTML = '<div class="compact-list">' + list.map((indicator) => {
      const level = indicatorLevel(indicator.score);
      const tone = level ? level.key : 'unknown';
      return [
        '<button class="compact-row" data-open-indicator="' + escape(indicator.key) + '">',
        '<span class="compact-icon ' + tone + '">' + icon('i-target') + '</span>',
        '<span class="compact-main"><strong class="mono-value">' + escape(truncate(indicator.normalized, 48)) + '</strong>',
        '<span>' + escape(intel ? intel.typeLabel(indicator.type) : indicator.type) + ' · ' + escape(relativeTime(indicator.lastSeen)) + '</span></span>',
        '<span class="mini-score">' + (typeof indicator.score === 'number' ? indicator.score : 'UNKNOWN') + '</span>',
        '</button>',
      ].join('');
    }).join('') + '</div>';
  }

  /* ────────────────────────────────────────────────────────────────────────
     History page and scanner history list
     ──────────────────────────────────────────────────────────────────────── */

  function filteredHistory() {
    const query = String((refs.historySearch && refs.historySearch.value) || '').trim().toLowerCase();
    const type = refs.historyTypeFilter ? refs.historyTypeFilter.value : 'all';
    const severity = refs.historySeverityFilter ? refs.historySeverityFilter.value : 'all';
    return state.history.filter((report) => {
      const level = report.level && report.level.key ? report.level.key : levelFor(report.score).key;
      if (type !== 'all' && report.type !== type) return false;
      if (severity !== 'all' && level !== severity) return false;
      if (!query) return true;
      const haystack = [
        report.target, report.displayTarget, report.summary,
        report.level ? report.level.label : '', report.level ? report.level.short : '',
        typeLabel(report.type),
      ].join(' ').toLowerCase();
      return haystack.includes(query);
    });
  }

  function renderHistoryPage() {
    if (!refs.historyFullList) return;
    const rows = filteredHistory();
    if (refs.historyFullCount) refs.historyFullCount.textContent = rows.length + ' ' + plural(rows.length, 'scan');
    if (!state.history.length) {
      refs.historyFullList.innerHTML = '<tr><td colspan="7" class="table-empty">' +
        emptyState('i-history', 'No scans stored', 'Run a link, message or image analysis to build the local ledger.') +
        '</td></tr>';
      return;
    }
    if (!rows.length) {
      refs.historyFullList.innerHTML = '<tr><td colspan="7" class="table-empty">' +
        emptyState('i-search', 'No matching scans', 'Adjust the search text or filters.', true) +
        '</td></tr>';
      return;
    }
    refs.historyFullList.innerHTML = rows.map((report) => {
      const level = report.level && report.level.key ? report.level.key : levelFor(report.score).key;
      return [
        '<tr>',
        '<td><span class="type-badge">' + typeIcon(report.type) + escape(simpleTypeLabel(report.type)) + '</span></td>',
        '<td><span class="mono-value cell-target" title="' + escape(report.target) + '">' + escape(report.displayTarget || report.target || 'Untitled') + '</span></td>',
        '<td><span class="verdict-inline ' + level + '"><span></span>' + escape(report.level ? report.level.label : 'Low risk') + '</span></td>',
        '<td class="num">' + scoreText(report.score) + '</td>',
        '<td class="num">' + (typeof report.confidence === 'number' ? report.confidence + '%' : '—') + '</td>',
        '<td class="nowrap">' + escape(formatDateTime(report.timestamp)) + '</td>',
        '<td class="align-right"><div class="row-actions">',
        '<button class="ghost-button compact" data-open-scan="' + escape(report.id) + '">Open</button>',
        '<button class="ghost-button compact" data-report-html="' + escape(report.id) + '">Report</button>',
        '</div></td>',
        '</tr>',
      ].join('');
    }).join('');
  }

  function renderHistoryList() {
    updateCounters();
    if (!refs.historyList) return;
    if (!state.history.length) {
      refs.historyList.innerHTML = state.view === 'simple'
        ? '<div class="empty-history"><div class="empty-history-icon">' + icon('i-history') + '</div><div><strong>Nothing checked yet</strong><span>Your recent checks will appear here. They stay on this device.</span></div></div>'
        : '<div class="empty-history"><div class="empty-history-icon">' + icon('i-history') + '</div><div><strong>No analyses yet</strong><span>Your verdict history will appear here. Stored only on this device.</span></div></div>';
      return;
    }
    refs.historyList.innerHTML = state.history.slice(0, 6).map((report) => {
      const level = report.level && report.level.key ? report.level.key : levelFor(report.score).key;
      const target = report.displayTarget || report.target || 'Untitled source';
      const category = simpleTypeLabel(report.type);
      const meta = state.view === 'simple'
        ? category + '<span class="history-sep"></span>' + relativeTime(report.timestamp)
        : category + '<span class="history-sep"></span>' + relativeTime(report.timestamp) + '<span class="history-sep"></span>' + (report.confidence || 0) + '% confidence';
      const score = state.view === 'simple'
        ? '<span class="history-score ' + level + ' simple"><strong>' + verdictWord(level) + '</strong></span>'
        : '<span class="history-score ' + level + '"><strong>' + scoreText(report.score) + '</strong><span>' + escape(report.level ? report.level.short : 'LOW') + '</span></span>';
      return [
        '<button class="history-row" data-history-id="' + escape(report.id) + '" title="' + escape(target) + '">',
        '<span class="history-type-icon">' + typeIcon(report.type) + '</span>',
        '<span class="history-main"><strong>' + escape(target) + '</strong><span>' + meta + '</span></span>',
        score,
        '<span class="history-chevron">' + icon('i-chevron') + '</span>',
        '</button>',
      ].join('');
    }).join('');
  }

  function addReport(report) {
    state.history = [report].concat(state.history.filter((item) => item.id !== report.id)).slice(0, MAX_HISTORY);
    state.result = report;
    persistHistory();
    ingestReport(report);
    updateCounters();
    renderHistoryList();
    if (state.section === 'history') renderHistoryPage();
    if (state.section === 'overview') renderOverview();
    if (state.section === 'intel') renderIntelPage();
  }

  function openScan(id) {
    const report = state.history.find((item) => item.id === id);
    if (!report) {
      showToast('That scan is no longer in local storage.');
      return;
    }
    state.result = report;
    state.previewReportId = null;
    setMode(report.type);
    routeTo('scanner', { scroll: false });
    renderResult(report);
    setTimeout(() => {
      const consoleNode = document.getElementById('console');
      if (consoleNode) consoleNode.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 120);
    showToast('Loaded stored analysis');
  }

  /* ────────────────────────────────────────────────────────────────────────
     View, mode, inputs
     ──────────────────────────────────────────────────────────────────────── */

  function loadView() {
    return readText(VIEW_KEY, 'simple') === 'advanced' ? 'advanced' : 'simple';
  }

  function updateScanButtonLabel(scanning) {
    if (!refs.scanButtonText) return;
    if (scanning) {
      refs.scanButtonText.textContent = state.view === 'simple' ? 'Checking…' : 'Analyzing';
    } else {
      refs.scanButtonText.textContent = state.view === 'simple' ? 'Check it now' : 'Run deep scan';
    }
  }

  function setView(view, options) {
    const next = view === 'advanced' ? 'advanced' : 'simple';
    state.view = next;
    document.body.dataset.view = next;
    $$('[data-view-option]').forEach((button) => {
      const active = button.dataset.viewOption === next;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    try { localStorage.setItem(VIEW_KEY, next); } catch (_) { /* session only */ }
    updateScanButtonLabel(state.scanning);
    if (!state.scanning && state.result) renderResult(state.result);
    renderHistoryList();
    if (options && options.announce) {
      showToast(next === 'simple' ? 'Simple view · plain-language results' : 'Advanced view · full technical evidence');
    }
    if (next === 'advanced' && state.result && refs.verdictScroll) refs.verdictScroll.scrollTop = 0;
  }

  function setMode(mode, focus) {
    if (!['url', 'image', 'message'].includes(mode)) return;
    state.mode = mode;
    refs.tabs.forEach((tab) => {
      const active = tab.dataset.mode === mode;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', String(active));
    });
    refs.panels.forEach((panel) => panel.classList.toggle('active', panel.dataset.panel === mode));
    if (focus && state.section === 'scanner') {
      if (mode === 'url') setTimeout(() => refs.urlInput.focus(), 80);
      if (mode === 'message') setTimeout(() => refs.messageInput.focus(), 80);
    }
  }

  function updateInputState() {
    if (refs.urlInput && refs.clearUrl) refs.clearUrl.hidden = !refs.urlInput.value.trim();
    if (refs.messageInput && refs.charCount) refs.charCount.textContent = String(refs.messageInput.value.length);
  }

  /* ────────────────────────────────────────────────────────────────────────
     Toast, modal, confirm, sidebar
     ──────────────────────────────────────────────────────────────────────── */

  function showToast(message) {
    if (!refs.toast || !refs.toastText) return;
    refs.toastText.textContent = message;
    refs.toast.classList.add('visible');
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => refs.toast.classList.remove('visible'), 3200);
  }

  function openModal(config) {
    if (!refs.modalBackdrop) return;
    state.lastFocus = document.activeElement;
    state.modalConfirm = config.onConfirm || null;
    refs.modalTitle.textContent = config.title || 'Sentinel AI';
    refs.modalKicker.textContent = config.kicker || 'Sentinel AI';
    refs.modalBody.innerHTML = config.body || '';
    refs.modalFooter.innerHTML = config.footer || '<button class="modal-secondary" data-modal-close>Close</button>';
    refs.modalIcon.innerHTML = icon(config.icon || 'i-shield');
    refs.modalBackdrop.hidden = false;
    document.body.classList.add('modal-open');
    setTimeout(() => {
      const focusable = refs.modalBackdrop.querySelector('input, textarea, select, button');
      if (focusable) focusable.focus();
    }, 50);
  }

  function closeModal() {
    if (!refs.modalBackdrop) return;
    refs.modalBackdrop.hidden = true;
    document.body.classList.remove('modal-open');
    state.modalConfirm = null;
    if (state.lastFocus && typeof state.lastFocus.focus === 'function') state.lastFocus.focus();
  }

  function showConfirm(config) {
    openModal({
      kicker: config.kicker || 'Confirm action',
      title: config.title || 'Are you sure?',
      icon: config.icon || 'i-alert',
      body: config.body || '<p>This action cannot be undone.</p>',
      footer: [
        '<button class="modal-secondary" data-modal-close>Cancel</button>',
        '<button class="' + (config.danger === false ? 'modal-primary' : 'modal-danger') + '" data-modal-confirm>' + icon('i-trash') + escape(config.confirmLabel || 'Confirm') + '</button>',
      ].join(''),
      onConfirm: config.onConfirm,
    });
  }

  function openSidebar() {
    if (!refs.sidebar) return;
    state.sidebarOpen = true;
    refs.sidebar.classList.add('open');
    if (document.getElementById('mobileBackdrop')) return;
    const backdrop = document.createElement('div');
    backdrop.className = 'mobile-backdrop';
    backdrop.id = 'mobileBackdrop';
    backdrop.addEventListener('click', closeSidebar);
    document.body.appendChild(backdrop);
  }

  function closeSidebar() {
    state.sidebarOpen = false;
    if (refs.sidebar) refs.sidebar.classList.remove('open');
    const backdrop = document.getElementById('mobileBackdrop');
    if (backdrop) backdrop.remove();
  }

  /* ────────────────────────────────────────────────────────────────────────
     Settings & data controls
     ──────────────────────────────────────────────────────────────────────── */

  function renderSettings() {
    if (refs.settingsStorageSize) refs.settingsStorageSize.textContent = storageSizeLabel();
    if (!refs.settingsStorageCounts) return;
    const items = [
      { label: 'Scans', value: state.history.length, limit: MAX_HISTORY, iconId: 'i-radar' },
      { label: 'Investigations', value: state.investigations.length, limit: MAX_INVESTIGATIONS, iconId: 'i-shield' },
      { label: 'Indicators', value: state.indicators.length, limit: MAX_INDICATORS, iconId: 'i-globe' },
    ];
    refs.settingsStorageCounts.innerHTML = items.map((item) => [
      '<div class="storage-count">',
      '<span class="storage-count-icon">' + icon(item.iconId) + '</span>',
      '<div><strong>' + item.value + '</strong><span>' + escape(item.label) + ' · max ' + item.limit + '</span></div>',
      '</div>',
    ].join('')).join('');
  }

  function confirmClearData(kind) {
    const copy = {
      history: {
        title: 'Clear scan history?',
        body: '<p>This removes every stored scan from this browser. The indicator ledger and investigations stay unless cleared separately. This cannot be undone.</p>',
        confirmLabel: 'Clear history',
      },
      investigations: {
        title: 'Clear all investigations?',
        body: '<p>This removes every incident, analyst note and associated evidence snapshot stored in this browser. This cannot be undone.</p>',
        confirmLabel: 'Clear investigations',
      },
      indicators: {
        title: 'Clear the indicator ledger?',
        body: '<p>This removes all tracked indicator observations. Scan history remains, but indicators will not be re-imported automatically. This cannot be undone.</p>',
        confirmLabel: 'Clear indicators',
      },
      all: {
        title: 'Clear all local data?',
        body: '<p>This removes scan history, investigations, the indicator ledger, and saved view and section preferences from this browser. This cannot be undone.</p>',
        confirmLabel: 'Clear everything',
      },
    };
    const entry = copy[kind] || copy.all;
    showConfirm({
      kicker: 'Local data controls',
      title: entry.title,
      icon: 'i-trash',
      body: entry.body,
      confirmLabel: entry.confirmLabel,
      onConfirm: function () { clearLocalData(kind); },
    });
  }

  function clearLocalData(kind) {
    if (kind === 'history' || kind === 'all') {
      state.history = [];
      persistHistory();
    }
    if (kind === 'investigations' || kind === 'all') {
      state.investigations = [];
      state.activeInvestigation = null;
      persistInvestigations();
    }
    if (kind === 'indicators' || kind === 'all') {
      state.indicators = [];
      persistIndicators();
      writeStore(INDICATOR_SEED_KEY, true);
    }
    if (kind === 'all') {
      try {
        [STORAGE_KEY, INVESTIGATION_KEY, INDICATOR_KEY, INDICATOR_SEED_KEY, VIEW_KEY, SECTION_KEY].forEach((key) => localStorage.removeItem(key));
      } catch (_) { /* ignore */ }
      state.result = null;
      state.previewReportId = null;
      if (refs.verdictResult) refs.verdictResult.hidden = true;
      if (refs.verdictIdle) refs.verdictIdle.hidden = false;
      if (refs.verdictScanning) refs.verdictScanning.hidden = true;
      setVerdictState('', 'Ready');
    }
    updateCounters();
    renderHistoryList();
    if (state.section === 'overview') renderOverview();
    if (state.section === 'history') renderHistoryPage();
    if (state.section === 'intel') renderIntelPage();
    if (state.section === 'investigations') renderInvestigations();
    renderSettings();
    closeModal();
    showToast(kind === 'all' ? 'All local data cleared' : 'Local data updated');
  }

  /* ────────────────────────────────────────────────────────────────────────
     Scanner flow
     ──────────────────────────────────────────────────────────────────────── */

  function setVerdictState(kind, label) {
    if (!refs.verdictState) return;
    refs.verdictState.className = 'verdict-state' + (kind ? ' ' + kind : '');
    refs.verdictState.innerHTML = '<span></span> ' + escape(label);
  }

  function clearScanTimers() {
    state.scanTimers.forEach((timer) => clearTimeout(timer));
    state.scanTimers = [];
    if (state.scanInterval) {
      clearInterval(state.scanInterval);
      state.scanInterval = null;
    }
  }

  function animateScanning() {
    clearScanTimers();
    const steps = $$('.scan-step', refs.scanSteps);
    let current = 0;
    let progress = 8;
    refs.scanProgressBar.style.width = progress + '%';
    steps.forEach((step, index) => {
      step.classList.toggle('active', index === 0);
      step.classList.remove('done');
      const status = $('.step-status', step);
      if (status) status.textContent = index === 0 ? 'running' : 'queued';
    });
    state.scanInterval = setInterval(() => {
      if (current < steps.length - 1) {
        const step = steps[current];
        step.classList.remove('active');
        step.classList.add('done');
        const previousStatus = $('.step-status', step);
        if (previousStatus) previousStatus.textContent = 'complete';
        current += 1;
        steps[current].classList.add('active');
        const status = $('.step-status', steps[current]);
        if (status) status.textContent = 'running';
      }
      progress = Math.min(92, progress + 15 + Math.random() * 10);
      refs.scanProgressBar.style.width = Math.round(progress) + '%';
    }, 330);
  }

  function startScanning() {
    state.scanning = true;
    clearScanTimers();
    refs.scanButton.disabled = true;
    refs.scanButton.classList.add('is-loading');
    updateScanButtonLabel(true);
    refs.verdictIdle.hidden = true;
    refs.verdictResult.hidden = true;
    refs.verdictScanning.hidden = false;
    refs.verdictScroll.scrollTop = 0;
    setVerdictState('live', state.view === 'simple' ? 'Checking' : 'Scanning');
    const noun = state.mode === 'url' ? 'link' : state.mode === 'image' ? 'image' : 'message';
    refs.scanningTitle.textContent = state.view === 'simple'
      ? 'Checking this ' + (state.mode === 'image' ? 'photo' : noun)
      : 'Analyzing ' + noun;
    refs.scanningSubtitle.textContent = state.view === 'simple'
      ? state.mode === 'image'
        ? 'Looking at the file, hidden details, QR codes, and any text in the image.'
        : state.mode === 'message'
          ? 'Looking for pressure, fake requests, and dangerous links.'
          : 'Looking at the web address, the page path, and where it leads.'
      : state.mode === 'image'
        ? 'Inspecting file structure, metadata, QR payloads, and on-device OCR.'
        : state.mode === 'message'
          ? 'Mapping language patterns, intent, and embedded destinations.'
          : 'Inspecting structure, identity signals, and destination intent.';
    animateScanning();
  }

  function finishScanningUI() {
    state.scanning = false;
    clearScanTimers();
    refs.scanButton.disabled = false;
    refs.scanButton.classList.remove('is-loading');
    updateScanButtonLabel(false);
    refs.verdictScanning.hidden = true;
    refs.verdictResult.hidden = false;
  }

  function failScanning(message) {
    state.scanning = false;
    clearScanTimers();
    refs.scanButton.disabled = false;
    refs.scanButton.classList.remove('is-loading');
    updateScanButtonLabel(false);
    refs.verdictScanning.hidden = true;
    refs.verdictIdle.hidden = false;
    setVerdictState('', state.view === 'simple' ? 'Ready' : 'Standby');
    showToast(message);
  }

  async function runScan() {
    if (state.scanning) return;
    let input;
    if (state.mode === 'url') {
      input = refs.urlInput.value.trim();
      if (!input) {
        refs.urlField.classList.remove('shake');
        void refs.urlField.offsetWidth;
        refs.urlField.classList.add('shake');
        refs.urlInput.focus();
        showToast('Enter a link to analyze.');
        return;
      }
    } else if (state.mode === 'message') {
      input = refs.messageInput.value.trim();
      if (!input) {
        refs.messageInput.focus();
        showToast('Paste a message to analyze.');
        return;
      }
    } else if (!state.file) {
      refs.dropzone.focus();
      showToast('Choose or drop an image first.');
      return;
    }

    startScanning();
    const started = Date.now();
    const minimumWait = state.mode === 'image' ? 1650 : 1250;
    try {
      let report;
      if (state.mode === 'url') {
        report = engine.analyzeUrl(input);
      } else if (state.mode === 'message') {
        report = engine.analyzeMessage(input);
      } else {
        report = await engine.analyzeImage(state.file, {
          onProgress: function (progress, status) {
            if (status && /recogniz|loading|initializ/i.test(status)) {
              refs.scanningSubtitle.textContent = 'Optical analysis in progress · ' + Math.round(progress * 100) + '%';
            } else if (status) {
              refs.scanningSubtitle.textContent = status.charAt(0).toUpperCase() + status.slice(1) + ' · ' + Math.round(progress * 100) + '%';
            }
            if (progress > 0.2) refs.scanProgressBar.style.width = Math.max(35, Math.min(90, Math.round(progress * 88))) + '%';
          },
        });
      }

      const elapsed = Date.now() - started;
      if (elapsed < minimumWait) await new Promise((resolve) => setTimeout(resolve, minimumWait - elapsed));
      refs.scanProgressBar.style.width = '100%';
      await new Promise((resolve) => setTimeout(resolve, 260));
      state.previewReportId = report.type === 'image' ? report.id : null;
      addReport(report);
      renderResult(report);
      finishScanningUI();
      if (state.view === 'simple') {
        showToast(verdictWord(report.level.key) + ' · ' + simpleHeadline(report.level.key));
      } else {
        showToast((report.level ? report.level.label : 'Verdict ready') + ' · ' + report.score + '/100');
      }
    } catch (error) {
      failScanning(error && error.message ? error.message : 'Analysis could not be completed.');
    }
  }

  /* ────────────────────────────────────────────────────────────────────────
     Simple result
     ──────────────────────────────────────────────────────────────────────── */

  function friendlyReason(signal) {
    const id = signal.id || '';
    if (/^url-(lookalike|brand|punycode|unicode)$/.test(id)) return 'It pretends to be a company you know, but the web address is not theirs.';
    if (/^url-(userinfo|at-obfuscation)$/.test(id)) return 'The link is disguised to hide where it really goes.';
    if (/^url-(ip-literal|private-ip)$/.test(id)) return 'The link points to a numeric address, not a real company website.';
    if (/^url-(tld-high|tld-medium|free-host|shortener)$/.test(id)) return 'The web address has signs scammers often use to hide who they are.';
    if (/^url-(redirect|encoded|long|token)$/.test(id)) return 'The link is built to hide its real destination.';
    if (/^url-(credentials|keywords|combo)$/.test(id)) return 'It is set up to look like a login or verification page.';
    if (/^url-(executable|archive|double-extension|dangerous-protocol)$/.test(id)) return 'Opening it could download a harmful file or run unsafe code.';
    if (id === 'url-http') return 'The connection is not secure.';
    if (/^url-/.test(id)) return 'The web address has unusual details that scammers often use.';
    if (/^text-(seed-phrase|otp|credentials|personal-data)$/.test(id)) return 'It asks for private information like passwords, security codes, or ID details.';
    if (/^text-(gift-card|wire|crypto|wallet|payment-pressure)$/.test(id)) return 'It asks for money in a way scammers commonly use.';
    if (/^text-(executive-impersonation|impersonation|brand-combo)$/.test(id)) return 'Someone is pretending to be a boss or a trusted company.';
    if (/^text-(urgency|threat|fear-combo|account-takeover)$/.test(id)) return 'It tries to scare you or rush you into acting.';
    if (id === 'text-secrecy') return 'It asks you to keep the request secret.';
    if (/^text-(lottery|investment)$/.test(id)) return 'It promises a prize or easy money.';
    if (id === 'text-link-risk') return 'It contains a link that looks dangerous.';
    if (id === 'text-attachment') return 'It includes an attachment that could be harmful.';
    if (id === 'text-off-platform') return 'It wants to move the conversation somewhere less safe.';
    if (id === 'text-click-here') return 'It pushes you hard to click a link.';
    if (/^text-(generic-greeting|kindly|punctuation|caps|mixed-script)$/.test(id)) return 'The wording looks like a mass scam message.';
    if (/^text-/.test(id)) return 'The message uses language that scammers often use.';
    if (id === 'img-gps') return 'The photo contains location information.';
    if (/^img-(ai|editor)$/.test(id)) return 'This image may be AI-generated or heavily edited.';
    if (/^img-qr-/.test(id)) return 'The QR code leads to a risky destination.';
    if (id === 'img-ocr-risk') return 'The text inside the image reads like a phishing message.';
    if (/^img-(executable|trailing|script|svg-active)$/.test(id)) return 'The file contains hidden code or extra hidden data.';
    if (/^img-(mime-mismatch|mismatch)$/.test(id)) return 'The file is not the type it claims to be.';
    if (id === 'img-metadata-url') return 'Hidden web addresses were found inside the file.';
    if (id === 'img-svg-external') return 'The image loads content from an unknown source.';
    if (/^img-/.test(id)) return 'The file has unusual details that could be risky.';
    return 'We found activity that matches common scam or attack patterns.';
  }

  function friendlyReasons(report) {
    const seen = new Set();
    const out = [];
    (report.signals || []).forEach((signal) => {
      const reason = friendlyReason(signal);
      if (seen.has(reason)) return;
      seen.add(reason);
      out.push(reason);
    });
    return out.slice(0, 3);
  }

  function certaintyLabel(confidence) {
    if (confidence >= 90) return 'Very sure';
    if (confidence >= 80) return 'Fairly sure';
    return 'Somewhat sure';
  }

  function simpleActions(report) {
    const level = report.level ? report.level.key : 'low';
    const type = report.type;
    if (level === 'low') {
      return [
        'No action needed right now.',
        'Still be careful with anything you did not expect.',
        'When in doubt, check directly with the sender or company.',
      ];
    }
    if (type === 'url') {
      if (level === 'moderate') {
        return ['Do not click until you check it.', 'Find the company’s official website yourself and compare.', 'If it arrived unexpectedly, treat it as a scam.'];
      }
      return ['Do not click the link.', 'If you already clicked, do not enter any details or download anything.', 'Open the official app or type the company’s website address yourself.'];
    }
    if (type === 'image') {
      if (level === 'moderate') {
        return ['Do not act on anything in the image yet.', 'Check the sender or source another way.', 'Remove location data before sharing your own photos.'];
      }
      return ['Do not scan, open, or share anything in this image.', 'Delete it if it came from someone you do not know.', 'If it pretends to be a company, contact them through their official app.'];
    }
    if (level === 'moderate') {
      return ['Do not reply straight away.', 'Call the person or company using a number you already know.', 'Do not open links or attachments until it checks out.'];
    }
    return ['Do not reply, pay, or send codes.', 'Never share passwords, one-time codes, or recovery phrases.', 'Report the message and block the sender.'];
  }

  function resultActionsHtml(report) {
    return [
      '<div class="result-actions result-actions-wide">',
      '<button class="result-action primary" data-investigate-scan="' + escape(report.id) + '">' + icon('i-shield') + 'Investigation</button>',
      '<button class="result-action" data-report-print="' + escape(report.id) + '">' + icon('i-report') + 'Print report</button>',
      '<button class="result-action" data-report-html="' + escape(report.id) + '">' + icon('i-download') + 'Download HTML</button>',
      '<button class="result-action" data-copy-report="' + escape(report.id) + '">' + icon('i-copy') + 'Copy summary</button>',
      '</div>',
    ].join('');
  }

  function renderSimpleResult(report) {
    const level = report.level ? report.level.key : 'low';
    const word = verdictWord(level);
    const headline = simpleHeadline(level);
    const message = level === 'critical'
      ? 'This strongly matches known scams or attacks. Do not click, reply, pay, or share personal information.'
      : level === 'high'
        ? 'This has several warning signs of a scam or attack. Do not click, reply, pay, or share personal information.'
        : level === 'moderate'
          ? 'A few things look unusual. Do not enter details or send money until you check another way.'
          : 'We did not find the usual signs of a scam. That is not a guarantee, so still be careful with anything unexpected.';
    const reasons = friendlyReasons(report);
    const actions = simpleActions(report);
    const preview = report.type === 'image' && state.previewUrl && state.previewReportId === report.id
      ? '<div class="target-thumb"><img src="' + escape(state.previewUrl) + '" alt="" /></div>'
      : '<div class="target-icon">' + typeIcon(report.type) + '</div>';
    const verdictIcon = level === 'low' ? 'i-check' : level === 'moderate' ? 'i-alert' : 'i-shield';
    const reasonHtml = reasons.length
      ? '<ul class="simple-reasons">' + reasons.map((reason) => '<li><span></span><p>' + escape(reason) + '</p></li>').join('') + '</ul>'
      : '<ul class="simple-reasons"><li><span></span><p>No warning signs matched our checks.</p></li></ul>';
    const actionHtml = actions.map((action, index) => '<li><span class="simple-step">' + (index + 1) + '</span><p>' + escape(action) + '</p></li>').join('');

    refs.verdictResult.innerHTML = [
      '<div class="simple-result">',
      '<div class="result-topline"><span class="result-type">' + typeIcon(report.type) + ' ' + escape(simpleTypeLabel(report.type)) + ' check</span><span class="result-time">' + escape(relativeTime(report.timestamp)) + '</span></div>',
      '<div class="simple-verdict ' + level + '">',
      '<div class="simple-verdict-icon">' + icon(verdictIcon) + '</div>',
      '<span class="simple-verdict-word">' + word + '</span>',
      '<h3>' + escape(headline) + '</h3>',
      '<p>' + escape(message) + '</p>',
      '</div>',
      '<div class="result-target-card">' + preview + '<div class="target-copy"><span>What we checked</span><p title="' + escape(report.target) + '">' + escape(report.target) + '</p></div></div>',
      '<div class="simple-block"><h4>Why we think so</h4>' + reasonHtml + '</div>',
      '<div class="simple-block"><h4>What to do now</h4><ol class="simple-actions">' + actionHtml + '</ol></div>',
      '<div class="simple-certainty"><span>How sure are we?</span><strong>' + certaintyLabel(report.confidence) + '</strong></div>',
      resultActionsHtml(report),
      '<button class="simple-details" data-switch-advanced>See full technical details' + icon('i-arrow') + '</button>',
      '<p class="simple-disclaimer">This is an automatic check, not a guarantee. If money or passwords are involved, confirm through another channel.</p>',
      '</div>',
    ].join('');

    refs.verdictIdle.hidden = true;
    refs.verdictScanning.hidden = true;
    refs.verdictResult.hidden = false;
    setVerdictState(level === 'low' ? 'live' : level === 'moderate' ? 'warning' : 'alert', word);
    refs.verdictScroll.scrollTop = 0;
  }

  function renderResult(report) {
    if (!report) return;
    if (state.view === 'simple') renderSimpleResult(report);
    else renderAdvancedResult(report);
  }

  /* ────────────────────────────────────────────────────────────────────────
     Advanced result
     ──────────────────────────────────────────────────────────────────────── */

  function detailChips(report) {
    const details = report.details || {};
    const chips = [];
    if (report.type === 'url') {
      chips.push(['Domain', details.registrable || details.hostname || '—']);
      chips.push(['Protocol', details.scheme ? details.scheme.toUpperCase() : '—']);
      chips.push(['TLD', details.tld ? '.' + details.tld : '—']);
      chips.push(['Trusted domain', details.trusted ? 'Recognized' : 'Unverified']);
      if (details.redirectedTo) chips.push(['Redirects to', details.redirectedTo]);
    } else if (report.type === 'image') {
      chips.push(['File type', details.fileType || '—']);
      chips.push(['Dimensions', details.dimensions ? details.dimensions.width + ' × ' + details.dimensions.height : '—']);
      chips.push(['Metadata fields', String(details.metadataCount || 0)]);
      chips.push(['OCR', details.ocr ? (details.ocr.confidence || 0) + '% confidence' : details.ocrSupported ? 'No text found' : 'Unavailable']);
      chips.push(['QR payload', details.qr ? details.qr.payloadType || 'decoded' : 'None detected']);
      chips.push(['Trailing data', details.trailingBytes ? details.trailingBytes + ' bytes' : 'None']);
      if (details.hashes && details.hashes.sha256) chips.push(['SHA-256', details.hashes.sha256.slice(0, 24) + '…']);
    } else {
      chips.push(['Characters', String(details.rawLength || 0)]);
      chips.push(['Embedded links', String(details.linkCount || 0)]);
      chips.push(['Link risk', details.links && details.links.length ? details.links[0].score + '/100' : 'None']);
      chips.push(['Analysis scope', 'Language + links']);
    }
    chips.push(['Engine', report.engineVersion || '2.5.0']);
    return chips.map(([key, value]) => '<div class="detail-chip"><span>' + escape(key) + '</span><strong title="' + escape(value) + '">' + escape(value) + '</strong></div>').join('');
  }

  function detailDisclosure(report) {
    const details = report.details || {};
    let extra = '';
    if (report.type === 'image') {
      if (details.qr && details.qr.data) extra += '<pre class="detail-pre">QR PAYLOAD\n' + escape(details.qr.data) + '</pre>';
      if (details.ocr && details.ocr.text) extra += '<pre class="detail-pre">OCR TEXT\n' + escape(details.ocr.text.slice(0, 1200)) + '</pre>';
      if (details.metadata && Object.keys(details.metadata).length) {
        const metaText = Object.entries(details.metadata)
          .filter(([key]) => !key.startsWith('_'))
          .slice(0, 18)
          .map(([key, value]) => key + ': ' + (typeof value === 'object' ? JSON.stringify(value) : value))
          .join('\n');
        if (metaText) extra += '<pre class="detail-pre">METADATA\n' + escape(metaText) + '</pre>';
      }
    }
    if (report.type === 'message' && details.preview) {
      extra += '<pre class="detail-pre">MESSAGE PREVIEW\n' + escape(details.preview) + '</pre>';
    }
    if (!extra) return '';
    return '<details class="detail-disclosure"><summary>Source forensics</summary><div class="detail-body">' + extra + '</div></details>';
  }

  function extractedFor(report) {
    if (!intel) return [];
    try { return intel.extractIndicators(report); } catch (_) { return []; }
  }

  function renderAdvancedResult(report) {
    const level = report.level ? report.level.key : 'low';
    const color = riskColor(level);
    const circumference = 289;
    const offset = circumference - (Math.max(0, Math.min(100, report.score)) / 100) * circumference;
    const signals = report.signals || [];
    const categories = report.categories || [];
    const positives = report.positives || [];
    const recommendations = report.recommendations || [];
    const indicators = extractedFor(report).slice(0, 8);
    const preview = report.type === 'image' && state.previewUrl && state.previewReportId === report.id
      ? '<div class="target-thumb"><img src="' + escape(state.previewUrl) + '" alt="" /></div>'
      : '<div class="target-icon">' + typeIcon(report.type) + '</div>';
    const signalHtml = signals.slice(0, 8).map((signal, index) => [
      '<div class="signal-item sev-' + escape(signal.severity) + (index >= 3 ? ' extra' : '') + '">',
      '<span class="signal-index">' + String(index + 1).padStart(2, '0') + '</span>',
      '<div class="signal-copy"><strong>' + escape(signal.title) + '</strong><p>' + escape(signal.description) + '</p>',
      signal.evidence ? '<div class="signal-evidence mono-value">' + escape(truncate(signal.evidence, 180)) + '</div>' : '',
      '<div class="signal-foot"><span class="signal-tag">' + escape(signal.category) + '</span></div></div>',
      '<span class="signal-points">+' + signal.points + '</span>',
      '</div>',
    ].join('')).join('');
    const categoryHtml = categories.map((category) => {
      const catColor = category.score >= 70 ? '#ff5f70' : category.score >= 45 ? '#ff9257' : category.score >= 20 ? '#f5c451' : '#54e6ae';
      return '<div class="category-row" style="--cat-score:' + category.score + '%;--cat-color:' + catColor + '"><span class="category-label">' + escape(category.label) + '</span><div class="category-bar"><span></span></div><span class="category-value">' + category.score + '</span></div>';
    }).join('');
    const recHtml = recommendations.map((rec) => '<li>' + escape(rec) + '</li>').join('');
    const positiveHtml = positives.length
      ? '<div class="positive-list">' + positives.slice(0, 5).map((item) => '<span class="positive-chip">' + icon('i-check') + escape(item) + '</span>').join('') + '</div>'
      : '';
    const indicatorHtml = indicators.length
      ? '<div class="mini-indicator-list">' + indicators.map((indicator) => '<button class="mini-indicator" data-open-indicator="' + escape(indicator.key) + '"><span>' + escape(intel.typeLabel(indicator.type)) + '</span><strong class="mono-value">' + escape(truncate(indicator.normalized, 52)) + '</strong><span class="mini-score">' + (typeof indicator.score === 'number' ? indicator.score : 'UNKNOWN') + '</span></button>').join('') + '</div>'
      : '<p class="panel-note">No indicators were extracted from this source.</p>';
    const signalsFound = signals.length;
    const topCategories = categories.filter((cat) => cat.score > 0).length;

    refs.verdictResult.innerHTML = [
      '<div class="result-topline"><span class="result-type">' + typeIcon(report.type) + ' ' + escape(typeLabel(report.type)) + '</span><span class="result-time">' + escape(relativeTime(report.timestamp)) + '</span></div>',
      '<div class="result-target-card">' + preview + '<div class="target-copy"><span>Analyzed source</span><p title="' + escape(report.target) + '">' + escape(report.target) + '</p></div></div>',
      '<div class="result-score-row" style="--risk-color:' + color + '">',
      '<div class="score-ring" style="--risk-color:' + color + '"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="score-track" cx="50" cy="50" r="46"></circle><circle class="score-value" cx="50" cy="50" r="46" style="--score-offset:' + offset + '"></circle></svg><div class="score-inner"><strong>' + report.score + '</strong><span>/ 100</span></div></div>',
      '<div class="result-verdict-copy"><span class="risk-pill ' + level + '"><span></span>' + escape(report.level ? report.level.short : level.toUpperCase()) + ' risk</span><h3>' + escape(report.level ? report.level.label : 'Verdict ready') + '</h3><p>' + signalsFound + ' correlated signal' + (signalsFound === 1 ? '' : 's') + ' across ' + (topCategories || 0) + ' categor' + (topCategories === 1 ? 'y' : 'ies') + '.</p></div>',
      '</div>',
      '<div class="result-meta-grid"><div class="result-meta"><span>Model confidence</span><strong>' + report.confidence + '%</strong></div><div class="result-meta"><span>Signals detected</span><strong>' + signalsFound + ' / 47 layers</strong></div></div>',
      '<div class="ai-summary"><span>Sentinel assessment</span><p>' + escape(report.summary) + '</p></div>',
      signalsFound
        ? '<div class="result-section"><div class="section-head"><h4>Detection signals</h4><span>' + signalsFound + ' found</span></div><div class="signal-list" id="signalList">' + signalHtml + '</div>' + (signalsFound > 3 ? '<button class="show-more" data-show-more>Show ' + (signalsFound - 3) + ' more signals</button>' : '') + '</div>'
        : '<div class="result-section"><div class="section-head"><h4>Detection signals</h4><span>none found</span></div><div class="ai-summary" style="margin:0"><span>Clean structural analysis</span><p>No malicious indicators matched the current ruleset. Stay cautious with unsolicited sources.</p></div></div>',
      '<div class="result-section"><div class="section-head"><h4>Risk breakdown</h4><span>0–100</span></div><div class="category-list">' + categoryHtml + '</div></div>',
      positiveHtml ? '<div class="result-section"><div class="section-head"><h4>Trust signals</h4><span>' + positives.length + '</span></div>' + positiveHtml + '</div>' : '',
      '<div class="result-section"><div class="section-head"><h4>Extracted indicators</h4><span>' + indicators.length + ' shown</span></div>' + indicatorHtml + '</div>',
      '<div class="result-section"><div class="section-head"><h4>Recommended actions</h4><span>response</span></div><ol class="recommendation-list">' + recHtml + '</ol></div>',
      detailDisclosure(report),
      '<div class="result-section" style="margin-top:9px"><details class="detail-disclosure"><summary>Technical evidence</summary><div class="detail-body"><div class="detail-grid">' + detailChips(report) + '</div></div></details></div>',
      resultActionsHtml(report),
      '<div class="result-actions"><button class="result-action" data-report-json="' + escape(report.id) + '">' + icon('i-database') + 'Export JSON</button></div>',
      '<div class="result-footer"><span>' + escape(report.engine || 'Sentinel Heuristic Engine') + ' · ' + escape(report.engineVersion || '2.5.0') + '</span><span>rule-based · 100% local</span></div>',
    ].join('');

    refs.verdictIdle.hidden = true;
    refs.verdictScanning.hidden = true;
    refs.verdictResult.hidden = false;
    setVerdictState(level === 'low' ? 'live' : level === 'moderate' ? 'warning' : 'alert', report.level ? report.level.short : 'Low');
    refs.verdictScroll.scrollTop = 0;
  }

  /* ────────────────────────────────────────────────────────────────────────
     Reports
     ──────────────────────────────────────────────────────────────────────── */

  function getReport(id) {
    if (id) return state.history.find((item) => item.id === id) || (state.result && state.result.id === id ? state.result : null);
    return state.result;
  }

  function associatedInvestigation(report) {
    if (!report) return null;
    return state.investigations.find((investigation) => {
      if ((investigation.scanIds || []).includes(report.id)) return true;
      return (investigation.evidence || []).some((entry) => entry.scanId === report.id);
    }) || null;
  }

  function reportOptions(report) {
    return {
      indicators: extractedFor(report),
      investigation: associatedInvestigation(report),
    };
  }

  function reportAsText(report) {
    if (!report) return '';
    const indicators = extractedFor(report);
    const investigation = associatedInvestigation(report);
    const lines = [
      'SENTINEL AI — THREAT REPORT',
      '══════════════════════════════',
      'Report ID: ' + (reportBuilder ? reportBuilder.reportId(report) : report.id),
      'Source: ' + (report.displayTarget || report.target),
      'Type: ' + typeLabel(report.type),
      'Verdict: ' + (report.level ? report.level.label : 'Unclassified') + ' (' + report.score + '/100)',
      'Confidence: ' + report.confidence + '%',
      'Scanned: ' + formatDateTime(report.timestamp),
      '',
      'ASSESSMENT',
      report.summary,
      '',
      'DETECTION SIGNALS',
      ...(report.signals && report.signals.length
        ? report.signals.map((signal, index) => (index + 1) + '. [' + signal.severity.toUpperCase() + '] ' + signal.title + ' (+' + signal.points + ')\n   ' + signal.description)
        : ['None detected.']),
      '',
      'EXTRACTED INDICATORS',
      ...(indicators.length
        ? indicators.map((indicator) => '- [' + indicator.type.toUpperCase() + '] ' + indicator.normalized + (typeof indicator.score === 'number' ? ' · scan score ' + indicator.score + '/100' : ' · score UNKNOWN'))
        : ['None extracted.']),
      '',
      'RECOMMENDED ACTIONS',
      ...((report.recommendations || []).map((rec, index) => (index + 1) + '. ' + rec)),
      '',
      investigation
        ? 'INVESTIGATION\n' + investigation.id + ' · ' + investigation.title + '\nStatus: ' + investigation.status + ' · Severity: ' + String(investigation.severity || '').toUpperCase()
        : 'INVESTIGATION\nNot associated with an investigation.',
      '',
      'External reputation was not queried. UNKNOWN is not SAFE.',
      'Engine: ' + report.engine + ' ' + report.engineVersion + ' · Analysis performed locally.',
    ];
    return lines.join('\n');
  }

  async function copyReport(id) {
    const report = getReport(id);
    if (!report) return;
    const text = reportAsText(report);
    try {
      await navigator.clipboard.writeText(text);
      showToast('Report summary copied to clipboard');
    } catch (_) {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      textarea.remove();
      showToast('Report summary copied');
    }
  }

  function sanitisedExport(report) {
    const clone = JSON.parse(JSON.stringify(report));
    delete clone.displayTarget;
    if (clone.details) {
      delete clone.details.metadata;
      delete clone.details.imageEnd;
    }
    const investigation = associatedInvestigation(report);
    return {
      reportId: reportBuilder ? reportBuilder.reportId(report) : clone.id,
      generatedAt: new Date().toISOString(),
      dataLocation: 'This device only',
      type: clone.type,
      target: clone.target,
      score: clone.score,
      level: clone.level,
      confidence: clone.confidence,
      summary: clone.summary,
      signals: clone.signals,
      positives: clone.positives,
      categories: clone.categories,
      recommendations: clone.recommendations,
      details: clone.details,
      indicators: extractedFor(report).map((indicator) => ({
        type: indicator.type,
        normalized: indicator.normalized,
        category: indicator.category,
        score: typeof indicator.score === 'number' ? indicator.score : null,
        reputation: 'UNKNOWN',
      })),
      investigation: investigation ? {
        id: investigation.id,
        title: investigation.title,
        status: investigation.status,
        severity: investigation.severity,
        description: investigation.description,
        createdAt: investigation.createdAt,
        updatedAt: investigation.updatedAt,
        notes: investigation.notes,
      } : null,
      disclaimer: 'Local heuristic analysis. External reputation was not queried. A low score is not a guarantee of safety.',
    };
  }

  function downloadJson(id) {
    const report = getReport(id);
    if (!report) return;
    const blob = new Blob([JSON.stringify(sanitisedExport(report), null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'sentinel-' + report.type + '-' + new Date().toISOString().slice(0, 10) + '.json';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast('Sanitized JSON report exported');
  }

  function downloadHtmlReport(id) {
    const report = getReport(id);
    if (!report || !reportBuilder) return;
    try {
      const filename = reportBuilder.download(report, reportOptions(report));
      showToast('Report downloaded · ' + filename);
    } catch (error) {
      showToast(error && error.message ? error.message : 'Could not build the report.');
    }
  }

  function printReport(id) {
    const report = getReport(id);
    if (!report || !reportBuilder) return;
    try {
      reportBuilder.print(report, reportOptions(report));
      showToast('Opening the print dialog');
    } catch (error) {
      showToast(error && error.message ? error.message : 'Could not open the print view.');
    }
  }

  /* ────────────────────────────────────────────────────────────────────────
     File handling
     ──────────────────────────────────────────────────────────────────────── */

  function handleFile(file) {
    if (!file) return;
    if (!file.type.startsWith('image/') && !/\.(jpe?g|png|webp|gif|heic|heif|avif|tiff?|bmp|svg)$/i.test(file.name)) {
      showToast('Choose a supported image file.');
      return;
    }
    if (file.size > 40 * 1024 * 1024) {
      showToast('Image must be smaller than 40 MB.');
      return;
    }
    if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
    state.file = file;
    state.previewUrl = URL.createObjectURL(file);
    refs.previewImage.src = state.previewUrl;
    refs.fileName.textContent = file.name;
    const kb = file.size / 1024;
    const size = kb >= 1024 ? (kb / 1024).toFixed(1) + ' MB' : Math.max(1, Math.round(kb)) + ' KB';
    refs.fileDetails.textContent = size + ' · ' + (file.type || 'image');
    refs.filePreview.hidden = false;
    refs.dropzone.hidden = true;
    showToast('Image ready for local inspection');
  }

  function removeFile() {
    if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
    state.file = null;
    state.previewUrl = null;
    state.previewReportId = null;
    refs.imageInput.value = '';
    refs.previewImage.removeAttribute('src');
    refs.filePreview.hidden = true;
    refs.dropzone.hidden = false;
  }

  /* ────────────────────────────────────────────────────────────────────────
     Threat intelligence: indicator analysis
     ──────────────────────────────────────────────────────────────────────── */

  function renderIntelPage() {
    renderIndicatorLedger();
    renderGraph();
    updateCounters();
  }

  function renderIntelError(message) {
    if (!refs.intelResult) return;
    refs.intelResult.innerHTML = [
      '<div class="intel-error">',
      '<span class="intel-error-icon">' + icon('i-x-circle') + '</span>',
      '<div><strong>Could not analyze that value</strong><span>' + escape(message) + '</span></div>',
      '</div>',
    ].join('');
  }

  function manualIndicatorFromAnalysis(analysis) {
    if (!analysis || !analysis.type || !analysis.normalized) return null;
    const observedAt = analysis.analyzedAt || Date.now();
    return {
      id: intel.idFor(analysis.type, analysis.normalized),
      key: intel.keyFor(analysis.type, analysis.normalized),
      type: analysis.type,
      value: analysis.value || analysis.normalized,
      normalized: analysis.normalized,
      category: intel.categoryForType(analysis.type),
      score: typeof analysis.score === 'number' ? analysis.score : null,
      confidence: typeof analysis.confidence === 'number' ? analysis.confidence : null,
      sourceScanId: null,
      sourceScanType: 'manual',
      sourceTarget: 'Manual indicator analysis',
      sourceLevel: analysis.level ? analysis.level.key : null,
      evidence: 'Analyzed locally without any network request',
      observedAt: observedAt,
    };
  }

  function runIndicatorAnalysis(value) {
    if (!intel) return;
    const raw = String(value === undefined ? (refs.intelInput ? refs.intelInput.value : '') : value).trim();
    if (!raw) {
      renderIntelError('Enter an indicator to analyze.');
      if (refs.intelInput) refs.intelInput.focus();
      return;
    }
    if (refs.intelInput) refs.intelInput.value = raw;
    try {
      const analysis = intel.analyze(raw);
      state.intelAnalysis = analysis;
      renderIntelAnalysis(analysis);
      const item = manualIndicatorFromAnalysis(analysis);
      if (item) {
        mergeIndicators([item]);
        renderIndicatorLedger();
        renderGraph();
        updateCounters();
        if (state.section === 'overview') renderOverview();
      }
      showToast('Indicator analyzed locally · external reputation UNKNOWN');
    } catch (error) {
      state.intelAnalysis = null;
      renderIntelError(error && error.message ? error.message : 'That value could not be analyzed.');
    }
  }

  function renderIntelAnalysis(analysis) {
    if (!refs.intelResult || !analysis || !intel) return;
    const level = analysis.level;
    const tone = level ? level.key : 'unknown';
    const signals = analysis.signals || [];
    const signalHtml = signals.length
      ? '<div class="intel-signal-list">' + signals.map((signal) => [
          '<div class="intel-signal">',
          '<span class="severity-chip ' + escape(signal.severity) + '">' + escape(String(signal.severity || '').toUpperCase()) + '</span>',
          '<div><strong>' + escape(signal.title) + '</strong><p>' + escape(signal.description) + '</p></div>',
          '<span class="signal-points">+' + (signal.points || 0) + '</span>',
          '</div>',
        ].join('')).join('') + '</div>'
      : '<p class="panel-note">No local structural signals matched this value.</p>';
    const positives = (analysis.positives || []).length
      ? '<div class="positive-list">' + analysis.positives.map((item) => '<span class="positive-chip">' + icon('i-check') + escape(item) + '</span>').join('') + '</div>'
      : '';
    const recommendations = (analysis.recommendations || []).length
      ? '<ol class="recommendation-list">' + analysis.recommendations.map((item) => '<li>' + escape(item) + '</li>').join('') + '</ol>'
      : '<p class="panel-note">No specific actions were produced.</p>';
    const notes = (analysis.notes || []).length
      ? '<ul class="plain-list">' + analysis.notes.map((item) => '<li>' + escape(item) + '</li>').join('') + '</ul>'
      : '';
    const score = typeof analysis.score === 'number' ? analysis.score + '<span>/100</span>' : 'UNKNOWN';
    const confidence = typeof analysis.confidence === 'number' ? analysis.confidence + '%' : '—';

    refs.intelResult.innerHTML = [
      '<div class="intel-analysis">',
      '<div class="intel-analysis-head">',
      '<div><span class="type-badge intel-type">' + escape(intel.typeLabel(analysis.type)) + '</span><h3 class="mono-value break">' + escape(analysis.normalized) + '</h3></div>',
      '<div class="reputation-badge">' + icon('i-globe') + '<span>External reputation</span><strong>UNKNOWN</strong></div>',
      '</div>',
      '<div class="intel-stat-grid">',
      '<div class="intel-stat ' + tone + '"><span>Local score</span><strong>' + score + '</strong></div>',
      '<div class="intel-stat"><span>Local confidence</span><strong>' + confidence + '</strong></div>',
      '<div class="intel-stat"><span>Category</span><strong>' + escape(intel.categoryForType(analysis.type)) + '</strong></div>',
      '<div class="intel-stat"><span>Source</span><strong>Manual</strong></div>',
      '</div>',
      '<div class="ai-summary"><span>Local assessment</span><p>' + escape(analysis.summary) + '</p></div>',
      '<div class="intel-section"><div class="section-head"><h4>Structural signals</h4><span>' + signals.length + ' found</span></div>' + signalHtml + '</div>',
      positives ? '<div class="intel-section"><div class="section-head"><h4>Neutral or trust signals</h4><span>' + analysis.positives.length + '</span></div>' + positives + '</div>' : '',
      '<div class="intel-section"><div class="section-head"><h4>Recommended actions</h4><span>response</span></div>' + recommendations + '</div>',
      notes ? '<div class="intel-section"><div class="section-head"><h4>Analysis notes</h4><span>scope</span></div>' + notes + '</div>' : '',
      '<div class="intel-disclaimer">' + icon('i-alert') + '<span>' + escape(analysis.reputationNote || 'External reputation: UNKNOWN — no live reputation lookup was performed. Unknown is not safe.') + '</span></div>',
      '<div class="result-actions result-actions-wide">',
      '<button class="result-action primary" data-intel-to-inv>' + icon('i-shield') + 'Use in investigation</button>',
      '<button class="result-action" data-intel-reanalyze>' + icon('i-refresh') + 'Re-run analysis</button>',
      '<button class="result-action" data-copy-indicator>' + icon('i-copy') + 'Copy value</button>',
      '</div>',
      '</div>',
    ].join('');
  }

  function copyText(text, successMessage) {
    const value = String(text || '');
    if (!value) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(() => showToast(successMessage || 'Copied')).catch(() => fallbackCopy(value, successMessage));
    } else {
      fallbackCopy(value, successMessage);
    }
  }

  function fallbackCopy(value, successMessage) {
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try { document.execCommand('copy'); showToast(successMessage || 'Copied'); }
    catch (_) { showToast('Clipboard access is unavailable.'); }
    textarea.remove();
  }

  /* ────────────────────────────────────────────────────────────────────────
     Indicator ledger
     ──────────────────────────────────────────────────────────────────────── */

  function indicatorTypeName(type) {
    return intel ? intel.typeLabel(type) : type;
  }

  function renderIndicatorLedger() {
    if (!refs.indicatorList) return;
    const query = String((refs.indicatorSearch && refs.indicatorSearch.value) || '').trim().toLowerCase();
    const type = refs.indicatorTypeFilter ? refs.indicatorTypeFilter.value : 'all';
    const list = state.indicators.filter((indicator) => {
      if (type !== 'all' && indicator.type !== type) return false;
      if (!query) return true;
      return [indicator.normalized, indicator.value, indicator.category, indicatorTypeName(indicator.type)]
        .join(' ').toLowerCase().includes(query);
    });
    if (refs.indicatorCount) {
      refs.indicatorCount.textContent = list.length + ' of ' + state.indicators.length + ' ' + plural(state.indicators.length, 'indicator');
    }
    if (!state.indicators.length) {
      refs.indicatorList.innerHTML = emptyState('i-globe', 'The ledger is empty', 'Indicators are extracted automatically from scans and added when you analyze a value.');
      return;
    }
    if (!list.length) {
      refs.indicatorList.innerHTML = emptyState('i-search', 'No matching indicators', 'Adjust the search text or type filter.', true);
      return;
    }
    refs.indicatorList.innerHTML = list.map((indicator) => {
      const level = indicatorLevel(indicator.score);
      const tone = level ? level.key : 'unknown';
      return [
        '<button class="ledger-row type-' + escape(indicator.type) + '" data-indicator-key="' + escape(indicator.key) + '">',
        '<span class="ledger-type">' + icon('i-target') + '<span>' + escape(indicatorTypeName(indicator.type)) + '</span></span>',
        '<span class="ledger-main"><strong class="mono-value">' + escape(indicator.normalized) + '</strong><span>' + escape(indicator.category || 'Indicator') + ' · ' + (indicator.observations ? indicator.observations.length : 0) + ' ' + plural(indicator.observations ? indicator.observations.length : 0, 'observation') + ' · ' + escape(relativeTime(indicator.lastSeen)) + '</span></span>',
        '<span class="ledger-score ' + tone + '"><strong>' + (typeof indicator.score === 'number' ? indicator.score : 'UNKNOWN') + '</strong><span>' + (level ? level.short : 'unscored') + '</span></span>',
        '<span class="ledger-arrow">' + icon('i-chevron') + '</span>',
        '</button>',
      ].join('');
    }).join('');
  }

  function openIndicatorDetail(key) {
    const indicator = state.indicators.find((item) => item.key === key);
    if (!indicator) {
      showToast('That indicator is no longer tracked.');
      return;
    }
    const level = indicatorLevel(indicator.score);
    const observations = (indicator.observations || []).map((observation) => [
      '<div class="observation-row">',
      '<span>' + escape(observation.sourceTarget || 'Manual analysis') + '</span>',
      '<span>' + escape(formatDateTime(observation.observedAt)) + '</span>',
      '<span>' + (typeof observation.score === 'number' ? observation.score + '/100' : 'UNKNOWN') + '</span>',
      '</div>',
    ].join('')).join('');
    openModal({
      kicker: 'Indicator ledger',
      title: truncate(indicator.normalized, 90),
      icon: 'i-target',
      body: [
        '<div class="intel-stat-grid modal-stats">',
        '<div class="intel-stat ' + (level ? level.key : 'unknown') + '"><span>Highest local score</span><strong>' + (typeof indicator.score === 'number' ? indicator.score + '<span>/100</span>' : 'UNKNOWN') + '</strong></div>',
        '<div class="intel-stat"><span>External reputation</span><strong>UNKNOWN</strong></div>',
        '<div class="intel-stat"><span>Type</span><strong>' + escape(indicatorTypeName(indicator.type)) + '</strong></div>',
        '<div class="intel-stat"><span>Category</span><strong>' + escape(indicator.category || 'Indicator') + '</strong></div>',
        '</div>',
        '<div class="modal-kv"><span>Normalized value</span><strong class="mono-value break">' + escape(indicator.normalized) + '</strong></div>',
        '<div class="modal-kv"><span>First observed</span><strong>' + escape(formatDateTime(indicator.firstSeen)) + '</strong></div>',
        '<div class="modal-kv"><span>Last observed</span><strong>' + escape(formatDateTime(indicator.lastSeen)) + '</strong></div>',
        '<h3 class="modal-subhead">Observations</h3>',
        observations || '<p class="panel-note">No observation metadata is stored.</p>',
        '<p class="settings-note">External reputation was not queried. An unknown indicator is not a safe indicator.</p>',
      ].join(''),
      footer: '<button class="modal-secondary" data-modal-close>Close</button><button class="modal-primary" data-intel-detail-analyze="' + escape(indicator.key) + '">' + icon('i-refresh') + 'Analyze locally</button>',
    });
  }

  /* ────────────────────────────────────────────────────────────────────────
     Relationship graph (native SVG)
     ──────────────────────────────────────────────────────────────────────── */

  function graphNodeShort(value, length) {
    return truncate(value, length || 30);
  }

  function renderGraph() {
    if (!refs.graphStage || !intel) return;
    const data = intel.buildGraph(state.history, state.indicators);
    state.graphData = data;
    if (state.graphSelected && !data.nodes.some((node) => node.key === state.graphSelected)) state.graphSelected = null;
    if (refs.graphMeta) refs.graphMeta.textContent = data.nodes.length + ' ' + plural(data.nodes.length, 'node') + ' · ' + data.edges.length + ' ' + plural(data.edges.length, 'link');
    if (!data.nodes.length) {
      refs.graphStage.innerHTML = emptyState('i-graph', 'No relationship graph yet', 'The graph is built from real indicators in stored scans. Analyze or scan something first.');
      renderGraphDetails(null);
      return;
    }

    const nodeLookup = new Map(data.nodes.map((node) => [node.key, node]));
    const edges = data.edges.map((edge) => {
      const source = nodeLookup.get(edge.source);
      const target = nodeLookup.get(edge.target);
      if (!source || !target) return '';
      return '<line class="graph-edge" x1="' + source.x + '" y1="' + source.y + '" x2="' + target.x + '" y2="' + target.y + '"><title>' + escape(edge.label) + '</title></line>';
    }).join('');

    const nodes = data.nodes.map((node) => {
      const color = intel.typeColor(node.type);
      const selected = state.graphSelected === node.key ? ' selected' : '';
      const radius = Math.max(8, node.radius || 9);
      return [
        '<g class="graph-node type-' + escape(node.type) + selected + '" data-graph-node="' + escape(node.key) + '" tabindex="0" role="button" aria-label="' + escape(indicatorTypeName(node.type) + ': ' + node.value) + '">',
        '<title>' + escape(indicatorTypeName(node.type) + ' · ' + node.value) + '</title>',
        '<circle class="graph-node-halo" cx="' + node.x + '" cy="' + node.y + '" r="' + (radius + 6) + '" style="--node-color:' + color + '"></circle>',
        '<circle class="graph-node-dot" cx="' + node.x + '" cy="' + node.y + '" r="' + radius + '" style="--node-color:' + color + '"></circle>',
        '<text x="' + node.x + '" y="' + (node.y + radius + 14) + '" text-anchor="middle">' + escape(graphNodeShort(node.label)) + '</text>',
        '</g>',
      ].join('');
    }).join('');

    const edgeNote = data.edges.length ? '' : '<div class="graph-empty-note">Indicators are tracked, but no evidence-supported links exist yet.</div>';
    refs.graphStage.innerHTML = [
      '<svg class="threat-graph" viewBox="0 0 ' + data.width + ' ' + data.height + '" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Threat relationship graph with ' + data.nodes.length + ' nodes and ' + data.edges.length + ' links">',
      '<g class="graph-edges">' + edges + '</g>',
      '<g class="graph-nodes">' + nodes + '</g>',
      '</svg>',
      edgeNote,
    ].join('');
    renderGraphDetails(state.graphSelected);
  }

  function renderGraphDetails(key) {
    if (!refs.graphDetails) return;
    if (!key || !state.graphData) {
      refs.graphDetails.innerHTML = [
        '<span class="panel-kicker">Node inspector</span>',
        emptyState('i-graph', 'Select a node', 'Click any indicator in the graph to inspect its type, category, source evidence and local score.', true),
      ].join('');
      return;
    }
    const node = state.graphData.nodes.find((candidate) => candidate.key === key);
    if (!node) {
      refs.graphDetails.innerHTML = '<span class="panel-kicker">Node inspector</span>' + emptyState('i-graph', 'Select a node', 'Click any indicator in the graph to inspect its details.', true);
      return;
    }
    const level = indicatorLevel(node.score);
    const observations = ((node.meta && node.meta.observations) || []).slice(0, 5);
    const observationHtml = observations.length
      ? '<div class="observation-list">' + observations.map((observation) => '<div class="observation-row"><span>' + escape(observation.sourceTarget || 'Manual') + '</span><span>' + escape(formatDateTime(observation.observedAt)) + '</span><span>' + (typeof observation.score === 'number' ? observation.score + '/100' : 'UNKNOWN') + '</span></div>').join('') + '</div>'
      : '<p class="panel-note">No observation detail stored.</p>';
    refs.graphDetails.innerHTML = [
      '<span class="panel-kicker">Node inspector</span>',
      '<div class="graph-detail-head"><span class="type-badge">' + escape(indicatorTypeName(node.type)) + '</span><span class="graph-degree">' + node.degree + ' ' + plural(node.degree, 'link') + '</span></div>',
      '<strong class="mono-value break graph-detail-value">' + escape(node.value) + '</strong>',
      '<div class="intel-stat-grid graph-stats">',
      '<div class="intel-stat ' + (level ? level.key : 'unknown') + '"><span>Highest score</span><strong>' + (typeof node.score === 'number' ? node.score + '<span>/100</span>' : 'UNKNOWN') + '</strong></div>',
      '<div class="intel-stat"><span>Reputation</span><strong>UNKNOWN</strong></div>',
      '</div>',
      '<dl class="settings-list compact-settings">',
      '<div><dt>Category</dt><dd>' + escape(node.category || 'Indicator') + '</dd></div>',
      '<div><dt>First seen</dt><dd>' + escape(formatDateTime(node.meta && node.meta.firstSeen ? node.meta.firstSeen : node.lastSeen)) + '</dd></div>',
      '<div><dt>Last seen</dt><dd>' + escape(formatDateTime(node.lastSeen)) + '</dd></div>',
      '</dl>',
      '<h4 class="graph-detail-subhead">Evidence</h4>',
      observationHtml,
      '<button class="result-action primary full-width" data-graph-analyze="' + escape(node.key) + '">' + icon('i-target') + 'Analyze locally</button>',
    ].join('');
  }

  /* ────────────────────────────────────────────────────────────────────────
     Investigations
     ──────────────────────────────────────────────────────────────────────── */

  function nextIncidentId() {
    const year = new Date().getFullYear();
    const prefix = 'INC-' + year + '-';
    let highest = 0;
    state.investigations.forEach((investigation) => {
      const match = String(investigation.id || '').match(new RegExp('^' + prefix + '(\\d+)$'));
      if (match) highest = Math.max(highest, Number(match[1]));
    });
    return prefix + String(highest + 1).padStart(4, '0');
  }

  function evidenceSnapshot(report) {
    return {
      scanId: report.id,
      type: report.type,
      target: report.target,
      displayTarget: report.displayTarget || report.target,
      score: report.score,
      level: report.level ? { key: report.level.key, label: report.level.label, short: report.level.short } : levelFor(report.score),
      confidence: report.confidence,
      summary: report.summary,
      timestamp: report.timestamp,
      signals: (report.signals || []).slice(0, 14).map((signal) => ({
        id: signal.id,
        title: signal.title,
        description: signal.description,
        severity: signal.severity,
        points: signal.points,
        category: signal.category,
        evidence: signal.evidence,
      })),
      recommendations: (report.recommendations || []).slice(0, 8),
      categories: (report.categories || []).filter((category) => category.score > 0).map((category) => ({
        key: category.key, label: category.label, score: category.score,
      })),
    };
  }

  function indicatorReference(indicator) {
    return {
      key: indicator.key || intel.keyFor(indicator.type, indicator.normalized),
      type: indicator.type,
      normalized: indicator.normalized,
      category: indicator.category || intel.categoryForType(indicator.type),
      score: typeof indicator.score === 'number' ? indicator.score : null,
      confidence: typeof indicator.confidence === 'number' ? indicator.confidence : null,
      sourceScanId: indicator.sourceScanId || null,
      evidence: indicator.evidence || '',
    };
  }

  function attachScanToInvestigation(investigation, report) {
    if (!report) return;
    if (!investigation.scanIds.includes(report.id)) investigation.scanIds.push(report.id);
    if (!investigation.evidence.some((entry) => entry.scanId === report.id)) {
      investigation.evidence.unshift(evidenceSnapshot(report));
    }
    extractedFor(report).forEach((indicator) => {
      const reference = indicatorReference(indicator);
      if (!investigation.indicators.some((item) => item.key === reference.key)) {
        investigation.indicators.push(reference);
      }
    });
  }

  function openInvestigationForm(scanId, prefill) {
    const report = scanId ? state.history.find((item) => item.id === scanId) : null;
    const analysis = prefill && prefill.indicator ? prefill.indicator : null;
    state.pendingIndicatorAnalysis = analysis;
    const level = report ? (report.level ? report.level.key : levelFor(report.score).key) : analysis && analysis.level ? analysis.level.key : 'moderate';
    const title = report
      ? 'Investigate ' + truncate(report.displayTarget || report.target, 80)
      : analysis
        ? 'Investigate indicator ' + truncate(analysis.normalized, 58)
        : '';
    const description = report ? report.summary : analysis ? analysis.summary : '';
    const scanOptions = ['<option value="">No associated scan</option>'].concat(state.history.map((item) => {
      const selected = report && report.id === item.id ? ' selected' : '';
      return '<option value="' + escape(item.id) + '"' + selected + '>' + escape(truncate((item.displayTarget || item.target) + ' · ' + item.score + '/100', 84)) + '</option>';
    })).join('');
    const severityOptions = SEVERITIES.map((key) => '<option value="' + key + '"' + (key === level ? ' selected' : '') + '>' + key.charAt(0).toUpperCase() + key.slice(1) + '</option>').join('');
    const statusOptions = STATUSES.map((status) => '<option value="' + status + '"' + (status === 'Open' ? ' selected' : '') + '>' + status + '</option>').join('');

    openModal({
      kicker: 'Incident workspace',
      title: 'New investigation',
      icon: 'i-shield',
      body: [
        '<div class="form-grid">',
        '<label class="form-field form-full"><span>Title</span><input id="invTitle" type="text" maxlength="140" autocomplete="off" placeholder="Brief description of the incident" value="' + escape(title) + '" /></label>',
        '<label class="form-field"><span>Severity</span><select id="invSeverity">' + severityOptions + '</select></label>',
        '<label class="form-field"><span>Initial status</span><select id="invStatus">' + statusOptions + '</select></label>',
        '<label class="form-field form-full"><span>Associated scan (optional)</span><select id="invScan">' + scanOptions + '</select></label>',
        '<label class="form-field form-full"><span>Description</span><textarea id="invDescription" rows="4" maxlength="5000" placeholder="What happened, what was observed, and what needs verification">' + escape(description) + '</textarea></label>',
        '<label class="form-field form-full"><span>Additional indicator (optional)</span><input id="invIndicator" type="text" maxlength="4096" autocomplete="off" spellcheck="false" placeholder="URL, domain, IP, email, hash or suspicious filename" value="' + escape(analysis ? analysis.normalized : '') + '" /></label>',
        '</div>',
        '<p class="form-note">' + icon('i-lock') + 'Scan indicators and an evidence snapshot are imported automatically. All investigation data stays in this browser.</p>',
      ].join(''),
      footer: '<button class="modal-secondary" data-modal-close>Cancel</button><button class="modal-primary" data-inv-create>' + icon('i-plus') + 'Create investigation</button>',
    });
  }

  function createInvestigationFromForm() {
    const titleInput = $('#invTitle');
    const severityInput = $('#invSeverity');
    const statusInput = $('#invStatus');
    const scanInput = $('#invScan');
    const descriptionInput = $('#invDescription');
    const indicatorInput = $('#invIndicator');
    const title = titleInput ? titleInput.value.trim() : '';
    if (!title) {
      showToast('Enter an investigation title.');
      if (titleInput) titleInput.focus();
      return;
    }
    const now = Date.now();
    const investigation = {
      id: nextIncidentId(),
      title: title.slice(0, 140),
      severity: SEVERITIES.includes(severityInput ? severityInput.value : '') ? severityInput.value : 'moderate',
      status: STATUSES.includes(statusInput ? statusInput.value : '') ? statusInput.value : 'Open',
      description: (descriptionInput ? descriptionInput.value : '').trim().slice(0, 5000),
      createdAt: now,
      updatedAt: now,
      resolvedAt: null,
      scanIds: [],
      evidence: [],
      indicators: [],
      notes: [],
      timeline: [{ type: 'created', at: now, label: 'Investigation created' }],
    };

    if (scanInput && scanInput.value) {
      const report = state.history.find((item) => item.id === scanInput.value);
      attachScanToInvestigation(investigation, report);
    }

    if (indicatorInput && indicatorInput.value.trim()) {
      const raw = indicatorInput.value.trim();
      const type = intel ? intel.detectType(raw) : null;
      if (!type) {
        showToast('That indicator type could not be identified. Use a URL, domain, IP, email, hash or filename.');
        indicatorInput.focus();
        return;
      }
      const normalized = intel.normalize(type, raw);
      const prefill = state.pendingIndicatorAnalysis;
      const matchesPrefill = prefill && prefill.normalized === normalized;
      const reference = {
        key: intel.keyFor(type, normalized),
        type: type,
        normalized: normalized,
        category: intel.categoryForType(type),
        score: matchesPrefill && typeof prefill.score === 'number' ? prefill.score : null,
        confidence: matchesPrefill && typeof prefill.confidence === 'number' ? prefill.confidence : null,
        sourceScanId: null,
        evidence: 'Added manually to this investigation',
      };
      if (!investigation.indicators.some((item) => item.key === reference.key)) investigation.indicators.push(reference);
      mergeIndicators([{
        id: intel.idFor(type, normalized),
        key: reference.key,
        type: type,
        value: raw,
        normalized: normalized,
        category: reference.category,
        score: reference.score,
        confidence: reference.confidence,
        sourceScanId: null,
        sourceScanType: 'manual',
        sourceTarget: 'Investigation ' + investigation.id,
        sourceLevel: reference.score === null ? null : levelFor(reference.score).key,
        evidence: reference.evidence,
        observedAt: now,
      }]);
    }

    state.pendingIndicatorAnalysis = null;
    state.investigations.unshift(investigation);
    state.investigations = state.investigations.slice(0, MAX_INVESTIGATIONS);
    state.activeInvestigation = investigation.id;
    persistInvestigations();
    persistIndicators();
    closeModal();
    routeTo('investigations', { scroll: false });
    renderInvestigations();
    showToast('Investigation ' + investigation.id + ' created');
  }

  function openInvestigation(id) {
    const investigation = state.investigations.find((item) => item.id === id);
    if (!investigation) {
      showToast('That investigation no longer exists.');
      return;
    }
    state.activeInvestigation = investigation.id;
    routeTo('investigations');
  }

  function renderInvestigations() {
    if (!refs.investigationListView || !refs.investigationDetailView) return;
    const investigation = state.activeInvestigation
      ? state.investigations.find((item) => item.id === state.activeInvestigation)
      : null;
    if (investigation) {
      refs.investigationListView.hidden = true;
      refs.investigationDetailView.hidden = false;
      renderInvestigationDetail(investigation);
    } else {
      state.activeInvestigation = null;
      refs.investigationListView.hidden = false;
      refs.investigationDetailView.hidden = true;
      renderInvestigationSummary();
      renderInvestigationList();
    }
    updateCounters();
  }

  function renderInvestigationSummary() {
    if (!refs.investigationSummary) return;
    const counts = { Open: 0, Investigating: 0, Contained: 0, Resolved: 0 };
    state.investigations.forEach((investigation) => {
      if (counts[investigation.status] !== undefined) counts[investigation.status] += 1;
    });
    refs.investigationSummary.innerHTML = STATUSES.map((status) => [
      '<div class="inv-summary-card ' + status.toLowerCase() + '">',
      '<span>' + status + '</span><strong>' + counts[status] + '</strong>',
      '</div>',
    ].join('')).join('');
  }

  function renderInvestigationList() {
    if (!refs.investigationList) return;
    const query = String((refs.invSearch && refs.invSearch.value) || '').trim().toLowerCase();
    const status = refs.invStatusFilter ? refs.invStatusFilter.value : 'all';
    const severity = refs.invSeverityFilter ? refs.invSeverityFilter.value : 'all';
    const list = state.investigations.filter((investigation) => {
      if (status !== 'all' && investigation.status !== status) return false;
      if (severity !== 'all' && investigation.severity !== severity) return false;
      if (!query) return true;
      return [investigation.title, investigation.id, investigation.description, investigation.status]
        .join(' ').toLowerCase().includes(query);
    }).sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
    if (refs.investigationCount) refs.investigationCount.textContent = list.length + ' of ' + state.investigations.length + ' ' + plural(state.investigations.length, 'investigation');
    if (!state.investigations.length) {
      refs.investigationList.innerHTML = emptyState('i-shield', 'No investigations yet', 'Create an investigation from a scan result, or start one here and attach evidence later.');
      return;
    }
    if (!list.length) {
      refs.investigationList.innerHTML = emptyState('i-search', 'No matching investigations', 'Adjust the search text, status or severity filter.', true);
      return;
    }
    refs.investigationList.innerHTML = list.map((investigation) => [
      '<button class="inv-card" data-open-inv="' + escape(investigation.id) + '">',
      '<div class="inv-card-top"><span class="incident-id">' + escape(investigation.id) + '</span>' + statusChip(investigation.status) + '</div>',
      '<strong>' + escape(investigation.title) + '</strong>',
      '<p>' + escape(truncate(investigation.description || 'No description recorded.', 150)) + '</p>',
      '<div class="inv-card-meta">' + severityChip(investigation.severity) +
        '<span>' + (investigation.indicators || []).length + ' ' + plural((investigation.indicators || []).length, 'indicator') + '</span>' +
        '<span>' + (investigation.scanIds || []).length + ' ' + plural((investigation.scanIds || []).length, 'scan') + '</span>' +
        '<span>Updated ' + escape(relativeTime(investigation.updatedAt)) + '</span></div>',
      '</button>',
    ].join('')).join('');
  }

  function renderInvestigationDetail(investigation) {
    if (!refs.investigationDetailView) return;
    const scanIds = investigation.scanIds || [];
    const indicators = investigation.indicators || [];
    const evidence = investigation.evidence || [];
    const notes = (investigation.notes || []).slice().sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    const timeline = (investigation.timeline || []).slice().sort((a, b) => (b.at || 0) - (a.at || 0)).slice(0, 8);
    const statusOptions = STATUSES.map((status) => '<option value="' + status + '"' + (status === investigation.status ? ' selected' : '') + '>' + status + '</option>').join('');

    const indicatorRows = indicators.length
      ? '<div class="inv-indicator-list">' + indicators.map((indicator) => [
          '<div class="inv-indicator-row">',
          '<span class="type-badge">' + escape(indicatorTypeName(indicator.type)) + '</span>',
          '<span class="mono-value break">' + escape(indicator.normalized) + '</span>',
          '<span class="mini-score">' + (typeof indicator.score === 'number' ? indicator.score : 'UNKNOWN') + '</span>',
          '<button class="icon-button tiny" data-remove-inv-indicator="' + escape(indicator.key) + '" aria-label="Remove indicator" title="Remove from investigation">' + icon('i-close') + '</button>',
          '</div>',
        ].join('')).join('') + '</div>'
      : '<p class="panel-note">No indicators are associated with this investigation yet.</p>';

    const evidenceHtml = evidence.length
      ? evidence.map((entry) => {
          const canOpen = state.history.some((report) => report.id === entry.scanId);
          const level = entry.level && entry.level.key ? entry.level.key : levelFor(entry.score || 0).key;
          return [
            '<div class="evidence-card">',
            '<div class="evidence-head"><span class="compact-icon ' + level + '">' + typeIcon(entry.type) + '</span><div><strong>' + escape(entry.displayTarget || entry.target || 'Stored scan') + '</strong><span>' + escape(formatDateTime(entry.timestamp)) + ' · ' + escape(typeLabel(entry.type)) + '</span></div>' + reportScoreBadge(entry) + '</div>',
            '<p>' + escape(entry.summary || 'No assessment summary stored.') + '</p>',
            entry.signals && entry.signals.length
              ? '<details class="evidence-signals"><summary>Original signals · ' + entry.signals.length + '</summary><ul>' + entry.signals.slice(0, 8).map((signal) => '<li>' + severityChip(signal.severity) + '<span><strong>' + escape(signal.title) + '</strong><span>' + escape(signal.description) + '</span></span></li>').join('') + '</ul></details>'
              : '<p class="panel-note">No detection signals were stored with this evidence.</p>',
            '<div class="evidence-actions">',
            canOpen
              ? '<button class="ghost-button compact" data-open-scan="' + escape(entry.scanId) + '">' + icon('i-eye') + 'Open original scan</button><button class="ghost-button compact" data-report-html="' + escape(entry.scanId) + '">' + icon('i-download') + 'Report</button>'
              : '<span class="evidence-note">' + icon('i-database') + 'Stored snapshot · original scan no longer in history</span>',
            '</div>',
            '</div>',
          ].join('');
        }).join('')
      : '<p class="panel-note">No scan evidence is attached. Create an investigation from a scan result to capture it automatically.</p>';

    const notesHtml = notes.length
      ? '<div class="note-list">' + notes.map((note) => '<div class="note-item"><span class="note-time">' + escape(formatDateTime(note.createdAt)) + '</span><p>' + escape(note.text) + '</p></div>').join('') + '</div>'
      : '<p class="panel-note">No analyst notes recorded yet.</p>';

    const timelineHtml = timeline.length
      ? '<ul class="timeline">' + timeline.map((entry) => '<li><span class="timeline-dot"></span><div><strong>' + escape(entry.label) + '</strong><span>' + escape(formatDateTime(entry.at)) + '</span></div></li>').join('') + '</ul>'
      : '';

    refs.investigationDetailView.innerHTML = [
      '<div class="inv-detail">',
      '<div class="inv-detail-head">',
      '<button class="ghost-button" data-inv-back>' + icon('i-back') + 'All investigations</button>',
      '<div class="inv-detail-title"><div class="inv-detail-kicker"><span class="incident-id">' + escape(investigation.id) + '</span>' + severityChip(investigation.severity) + statusChip(investigation.status) + '</div><h1>' + escape(investigation.title) + '</h1><p>Opened ' + escape(formatDateTime(investigation.createdAt)) + ' · Updated ' + escape(formatDateTime(investigation.updatedAt)) + (investigation.resolvedAt ? ' · Resolved ' + escape(formatDateTime(investigation.resolvedAt)) : '') + '</p></div>',
      '<div class="inv-detail-actions"><select class="select-field" data-inv-status="' + escape(investigation.id) + '" aria-label="Update investigation status">' + statusOptions + '</select>' + (investigation.status !== 'Resolved' ? '<button class="primary-button compact" data-inv-resolve="' + escape(investigation.id) + '">' + icon('i-check-circle') + 'Resolve</button>' : '') + '<button class="danger-outline compact" data-inv-delete="' + escape(investigation.id) + '">' + icon('i-trash') + 'Delete</button></div>',
      '</div>',
      '<div class="inv-detail-grid">',
      '<section class="panel inv-panel">',
      '<div class="panel-head"><div><span class="panel-kicker">Case summary</span><h2>Description &amp; activity</h2></div></div>',
      '<div class="inv-panel-body"><p class="inv-description">' + escape(investigation.description || 'No description was recorded.') + '</p>' + timelineHtml + '</div>',
      '</section>',
      '<section class="panel inv-panel">',
      '<div class="panel-head"><div><span class="panel-kicker">' + indicators.length + ' tracked</span><h2>Associated indicators</h2></div></div>',
      '<div class="inv-panel-body">' + indicatorRows,
      '<div class="inline-form"><input id="invIndicatorInput" type="text" maxlength="4096" autocomplete="off" spellcheck="false" placeholder="Add URL, domain, IP, email, hash or filename" aria-label="Add indicator to investigation" /><button class="primary-button compact" data-add-inv-indicator="' + escape(investigation.id) + '">' + icon('i-plus') + 'Add</button></div>',
      '</div>',
      '</section>',
      '<section class="panel inv-panel inv-wide">',
      '<div class="panel-head"><div><span class="panel-kicker">Original evidence</span><h2>Associated scans</h2></div><span class="panel-count">' + evidence.length + ' ' + plural(evidence.length, 'snapshot') + '</span></div>',
      '<div class="inv-panel-body">' + evidenceHtml + '</div>',
      '</section>',
      '<section class="panel inv-panel inv-wide">',
      '<div class="panel-head"><div><span class="panel-kicker">Analyst record</span><h2>Notes</h2></div><span class="panel-count">' + notes.length + ' ' + plural(notes.length, 'note') + '</span></div>',
      '<div class="inv-panel-body"><div class="note-form"><textarea id="invNoteInput" rows="3" maxlength="5000" placeholder="Record findings, decisions, containment steps or verification results" aria-label="Investigation note"></textarea><div class="note-form-footer"><span>' + icon('i-lock') + 'Stored on this device</span><button class="primary-button compact" data-add-note="' + escape(investigation.id) + '">' + icon('i-note') + 'Add note</button></div></div>' + notesHtml + '</div>',
      '</section>',
      '</div>',
      '</div>',
    ].join('');
  }

  function setInvestigationStatus(id, status) {
    if (!STATUSES.includes(status)) return;
    const investigation = state.investigations.find((item) => item.id === id);
    if (!investigation) return;
    if (investigation.status === status) return;
    const now = Date.now();
    investigation.status = status;
    investigation.updatedAt = now;
    if (status === 'Resolved') investigation.resolvedAt = now;
    else delete investigation.resolvedAt;
    investigation.timeline = investigation.timeline || [];
    investigation.timeline.push({ type: 'status', at: now, label: 'Status changed to ' + status });
    persistInvestigations();
    renderInvestigations();
    if (state.section === 'overview') renderOverview();
    showToast(investigation.id + ' · ' + status);
  }

  function addInvestigationNote(id) {
    const investigation = state.investigations.find((item) => item.id === id);
    if (!investigation) return;
    const textarea = $('#invNoteInput');
    const text = textarea ? textarea.value.trim() : '';
    if (!text) {
      showToast('Write a note before saving.');
      if (textarea) textarea.focus();
      return;
    }
    const now = Date.now();
    investigation.notes = investigation.notes || [];
    investigation.notes.push({ id: 'note-' + now.toString(36), text: text.slice(0, 5000), createdAt: now, author: 'Local analyst' });
    investigation.updatedAt = now;
    investigation.timeline = investigation.timeline || [];
    investigation.timeline.push({ type: 'note', at: now, label: 'Analyst note added' });
    persistInvestigations();
    renderInvestigationDetail(investigation);
    renderInvestigationList();
    showToast('Note added to ' + investigation.id);
  }

  function addIndicatorToInvestigation(id) {
    const investigation = state.investigations.find((item) => item.id === id);
    if (!investigation) return;
    const input = $('#invIndicatorInput');
    const raw = input ? input.value.trim() : '';
    if (!raw) {
      showToast('Enter an indicator to add.');
      if (input) input.focus();
      return;
    }
    const type = intel ? intel.detectType(raw) : null;
    if (!type) {
      showToast('Indicator type not recognized. Use a URL, domain, IP, email, hash or filename.');
      if (input) input.focus();
      return;
    }
    const normalized = intel.normalize(type, raw);
    const key = intel.keyFor(type, normalized);
    if (investigation.indicators.some((item) => item.key === key)) {
      showToast('That indicator is already associated.');
      return;
    }
    const now = Date.now();
    const reference = {
      key: key,
      type: type,
      normalized: normalized,
      category: intel.categoryForType(type),
      score: null,
      confidence: null,
      sourceScanId: null,
      evidence: 'Added manually to this investigation',
    };
    investigation.indicators.push(reference);
    investigation.updatedAt = now;
    investigation.timeline = investigation.timeline || [];
    investigation.timeline.push({ type: 'indicator', at: now, label: 'Indicator added: ' + truncate(normalized, 60) });
    mergeIndicators([{
      id: intel.idFor(type, normalized),
      key: key,
      type: type,
      value: raw,
      normalized: normalized,
      category: reference.category,
      score: null,
      confidence: null,
      sourceScanId: null,
      sourceScanType: 'manual',
      sourceTarget: 'Investigation ' + investigation.id,
      sourceLevel: null,
      evidence: reference.evidence,
      observedAt: now,
    }]);
    persistInvestigations();
    persistIndicators();
    renderInvestigationDetail(investigation);
    showToast('Indicator added to ' + investigation.id);
  }

  function removeIndicatorFromInvestigation(investigationId, key) {
    const investigation = state.investigations.find((item) => item.id === investigationId);
    if (!investigation) return;
    const before = (investigation.indicators || []).length;
    investigation.indicators = (investigation.indicators || []).filter((indicator) => indicator.key !== key);
    if (investigation.indicators.length === before) return;
    investigation.updatedAt = Date.now();
    persistInvestigations();
    renderInvestigationDetail(investigation);
    showToast('Indicator removed from investigation');
  }

  function confirmDeleteInvestigation(id) {
    const investigation = state.investigations.find((item) => item.id === id);
    if (!investigation) return;
    showConfirm({
      kicker: 'Delete investigation',
      title: 'Delete ' + investigation.id + '?',
      icon: 'i-trash',
      body: '<p>This removes the investigation, its notes and its stored evidence snapshots from this browser. The original scan history and indicator ledger are not affected. This cannot be undone.</p>',
      confirmLabel: 'Delete investigation',
      onConfirm: function () {
        state.investigations = state.investigations.filter((item) => item.id !== id);
        state.activeInvestigation = null;
        persistInvestigations();
        renderInvestigations();
        if (state.section === 'overview') renderOverview();
        showToast('Investigation deleted');
      },
    });
  }

  /* ────────────────────────────────────────────────────────────────────────
     Analytics / detection test centre
     ──────────────────────────────────────────────────────────────────────── */

  function renderAnalytics() {
    if (state.testRunning) return;
    if (!state.testResults.length) {
      if (refs.analyticsSummary) refs.analyticsSummary.innerHTML = '';
      if (refs.analyticsResults) refs.analyticsResults.innerHTML = emptyState('i-play', 'Test suite has not run', 'Run the labelled dataset to calculate metrics from actual scanner output. Image cases run on-device OCR and can take a little longer.');
      return;
    }
    const metrics = state.testMetrics || computeTestMetrics(state.testResults);
    renderAnalyticsSummary(metrics);
    renderTestResults(state.testResults, metrics);
  }

  function renderAnalyticsSummary(metrics) {
    if (!refs.analyticsSummary) return;
    const percent = (value) => (value === null || value === undefined ? '—' : (value * 100).toFixed(1) + '%');
    refs.analyticsSummary.innerHTML = [
      metricCard('Total cases', String(metrics.total), metrics.executed + ' executed · ' + metrics.errors + ' error', 'i-database', 'blue'),
      metricCard('Correct detections', String(metrics.tp + metrics.tn), 'TP + TN on executed cases', 'i-check-circle', 'mint'),
      metricCard('False positives', String(metrics.fp), 'Benign cases flagged', 'i-alert', metrics.fp ? 'amber' : 'mint'),
      metricCard('False negatives', String(metrics.fn), 'Malicious cases missed', 'i-x-circle', metrics.fn ? 'red' : 'mint'),
      metricCard('Precision', percent(metrics.precision), 'TP ÷ (TP + FP)', 'i-target', 'violet'),
      metricCard('Recall', percent(metrics.recall), 'TP ÷ (TP + FN)', 'i-activity', 'violet'),
      metricCard('F1 score', percent(metrics.f1), 'Harmonic mean', 'i-pulse', 'blue'),
    ].join('');
  }

  function computeTestMetrics(results) {
    const executed = results.filter((result) => result.outcome !== 'error');
    const tp = executed.filter((result) => result.outcome === 'tp').length;
    const tn = executed.filter((result) => result.outcome === 'tn').length;
    const fp = executed.filter((result) => result.outcome === 'fp').length;
    const fn = executed.filter((result) => result.outcome === 'fn').length;
    const precision = tp + fp > 0 ? tp / (tp + fp) : null;
    const recall = tp + fn > 0 ? tp / (tp + fn) : null;
    const f1 = precision !== null && recall !== null && precision + recall > 0
      ? (2 * precision * recall) / (precision + recall)
      : null;
    return {
      total: results.length,
      executed: executed.length,
      errors: results.length - executed.length,
      tp: tp, tn: tn, fp: fp, fn: fn,
      precision: precision, recall: recall, f1: f1,
      accuracy: executed.length ? (tp + tn) / executed.length : null,
    };
  }

  function analyzeTestCase(testCase) {
    if (testCase.type === 'url') return Promise.resolve(engine.analyzeUrl(testCase.input));
    if (testCase.type === 'message') return Promise.resolve(engine.analyzeMessage(testCase.input));
    return fetch(testCase.sample, { cache: 'no-store' })
      .then((response) => {
        if (!response.ok) throw new Error('Sample fixture could not be loaded (' + response.status + ').');
        return response.blob();
      })
      .then((blob) => {
        const name = testCase.sample.split('/').pop();
        const file = new File([blob], name, { type: blob.type || 'image/png' });
        return engine.analyzeImage(file, {});
      });
  }

  async function runTestSuite() {
    if (state.testRunning) return;
    state.testRunning = true;
    state.testResults = [];
    state.testMetrics = null;
    if (refs.runTests) {
      refs.runTests.disabled = true;
      refs.runTests.innerHTML = icon('i-refresh') + 'Running suite…';
    }
    if (refs.analyticsProgress) refs.analyticsProgress.hidden = false;
    if (refs.analyticsSummary) refs.analyticsSummary.innerHTML = '';
    if (refs.analyticsResults) refs.analyticsResults.innerHTML = emptyState('i-activity', 'Running real scanner cases', 'Each case is executed through the same local engine used by the Scanner.');

    for (let index = 0; index < TEST_CASES.length; index += 1) {
      const testCase = TEST_CASES[index];
      if (refs.analyticsProgressLabel) refs.analyticsProgressLabel.textContent = 'Running: ' + testCase.name;
      if (refs.analyticsProgressCount) refs.analyticsProgressCount.textContent = (index + 1) + ' / ' + TEST_CASES.length;
      if (refs.analyticsProgressBar) refs.analyticsProgressBar.style.width = Math.round(((index + 1) / TEST_CASES.length) * 100) + '%';
      await new Promise((resolve) => setTimeout(resolve, 40));
      try {
        const report = await analyzeTestCase(testCase);
        const flagged = report.score >= FLAG_THRESHOLD;
        const expectedMalicious = testCase.label === 'malicious';
        const outcome = expectedMalicious ? (flagged ? 'tp' : 'fn') : (flagged ? 'fp' : 'tn');
        state.testResults.push({
          caseId: testCase.id,
          name: testCase.name,
          type: testCase.type,
          label: testCase.label,
          note: testCase.note,
          score: report.score,
          level: report.level,
          confidence: report.confidence,
          flagged: flagged,
          outcome: outcome,
          summary: report.summary,
        });
      } catch (error) {
        state.testResults.push({
          caseId: testCase.id,
          name: testCase.name,
          type: testCase.type,
          label: testCase.label,
          note: testCase.note,
          score: null,
          level: null,
          confidence: null,
          flagged: false,
          outcome: 'error',
          error: error && error.message ? error.message : 'Case could not be executed.',
        });
      }
    }

    state.testMetrics = computeTestMetrics(state.testResults);
    state.testRunning = false;
    if (refs.runTests) {
      refs.runTests.disabled = false;
      refs.runTests.innerHTML = icon('i-play') + 'Run test suite';
    }
    if (refs.analyticsProgress) refs.analyticsProgress.hidden = true;
    renderAnalytics();
    const metrics = state.testMetrics;
    showToast('Suite complete · ' + metrics.executed + ' executed · ' + metrics.fp + ' FP · ' + metrics.fn + ' FN');
  }

  function outcomeLabel(outcome) {
    if (outcome === 'tp') return 'True positive';
    if (outcome === 'tn') return 'True negative';
    if (outcome === 'fp') return 'False positive';
    if (outcome === 'fn') return 'False negative';
    return 'Not executed';
  }

  function renderTestResults(results, metrics) {
    if (!refs.analyticsResults) return;
    const rows = results.map((result) => {
      const actualLevel = result.level ? result.level.label : (typeof result.score === 'number' ? levelFor(result.score).label : '—');
      return [
        '<tr>',
        '<td><strong>' + escape(result.name) + '</strong>' + (result.note ? '<span class="test-note">' + escape(result.note) + '</span>' : '') + (result.error ? '<span class="test-error">' + escape(result.error) + '</span>' : '') + '</td>',
        '<td><span class="type-badge">' + typeIcon(result.type) + escape(simpleTypeLabel(result.type)) + '</span></td>',
        '<td><span class="dataset-label ' + escape(result.label) + '">' + escape(result.label) + '</span></td>',
        '<td class="num">' + (typeof result.score === 'number' ? result.score : '—') + '</td>',
        '<td>' + escape(actualLevel) + '</td>',
        '<td><span class="outcome-chip ' + escape(result.outcome) + '">' + escape(outcomeLabel(result.outcome)) + '</span></td>',
        '</tr>',
      ].join('');
    }).join('');
    refs.analyticsResults.innerHTML = [
      '<div class="test-results-head"><div><span class="panel-kicker">Case-by-case output</span><h3>' + metrics.total + ' labelled cases</h3></div><span class="panel-count">' + metrics.executed + ' executed · flag threshold ' + FLAG_THRESHOLD + '/100</span></div>',
      '<div class="table-wrap"><table class="data-table test-table"><thead><tr><th>Case</th><th>Type</th><th>Expected</th><th>Score</th><th>Verdict</th><th>Outcome</th></tr></thead><tbody>' + rows + '</tbody></table></div>',
      metrics.errors ? '<p class="test-error-note">' + metrics.errors + ' case(s) could not be executed and are excluded from precision, recall and F1. They remain in the total case count.</p>' : '',
    ].join('');
  }

  /* ────────────────────────────────────────────────────────────────────────
     Event wiring
     ──────────────────────────────────────────────────────────────────────── */

  function focusScannerInput() {
    if (state.section !== 'scanner') routeTo('scanner', { scroll: false });
    if (state.mode === 'message') refs.messageInput.focus();
    else if (state.mode === 'image') refs.dropzone.focus();
    else refs.urlInput.focus();
    if (state.mode === 'url') refs.urlInput.select();
  }

  function openIntelForIndicator(key) {
    routeTo('intel');
    openIndicatorDetail(key);
  }

  function handleRouteClick(route) {
    if (!route) return;
    routeTo(route);
  }

  function bindEvents() {
    refs.tabs.forEach((tab) => tab.addEventListener('click', () => setMode(tab.dataset.mode, true)));
    refs.urlInput.addEventListener('input', updateInputState);
    refs.messageInput.addEventListener('input', updateInputState);
    refs.clearUrl.addEventListener('click', () => {
      refs.urlInput.value = '';
      updateInputState();
      refs.urlInput.focus();
    });
    refs.pasteUrl.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          refs.urlInput.value = text.trim();
          updateInputState();
          showToast('Link pasted from clipboard');
          refs.urlInput.focus();
        }
      } catch (_) {
        showToast('Clipboard access is unavailable. Paste manually with ⌘V.');
        refs.urlInput.focus();
      }
    });

    $$('.example-chip[data-example-url]').forEach((chip) => {
      chip.addEventListener('click', () => {
        setMode('url');
        refs.urlInput.value = chip.dataset.exampleUrl;
        updateInputState();
        setTimeout(runScan, 160);
      });
    });
    $$('.example-chip[data-example-message]').forEach((chip) => {
      chip.addEventListener('click', () => {
        setMode('message');
        refs.messageInput.value = chip.dataset.exampleMessage;
        updateInputState();
        setTimeout(runScan, 160);
      });
    });
    $$('.example-chip[data-example-image]').forEach((chip) => {
      chip.addEventListener('click', async () => {
        setMode('image');
        chip.disabled = true;
        try {
          const response = await fetch(chip.dataset.exampleImage, { cache: 'no-store' });
          if (!response.ok) throw new Error('Sample unavailable');
          const blob = await response.blob();
          const name = chip.dataset.exampleImage.split('/').pop();
          const file = new File([blob], name, { type: blob.type || 'image/png' });
          handleFile(file);
          setTimeout(runScan, 260);
        } catch (_) {
          showToast('Could not load the sample image.');
        } finally {
          chip.disabled = false;
        }
      });
    });

    if (refs.scanButton) refs.scanButton.addEventListener('click', runScan);
    if (refs.commandTrigger) refs.commandTrigger.addEventListener('click', focusScannerInput);
    if (refs.mobileMenu) refs.mobileMenu.addEventListener('click', openSidebar);
    if (refs.newInvestigation) refs.newInvestigation.addEventListener('click', () => openInvestigationForm());
    if (refs.runTests) refs.runTests.addEventListener('click', runTestSuite);
    if (refs.refreshGraph) {
      refs.refreshGraph.addEventListener('click', () => {
        state.graphSelected = null;
        renderGraph();
        showToast('Relationship graph refreshed');
      });
    }
    if (refs.clearHistory) refs.clearHistory.addEventListener('click', () => confirmClearData('history'));
    if (refs.clearHistoryFull) refs.clearHistoryFull.addEventListener('click', () => confirmClearData('history'));

    refs.dropzone.addEventListener('click', () => refs.imageInput.click());
    refs.dropzone.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        refs.imageInput.click();
      }
    });
    refs.imageInput.addEventListener('change', (event) => handleFile(event.target.files && event.target.files[0]));
    refs.removeFile.addEventListener('click', removeFile);
    ['dragenter', 'dragover'].forEach((eventName) => {
      refs.dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        refs.dropzone.classList.add('dragging');
      });
    });
    ['dragleave', 'drop'].forEach((eventName) => {
      refs.dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        refs.dropzone.classList.remove('dragging');
      });
    });
    refs.dropzone.addEventListener('drop', (event) => {
      const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
      handleFile(file);
    });
    document.addEventListener('dragover', (event) => event.preventDefault());
    document.addEventListener('drop', (event) => {
      if (!event.target.closest('.dropzone')) {
        event.preventDefault();
        if (state.mode === 'image' && state.section === 'scanner' && event.dataTransfer && event.dataTransfer.files[0]) {
          handleFile(event.dataTransfer.files[0]);
        }
      }
    });

    if (refs.intelAnalyze) refs.intelAnalyze.addEventListener('click', () => runIndicatorAnalysis());
    if (refs.intelInput) {
      refs.intelInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          runIndicatorAnalysis();
        }
      });
    }

    if (refs.indicatorSearch) refs.indicatorSearch.addEventListener('input', renderIndicatorLedger);
    if (refs.indicatorTypeFilter) refs.indicatorTypeFilter.addEventListener('change', renderIndicatorLedger);
    if (refs.invSearch) refs.invSearch.addEventListener('input', renderInvestigationList);
    if (refs.invStatusFilter) refs.invStatusFilter.addEventListener('change', renderInvestigationList);
    if (refs.invSeverityFilter) refs.invSeverityFilter.addEventListener('change', renderInvestigationList);
    if (refs.historySearch) refs.historySearch.addEventListener('input', renderHistoryPage);
    if (refs.historyTypeFilter) refs.historyTypeFilter.addEventListener('change', renderHistoryPage);
    if (refs.historySeverityFilter) refs.historySeverityFilter.addEventListener('change', renderHistoryPage);

    document.addEventListener('change', (event) => {
      const statusSelect = event.target.closest('[data-inv-status]');
      if (statusSelect) {
        setInvestigationStatus(statusSelect.dataset.invStatus, statusSelect.value);
      }
    });

    document.addEventListener('click', (event) => {
      const confirmButton = event.target.closest('[data-modal-confirm]');
      if (confirmButton) {
        const callback = state.modalConfirm;
        closeModal();
        if (typeof callback === 'function') callback();
        return;
      }
      if (event.target.closest('[data-modal-close]')) {
        closeModal();
        return;
      }
      if (event.target === refs.modalBackdrop) {
        closeModal();
        return;
      }

      const routeButton = event.target.closest('[data-route]');
      if (routeButton) {
        event.preventDefault();
        handleRouteClick(routeButton.dataset.route);
        return;
      }

      const viewButton = event.target.closest('[data-view-option]');
      if (viewButton) {
        setView(viewButton.dataset.viewOption, { announce: true });
        return;
      }

      if (event.target.closest('[data-switch-advanced]')) {
        if (!refs.modalBackdrop.hidden) closeModal();
        setView('advanced', { announce: true });
        return;
      }
      if (event.target.closest('[data-switch-simple]')) {
        if (!refs.modalBackdrop.hidden) closeModal();
        setView('simple', { announce: true });
        return;
      }

      const openScanButton = event.target.closest('[data-open-scan]');
      if (openScanButton) {
        openScan(openScanButton.dataset.openScan);
        return;
      }
      const historyRow = event.target.closest('[data-history-id]');
      if (historyRow) {
        openScan(historyRow.dataset.historyId);
        return;
      }
      const openInvButton = event.target.closest('[data-open-inv]');
      if (openInvButton) {
        openInvestigation(openInvButton.dataset.openInv);
        return;
      }
      const openIndicatorButton = event.target.closest('[data-open-indicator]');
      if (openIndicatorButton) {
        openIntelForIndicator(openIndicatorButton.dataset.openIndicator);
        return;
      }
      const ledgerRow = event.target.closest('[data-indicator-key]');
      if (ledgerRow) {
        openIndicatorDetail(ledgerRow.dataset.indicatorKey);
        return;
      }

      const printButton = event.target.closest('[data-report-print]');
      if (printButton) {
        printReport(printButton.dataset.reportPrint);
        return;
      }
      const htmlButton = event.target.closest('[data-report-html]');
      if (htmlButton) {
        downloadHtmlReport(htmlButton.dataset.reportHtml);
        return;
      }
      const jsonButton = event.target.closest('[data-report-json]');
      if (jsonButton) {
        downloadJson(jsonButton.dataset.reportJson);
        return;
      }
      const copyButton = event.target.closest('[data-copy-report]');
      if (copyButton) {
        copyReport(copyButton.dataset.copyReport);
        return;
      }
      const investigateScanButton = event.target.closest('[data-investigate-scan]');
      if (investigateScanButton) {
        openInvestigationForm(investigateScanButton.dataset.investigateScan);
        return;
      }

      const showMoreButton = event.target.closest('[data-show-more]');
      if (showMoreButton) {
        const list = $('#signalList');
        if (!list) return;
        const expanded = list.classList.toggle('expanded');
        showMoreButton.textContent = expanded
          ? 'Show fewer signals'
          : 'Show ' + Math.max(0, (state.result ? state.result.signals.length : 0) - 3) + ' more signals';
        return;
      }

      const intelExample = event.target.closest('[data-intel-example]');
      if (intelExample) {
        runIndicatorAnalysis(intelExample.dataset.intelExample);
        return;
      }
      const reanalyzeIntel = event.target.closest('[data-intel-reanalyze]');
      if (reanalyzeIntel) {
        runIndicatorAnalysis(state.intelAnalysis ? state.intelAnalysis.normalized : (refs.intelInput ? refs.intelInput.value : ''));
        return;
      }
      const copyIndicator = event.target.closest('[data-copy-indicator]');
      if (copyIndicator) {
        copyText(state.intelAnalysis ? state.intelAnalysis.normalized : '', 'Indicator copied');
        return;
      }
      const toInvestigation = event.target.closest('[data-intel-to-inv]');
      if (toInvestigation) {
        if (!state.intelAnalysis) {
          showToast('Analyze an indicator first.');
          return;
        }
        openInvestigationForm(null, { indicator: state.intelAnalysis });
        return;
      }
      const detailAnalyze = event.target.closest('[data-intel-detail-analyze]');
      if (detailAnalyze) {
        const key = detailAnalyze.dataset.intelDetailAnalyze;
        const indicator = state.indicators.find((item) => item.key === key);
        closeModal();
        routeTo('intel', { scroll: false });
        if (indicator) setTimeout(() => runIndicatorAnalysis(indicator.normalized), 80);
        return;
      }
      const graphAnalyze = event.target.closest('[data-graph-analyze]');
      if (graphAnalyze) {
        const node = state.graphData && state.graphData.nodes.find((item) => item.key === graphAnalyze.dataset.graphAnalyze);
        if (node) runIndicatorAnalysis(node.value);
        return;
      }
      const graphNode = event.target.closest('[data-graph-node]');
      if (graphNode) {
        state.graphSelected = graphNode.dataset.graphNode;
        renderGraph();
        renderGraphDetails(state.graphSelected);
        return;
      }

      const invBack = event.target.closest('[data-inv-back]');
      if (invBack) {
        state.activeInvestigation = null;
        renderInvestigations();
        return;
      }
      const invResolve = event.target.closest('[data-inv-resolve]');
      if (invResolve) {
        setInvestigationStatus(invResolve.dataset.invResolve, 'Resolved');
        return;
      }
      const invDelete = event.target.closest('[data-inv-delete]');
      if (invDelete) {
        confirmDeleteInvestigation(invDelete.dataset.invDelete);
        return;
      }
      const addNote = event.target.closest('[data-add-note]');
      if (addNote) {
        addInvestigationNote(addNote.dataset.addNote);
        return;
      }
      const addInvIndicator = event.target.closest('[data-add-inv-indicator]');
      if (addInvIndicator) {
        addIndicatorToInvestigation(addInvIndicator.dataset.addInvIndicator);
        return;
      }
      const removeInvIndicator = event.target.closest('[data-remove-inv-indicator]');
      if (removeInvIndicator) {
        if (state.activeInvestigation) removeIndicatorFromInvestigation(state.activeInvestigation, removeInvIndicator.dataset.removeInvIndicator);
        return;
      }
      const createInv = event.target.closest('[data-inv-create]');
      if (createInv) {
        createInvestigationFromForm();
        return;
      }

      const clearButton = event.target.closest('[data-clear]');
      if (clearButton) {
        confirmClearData(clearButton.dataset.clear);
        return;
      }
    });

    document.addEventListener('submit', (event) => event.preventDefault());

    document.addEventListener('keydown', (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
        event.preventDefault();
        if (state.section !== 'scanner') {
          routeTo('scanner');
          setTimeout(runScan, 160);
        } else {
          runScan();
        }
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        focusScannerInput();
      }
      if (event.key === 'Escape') {
        if (!refs.modalBackdrop.hidden) closeModal();
        if (state.sidebarOpen) closeSidebar();
      }
      if ((event.key === 'Enter' || event.key === ' ') && event.target.closest('[data-graph-node]')) {
        event.preventDefault();
        const key = event.target.closest('[data-graph-node]').dataset.graphNode;
        state.graphSelected = key;
        renderGraph();
        renderGraphDetails(key);
      }
    });

    window.addEventListener('hashchange', () => {
      const section = currentSectionFromHash();
      if (section && section !== state.section) routeTo(section, { updateHash: false });
    });
  }

  function init() {
    state.view = loadView();
    state.history = loadHistory();
    state.investigations = loadInvestigations();
    state.indicators = loadIndicators();
    seedIndicatorsFromHistory();
    bindEvents();
    setView(state.view);
    setMode('url');
    updateInputState();
    renderHistoryList();
    renderSettings();
    setVerdictState('', state.view === 'simple' ? 'Ready' : 'Standby');
    const initialSection = currentSectionFromHash() || readText(SECTION_KEY, 'overview');
    routeTo(SECTIONS[initialSection] ? initialSection : 'overview', { scroll: false });
    setTimeout(() => {
      if (state.section === 'scanner' && window.innerWidth > 900) refs.urlInput.focus({ preventScroll: true });
    }, 420);
  }

  init();
})();
