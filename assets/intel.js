/* Sentinel AI — local indicator intelligence
 * Indicator extraction, normalization, local-only heuristic analysis and
 * evidence-supported relationship graph data. No network lookups.
 */
(function () {
  'use strict';

  const engine = window.SentinelEngine;

  const TYPE_LABELS = {
    url: 'URL',
    domain: 'Domain',
    ipv4: 'IPv4 address',
    ipv6: 'IPv6 address',
    email: 'Email address',
    hash: 'File hash',
    filename: 'Filename',
  };

  const TYPE_ORDER = ['url', 'domain', 'ipv4', 'ipv6', 'email', 'hash', 'filename'];

  const TYPE_COLORS = {
    url: '#6f9cff',
    domain: '#58edbc',
    ipv4: '#b696ff',
    ipv6: '#8fc9ff',
    email: '#f5c451',
    hash: '#ff9257',
    filename: '#ff7b9c',
  };

  const FREE_MAIL = new Set([
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'outlook.com',
    'hotmail.com', 'live.com', 'icloud.com', 'me.com', 'proton.me',
    'protonmail.com', 'aol.com', 'gmx.com', 'zoho.com', 'yandex.com',
  ]);

  const DISPOSABLE_MAIL = new Set([
    'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com',
    'temp-mail.org', 'yopmail.com', 'sharklasers.com', 'throwawaymail.com',
    'getnada.com', 'maildrop.cc', 'trashmail.com', 'fakeinbox.com',
    'dispostable.com', 'spamgourmet.com', 'mytemp.email',
  ]);

  const DANGEROUS_EXTENSIONS = new Set([
    'exe', 'scr', 'msi', 'bat', 'cmd', 'com', 'ps1', 'vbs', 'vbe', 'js',
    'jse', 'wsf', 'wsh', 'hta', 'jar', 'apk', 'dmg', 'pkg', 'deb', 'app',
    'run', 'bin', 'lnk',
  ]);

  const ARCHIVE_EXTENSIONS = new Set([
    'zip', 'rar', '7z', 'iso', 'img', 'vhd', 'vhdx', 'cab', 'tar', 'gz', 'tgz',
  ]);

  const MACRO_EXTENSIONS = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xlam']);
  const IMAGE_EXTENSIONS = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'tif', 'tiff', 'heic', 'avif']);
  const SAFE_COMMON_EXTENSIONS = new Set(['txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'csv', 'json', 'md']);

  const URL_RE = /(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;
  const EMAIL_RE = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/gi;
  const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
  const IPV6_RE = /\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{0,4}\b/gi;
  const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
  const SHA1_RE = /\b[a-f0-9]{40}\b/gi;
  const MD5_RE = /\b[a-f0-9]{32}\b/gi;
  const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
  /* No whitespace inside a filename: this prevents sentences that merely end
     in ".com" or ".pdf" from being captured as one long file name. The common
     TLD-shaped extensions (com, app, zip) are deliberately excluded so a bare
     domain is never mistaken for a file artifact. */
  const FILENAME_RE = /\b[\w][\w.()@+-]{0,90}\.(?:exe|scr|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|jar|apk|dmg|pkg|deb|run|bin|lnk|rar|7z|iso|img|vhd|vhdx|cab|tar|gz|tgz|docm|xlsm|pptm|dotm|xlam|pdf|docx?|xlsx?|pptx?|csv|json|txt|html?|jpe?g|png|gif|webp|svg|bmp|tiff?|heic|avif)\b/gi;

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function trimValue(value) {
    return String(value || '').trim().replace(/[),.;!?]+$/g, '');
  }

  function typeLabel(type) {
    return TYPE_LABELS[type] || 'Indicator';
  }

  function typeColor(type) {
    return TYPE_COLORS[type] || '#7d918b';
  }

  function isIpv4(value) {
    const parts = String(value).split('.');
    if (parts.length !== 4) return false;
    return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
  }

  function isIpv6(value) {
    const candidate = String(value).replace(/^\[|\]$/g, '');
    if (!candidate.includes(':') || !/^[a-f0-9:]+$/i.test(candidate)) return false;
    if (candidate.includes('::')) {
      return candidate.split(':').filter(Boolean).length <= 7;
    }
    return candidate.split(':').length === 8;
  }

  function isHash(value) {
    return /^[a-f0-9]{32}$/i.test(value) || /^[a-f0-9]{40}$/i.test(value) || /^[a-f0-9]{64}$/i.test(value);
  }

  function isFilename(value) {
    const clean = String(value).trim();
    if (!clean || /\s{2,}/.test(clean)) return false;
    return /\.(exe|scr|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|jar|apk|dmg|pkg|deb|run|bin|lnk|zip|rar|7z|iso|img|vhd|vhdx|cab|tar|gz|tgz|docm|xlsm|pptm|dotm|xlam|pdf|docx?|xlsx?|pptx?|csv|json|txt|html?|jpe?g|png|gif|webp|svg|bmp|tiff?|heic|avif)$/i.test(clean);
  }

  function detectType(value) {
    const raw = trimValue(value);
    if (!raw) return null;
    if (/^(https?:\/\/|www\.)/i.test(raw) || /^[a-z0-9-]+\.[a-z]{2,}(\/|\?|#)/i.test(raw)) return 'url';
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw)) return 'email';
    if (raw.startsWith('[') && raw.endsWith(']') && isIpv6(raw)) return 'ipv6';
    if (isIpv4(raw)) return 'ipv4';
    if (isIpv6(raw)) return 'ipv6';
    if (isHash(raw)) return 'hash';
    if (isFilename(raw)) return 'filename';
    if (/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(raw)) return 'domain';
    return null;
  }

  function normalize(type, value) {
    const raw = trimValue(value);
    if (type === 'url') {
      let candidate = raw;
      if (/^www\./i.test(candidate)) candidate = 'https://' + candidate;
      try {
        const url = new URL(candidate);
        url.protocol = url.protocol.toLowerCase();
        url.hostname = url.hostname.toLowerCase();
        return url.href.replace(/\/$/, '') || url.href;
      } catch (_) {
        return candidate;
      }
    }
    if (type === 'domain') {
      return raw.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '').replace(/\.$/, '');
    }
    if (type === 'email') return raw.toLowerCase();
    if (type === 'hash') return raw.toLowerCase();
    if (type === 'ipv6') return raw.toLowerCase().replace(/^\[|\]$/g, '');
    if (type === 'ipv4') return raw;
    return raw;
  }

  function keyFor(type, value) {
    return type + ':' + normalize(type, value);
  }

  function idFor(type, value) {
    let hash = 2166136261;
    const text = keyFor(type, value);
    for (let i = 0; i < text.length; i += 1) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    return 'ind-' + (hash >>> 0).toString(36);
  }

  function urlParts(value) {
    const raw = String(value || '').trim();
    try {
      const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : 'https://' + raw.replace(/^www\./i, ''));
      return {
        hostname: url.hostname.toLowerCase().replace(/^\[|\]$/g, ''),
        registrable: (url.hostname.toLowerCase().replace(/^\[|\]$/g, '')),
      };
    } catch (_) {
      return { hostname: '', registrable: '' };
    }
  }

  function categoryForType(type) {
    if (type === 'url') return 'Link / destination';
    if (type === 'domain' || type === 'ipv4' || type === 'ipv6') return 'Infrastructure';
    if (type === 'email') return 'Identity';
    if (type === 'hash') return 'File artifact';
    return 'Payload';
  }

  function topSignal(signals) {
    return (signals || []).slice().sort((a, b) => {
      const order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (order[b.severity] || 0) - (order[a.severity] || 0) || (b.points || 0) - (a.points || 0);
    })[0];
  }

  /** Extract indicators from a scanner report without inventing observations. */
  function extractIndicators(report) {
    if (!report || !report.id) return [];
    const found = new Map();

    function add(type, value, evidence, category) {
      if (!value) return;
      const normalized = normalize(type, value);
      if (!normalized) return;
      if (type === 'domain' && (isIpv4(normalized) || isIpv6(normalized))) return;
      if (type === 'domain' && !normalized.includes('.')) return;
      const key = keyFor(type, normalized);
      const existing = found.get(key);
      const observation = {
        type,
        value: String(value).trim(),
        normalized,
        category: category || categoryForType(type),
        evidence: evidence || '',
      };
      if (existing) {
        if (!existing.evidence && observation.evidence) existing.evidence = observation.evidence;
        if (!existing.category && observation.category) existing.category = observation.category;
        return;
      }
      found.set(key, observation);
    }

    function addUrl(value, evidence) {
      if (!value) return;
      const match = String(value).match(/(?:https?:\/\/|www\.)[^\s<>"'`]+/i);
      if (!match) return;
      let url = trimValue(match[0]);
      // Reject fragments that were visibly truncated in stored evidence or
      // copied from display text (for example a trailing ellipsis).
      if (/[…]/.test(url) || /\.{3}$/.test(url)) return;
      if (/^www\./i.test(url)) url = 'https://' + url;
      let parsed;
      try {
        parsed = new URL(url);
      } catch (_) {
        return;
      }
      if (!/^https?:$/.test(parsed.protocol)) return;
      const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
      if (!hostname) return;
      const isAddress = isIpv4(hostname) || isIpv6(hostname);
      if (!isAddress && !hostname.includes('.')) return;
      if (!isAddress && !/^[a-z0-9.-]+$/.test(hostname)) return;
      add('url', parsed.href, evidence);
      if (isIpv4(hostname)) add('ipv4', hostname, evidence);
      else if (isIpv6(hostname)) add('ipv6', hostname, evidence);
      else add('domain', hostname, evidence);
    }

    function scanText(text, evidence, options) {
      const source = String(text || '');
      if (!source) return;
      const allowUrls = !options || options.urls !== false;
      let remainder = source;

      if (allowUrls) {
        (source.match(URL_RE) || []).forEach((url) => addUrl(url, evidence));
      }

      (source.match(EMAIL_RE) || []).forEach((email) => {
        add('email', email, evidence);
        const domain = email.split('@')[1];
        if (domain) add('domain', domain, evidence);
      });

      (source.match(SHA256_RE) || []).forEach((hash) => add('hash', hash, evidence));
      (source.match(SHA1_RE) || []).forEach((hash) => add('hash', hash, evidence));
      (source.match(MD5_RE) || []).forEach((hash) => add('hash', hash, evidence));

      (source.match(IPV4_RE) || []).forEach((ip) => add('ipv4', ip, evidence));
      (source.match(IPV6_RE) || []).forEach((ip) => {
        if (isIpv6(ip)) add('ipv6', ip, evidence);
      });

      // Remove things already classified before looking for filenames and domains.
      remainder = remainder
        .replace(new RegExp(URL_RE.source, 'gi'), ' ')
        .replace(new RegExp(EMAIL_RE.source, 'gi'), ' ')
        .replace(new RegExp(SHA256_RE.source, 'gi'), ' ')
        .replace(new RegExp(SHA1_RE.source, 'gi'), ' ')
        .replace(new RegExp(MD5_RE.source, 'gi'), ' ')
        .replace(new RegExp(IPV4_RE.source, 'g'), ' ')
        .replace(new RegExp(IPV6_RE.source, 'gi'), ' ');

      (remainder.match(FILENAME_RE) || []).forEach((name) => {
        const clean = String(name).trim();
        if (clean.length < 4 || clean.length > 120) return;
        add('filename', clean, evidence);
      });

      const withoutFilenames = remainder.replace(new RegExp(FILENAME_RE.source, 'gi'), ' ');
      (withoutFilenames.match(DOMAIN_RE) || []).forEach((domain) => {
        const clean = domain.toLowerCase().replace(/\.$/, '');
        if (clean.length > 253) return;
        if (clean === 'example.com' || clean === 'localhost') return;
        const tld = clean.split('.').pop();
        if (IMAGE_EXTENSIONS.has(tld) || SAFE_COMMON_EXTENSIONS.has(tld)) return;
        add('domain', clean, evidence);
      });
    }

    const details = report.details || {};
    const top = topSignal(report.signals);
    const signalEvidence = top ? `${top.title}: ${top.evidence || top.description}` : '';

    if (report.type === 'url') {
      addUrl(details.normalized || details.raw || report.target, signalEvidence);
      if (details.hostname) {
        if (!isIpv4(details.hostname) && !isIpv6(details.hostname)) add('domain', details.hostname, signalEvidence);
      }
      if (details.registrable && !isIpv4(details.registrable) && !isIpv6(details.registrable)) {
        add('domain', details.registrable, signalEvidence);
      }
      if (details.redirectedTo) addUrl(details.redirectedTo, 'Redirect destination observed in the URL parameters');
    }

    if (report.type === 'message') {
      (details.links || []).forEach((link) => addUrl(link.url, signalEvidence));
      // The preview can be truncated when history is compacted, so parse free
      // text for addresses and artifacts but never for partially stored URLs.
      scanText(details.preview || '', signalEvidence, { urls: false });
    }

    if (report.type === 'image') {
      if (isFilename(report.target || '')) add('filename', report.target, 'Uploaded file name');
      if (details.hashes) {
        Object.keys(details.hashes).forEach((key) => {
          if (details.hashes[key]) add('hash', details.hashes[key], `${key.toUpperCase()} computed on this device`);
        });
      }
      (details.urls || []).forEach((link) => addUrl(link.url, 'URL embedded in image content'));
      if (details.qr && details.qr.data) {
        addUrl(details.qr.data, 'QR code payload');
        scanText(details.qr.data, 'QR code payload', { urls: false });
      }
      if (details.ocr) {
        const ocrReport = details.ocr.report || {};
        ((ocrReport.details || {}).links || []).forEach((link) => addUrl(link.url, 'Link recognised in on-device image text'));
        ((ocrReport.details || {}).urls || []).forEach((link) => addUrl(link.url, 'Link recognised in on-device image text'));
        if (details.ocr.text) scanText(details.ocr.text, 'Text read from the image on this device', { urls: false });
      }
      if (details.metadata) {
        Object.keys(details.metadata).forEach((key) => {
          if (key.startsWith('_')) return;
          const value = details.metadata[key];
          if (typeof value === 'string') scanText(value.slice(0, 2000), `Image metadata field: ${key}`, { urls: false });
        });
      }
    }

    // Signal evidence can contain artefacts not present in a compact history record.
    // It may also be truncated mid-value, so URLs come only from structured fields.
    (report.signals || []).forEach((signal) => {
      scanText(signal.evidence || '', `${signal.title}: ${signal.evidence || ''}`, { urls: false });
      scanText(signal.description || '', signal.title, { urls: false });
    });

    return Array.from(found.values()).map((item) => {
      const signal = (report.signals || []).find((candidate) => {
        const text = `${candidate.evidence || ''} ${candidate.description || ''}`.toLowerCase();
        return text.includes(item.normalized.toLowerCase());
      }) || top;
      return {
        ...item,
        id: idFor(item.type, item.normalized),
        key: keyFor(item.type, item.normalized),
        category: signal && signal.category ? signal.category : categoryForType(item.type),
        score: typeof report.score === 'number' ? report.score : null,
        confidence: typeof report.confidence === 'number' ? report.confidence : null,
        sourceScanId: report.id,
        sourceScanType: report.type,
        sourceTarget: report.displayTarget || report.target || 'Untitled scan',
        sourceLevel: report.level ? report.level.key : null,
        observedAt: report.timestamp || Date.now(),
      };
    });
  }

  function severityToPoints(severity) {
    if (severity === 'critical') return 40;
    if (severity === 'high') return 24;
    if (severity === 'medium') return 14;
    if (severity === 'low') return 6;
    return 0;
  }

  function makeSignal(id, title, description, severity, category) {
    return {
      id,
      title,
      description,
      severity,
      points: severityToPoints(severity),
      category: category || 'infrastructure',
      evidence: '',
    };
  }

  function analyzeUrlType(raw, type) {
    const urlValue = type === 'url' ? raw : 'https://' + raw;
    const report = engine.analyzeUrl(urlValue);
    const signals = (report.signals || []).slice();
    const notes = [
      'Structural analysis only. No live DNS, WHOIS, certificate or reputation lookup was performed.',
    ];
    if (type === 'domain') {
      notes.push('Domain-only analysis. The path, query and download checks do not apply.');
    }
    return {
      type,
      value: raw,
      normalized: normalize(type, raw),
      score: report.score,
      level: report.level,
      confidence: report.confidence,
      summary: report.summary,
      signals,
      recommendations: report.recommendations,
      notes,
      reputation: 'UNKNOWN',
      reputationNote: 'External reputation: UNKNOWN — Sentinel has no live reputation provider.',
      report,
    };
  }

  function analyzeIp(raw, type) {
    const bracketed = type === 'ipv6' ? '[' + raw.replace(/^\[|\]$/g, '') + ']' : raw;
    const report = engine.analyzeUrl('http://' + bracketed + '/');
    return {
      type,
      value: raw,
      normalized: normalize(type, raw),
      score: report.score,
      level: report.level,
      confidence: report.confidence,
      summary: report.summary,
      signals: report.signals,
      recommendations: report.recommendations,
      notes: [
        'Address-only analysis. Sentinel does not perform reverse DNS, port scanning or geolocation.',
        'A raw IP destination removes the domain identity cues users normally rely on.',
      ],
      reputation: 'UNKNOWN',
      reputationNote: 'External reputation: UNKNOWN — no address reputation lookup was performed.',
      report,
    };
  }

  function analyzeEmail(raw) {
    const normalized = normalize('email', raw);
    const localPart = normalized.split('@')[0] || '';
    const domain = normalized.split('@')[1] || '';
    const signals = [];
    const positives = [];
    let domainReport = null;

    if (domain) {
      try {
        domainReport = engine.analyzeUrl('https://' + domain);
        (domainReport.signals || []).forEach((signal) => signals.push(signal));
      } catch (_) {
        // The domain may not be parseable; email-only checks still apply.
      }
    }

    const registrable = domain.split('.').slice(-2).join('.');
    if (FREE_MAIL.has(registrable)) {
      positives.push('The domain is a well-known consumer mailbox provider.');
    }
    if (DISPOSABLE_MAIL.has(registrable) || DISPOSABLE_MAIL.has(domain)) {
      signals.push(makeSignal(
        'email-disposable',
        'Disposable mailbox domain',
        'The email domain is associated with temporary inboxes. Identity claims made from a disposable address should not be trusted.',
        'high',
        'identity',
      ));
    }
    if (/^[a-z0-9]{20,}$/i.test(localPart)) {
      signals.push(makeSignal(
        'email-random-local',
        'Random-looking mailbox name',
        'The local part of the address looks automatically generated. This is common in bulk account creation and fraud.',
        'low',
        'identity',
      ));
    }
    if (/\+.*@/.test(normalized)) {
      signaturesPush(signals, makeSignal(
        'email-plus-tag',
        'Plus-tagged mailbox alias',
        'The address uses a plus tag. This is not malicious by itself, but it can indicate bulk tracking or alias management.',
        'low',
        'identity',
      ));
    }

    const aggregate = engine._internals.aggregate(signals);
    const level = engine.levelForScore(aggregate.score);
    return {
      type: 'email',
      value: raw,
      normalized,
      score: aggregate.score,
      level,
      confidence: Math.max(62, Math.min(94, 70 + aggregate.signals.length * 3)),
      summary: aggregate.signals.length
        ? `The address and its domain show ${aggregate.signals.length} local risk signal${aggregate.signals.length === 1 ? '' : 's'}. This is not proof that the sender is malicious.`
        : 'No structural risk signals were found in the address or its domain. External reputation remains unknown.',
      signals: aggregate.signals,
      recommendations: [
        'Verify the sender through a separate channel before acting on any request.',
        'Do not judge trust from the display name; inspect the full address.',
        'External mailbox and domain reputation were not queried.',
      ],
      positives,
      notes: [
        'Email analysis is structural: syntax, domain shape and local reputation-free heuristics only.',
        'No message headers, SPF, DKIM or DMARC data were supplied or fetched.',
      ],
      reputation: 'UNKNOWN',
      reputationNote: 'External reputation: UNKNOWN — no live email or domain reputation was queried.',
      report: domainReport,
    };
  }

  function signaturesPush(list, value) {
    if (value) list.push(value);
  }

  function analyzeHash(raw) {
    const normalized = normalize('hash', raw);
    const kind = normalized.length === 64 ? 'SHA-256' : normalized.length === 40 ? 'SHA-1' : 'MD5';
    return {
      type: 'hash',
      value: raw,
      normalized,
      score: null,
      level: null,
      confidence: null,
      summary: `Valid ${kind} hash format. Sentinel cannot classify the file from a hash alone, and no reputation service was queried.`,
      signals: [],
      recommendations: [
        'Do not treat an unknown hash as safe. It is simply unclassified.',
        'Compare the hash with a trusted internal file inventory if one exists.',
        'Run the original file through an endpoint protection product before execution.',
      ],
      positives: [],
      notes: [
        `${kind} structure validated locally.`,
        'No file content was uploaded, opened or executed.',
        'External reputation: UNKNOWN — this is not a clean verdict.',
      ],
      reputation: 'UNKNOWN',
      reputationNote: 'External reputation: UNKNOWN — hash reputation lookup is not available.',
    };
  }

  function analyzeFilename(raw) {
    const normalized = normalize('filename', raw);
    const name = normalized.toLowerCase();
    const extension = (name.split('.').pop() || '').toLowerCase();
    const pieces = name.split('.');
    const signals = [];
    const positives = [];
    const notes = [
      'Filename-only analysis. The file content was not opened or executed.',
      'A suspicious name is not proof of malware; it identifies where verification should focus.',
    ];

    if (DANGEROUS_EXTENSIONS.has(extension)) {
      signals.push(makeSignal(
        'file-executable',
        `Executable file extension (.${extension})`,
        'Executable and script formats can run code when opened. Only run files from sources you can verify.',
        'high',
        'payload',
      ));
    }
    if (ARCHIVE_EXTENSIONS.has(extension)) {
      signals.push(makeSignal(
        'file-archive',
        `Archive file extension (.${extension})`,
        'Archives are frequently used to package payloads or hide file types from casual inspection.',
        'medium',
        'payload',
      ));
    }
    if (MACRO_EXTENSIONS.has(extension)) {
      signals.push(makeSignal(
        'file-macro',
        `Macro-enabled document (.${extension})`,
        'Macro-enabled Office formats can execute code if macros are allowed.',
        'medium',
        'payload',
      ));
    }
    if (pieces.length >= 3 && IMAGE_EXTENSIONS.has(pieces[pieces.length - 2]) && DANGEROUS_EXTENSIONS.has(extension)) {
      signals.push(makeSignal(
        'file-double-extension',
        'Deceptive double extension',
        'The filename hides an executable behind an image extension. This is a deliberate disguise technique.',
        'critical',
        'payload',
      ));
    }
    if (/\.[a-z0-9]+\.(exe|scr|js|vbs|bat|cmd)$/i.test(name) && !pieces.some((part) => IMAGE_EXTENSIONS.has(part))) {
      signals.push(makeSignal(
        'file-double-extension',
        'Nested executable extension',
        'The file has more than one extension and ends in an executable type. Confirm the true file type before opening.',
        'high',
        'payload',
      ));
    }
    if (/[\u202a-\u202e\u2066-\u2069]/.test(raw)) {
      signals.push(makeSignal(
        'file-rtl-override',
        'Unicode direction override in filename',
        'Direction-control characters can make a dangerous extension appear harmless in some interfaces.',
        'high',
        'payload',
      ));
    }
    if (/\s{2,}|^\s|\s$/.test(raw)) {
      signals.push(makeSignal(
        'file-padded-name',
        'Padded or irregular filename',
        'Extra spaces in filenames are sometimes used to push the true extension out of view.',
        'low',
        'payload',
      ));
    }
    if (!signals.length) {
      positives.push('No dangerous, archive or macro extension was identified.');
      if (SAFE_COMMON_EXTENSIONS.has(extension)) positives.push(`.${extension} is a common document format.`);
    }

    const aggregate = engine._internals.aggregate(signals);
    const level = engine.levelForScore(aggregate.score);
    return {
      type: 'filename',
      value: raw,
      normalized,
      score: aggregate.score,
      level,
      confidence: signals.length ? Math.min(82, 58 + aggregate.signals.length * 7) : 60,
      summary: aggregate.signals.length
        ? `The filename carries ${aggregate.signals.length} structural warning sign${aggregate.signals.length === 1 ? '' : 's'}. This is not a malware verdict.`
        : 'The filename has no obvious dangerous structure. The contents remain unverified.',
      signals: aggregate.signals,
      recommendations: [
        'Do not open or execute an unexpected attachment.',
        'Confirm the sender and the file purpose through a separate channel.',
        'Use endpoint protection or a sandbox for content analysis.',
      ],
      positives,
      notes,
      reputation: 'UNKNOWN',
      reputationNote: 'External reputation: UNKNOWN — the file was not uploaded or scanned by a reputation service.',
    };
  }

  /** Local-only indicator analysis. Throws a user-facing error for invalid input. */
  function analyze(value) {
    const raw = trimValue(value);
    if (!raw) throw new Error('Enter an indicator to analyze.');
    if (raw.length > 4096) throw new Error('Indicator is too long. Limit it to 4,096 characters.');
    const type = detectType(raw);
    if (!type) {
      throw new Error('Could not identify that indicator. Use a URL, domain, IP address, email, hash or filename.');
    }
    let result;
    if (type === 'url' || type === 'domain') result = analyzeUrlType(raw, type);
    else if (type === 'ipv4' || type === 'ipv6') result = analyzeIp(raw, type);
    else if (type === 'email') result = analyzeEmail(raw);
    else if (type === 'hash') result = analyzeHash(raw);
    else result = analyzeFilename(raw);
    result.analyzedAt = Date.now();
    result.typeLabel = typeLabel(result.type);
    return result;
  }

  function buildGraph(history, indicators) {
    const ledger = new Map();
    (indicators || []).forEach((indicator) => {
      if (!indicator || !indicator.type || !indicator.normalized) return;
      ledger.set(keyFor(indicator.type, indicator.normalized), indicator);
    });

    const nodeMap = new Map();
    const edgeMap = new Map();

    function ensureNode(type, normalized, meta) {
      const key = keyFor(type, normalized);
      if (nodeMap.has(key)) return nodeMap.get(key);
      const stored = ledger.get(key) || {};
      const node = {
        id: idFor(type, normalized),
        key,
        type,
        value: stored.normalized || normalized,
        label: stored.normalized || normalized,
        score: typeof stored.score === 'number' ? stored.score : (meta && meta.score),
        category: stored.category || (meta && meta.category) || categoryForType(type),
        lastSeen: stored.lastSeen || (meta && meta.observedAt) || Date.now(),
        observations: stored.observations ? stored.observations.length : 0,
        meta: stored,
      };
      nodeMap.set(key, node);
      return node;
    }

    function addEdge(a, b, label) {
      if (!a || !b || a.key === b.key) return;
      const id = [a.key, b.key].sort().join('|');
      if (edgeMap.has(id)) return;
      edgeMap.set(id, { id, source: a.key, target: b.key, label });
    }

    (history || []).slice(0, 30).forEach((report) => {
      const extracted = extractIndicators(report);
      const nodes = extracted.map((item) => ensureNode(item.type, item.normalized, item));
      const urls = nodes.filter((node) => node.type === 'url');
      const domains = nodes.filter((node) => node.type === 'domain');
      const ips = nodes.filter((node) => node.type === 'ipv4' || node.type === 'ipv6');
      const emails = nodes.filter((node) => node.type === 'email');

      urls.forEach((urlNode) => {
        const parts = urlParts(urlNode.value);
        const hostKeyDomain = keyFor('domain', parts.hostname);
        const hostKeyIp = keyFor('ipv4', parts.hostname);
        const hostKeyIp6 = keyFor('ipv6', parts.hostname);
        const domainNode = nodeMap.get(hostKeyDomain) || domains.find((node) => node.value === parts.hostname);
        const ipNode = nodeMap.get(hostKeyIp) || nodeMap.get(hostKeyIp6) || ips.find((node) => node.value === parts.hostname);
        if (domainNode) addEdge(urlNode, domainNode, 'belongs to domain');
        if (ipNode) addEdge(urlNode, ipNode, 'hosted at address');
      });

      emails.forEach((emailNode) => {
        const domain = String(emailNode.value).split('@')[1];
        if (!domain) return;
        const domainNode = nodeMap.get(keyFor('domain', domain)) || domains.find((node) => node.value === domain);
        if (domainNode) addEdge(emailNode, domainNode, 'uses mail domain');
      });

      // Co-occurrence in one scan is genuine evidence that the artefacts were observed together.
      const co = nodes.slice(0, 6);
      for (let i = 0; i < co.length; i += 1) {
        for (let j = i + 1; j < co.length; j += 1) {
          if (co[i].type !== co[j].type) addEdge(co[i], co[j], 'observed together');
        }
      }
    });

    const degree = new Map();
    edgeMap.forEach((edge) => {
      degree.set(edge.source, (degree.get(edge.source) || 0) + 1);
      degree.set(edge.target, (degree.get(edge.target) || 0) + 1);
    });

    let nodes = Array.from(nodeMap.values()).map((node) => ({
      ...node,
      degree: degree.get(node.key) || 0,
    }));
    nodes.sort((a, b) => b.degree - a.degree || b.lastSeen - a.lastSeen);
    if (nodes.length > 54) nodes = nodes.slice(0, 54);
    const allowed = new Set(nodes.map((node) => node.key));
    const edges = Array.from(edgeMap.values()).filter((edge) => allowed.has(edge.source) && allowed.has(edge.target));

    const width = 960;
    const height = 540;
    const rng = mulberry32(1337);
    const centerX = width / 2;
    const centerY = height / 2;
    nodes.forEach((node, index) => {
      const angle = index * 2.399963229728653;
      const radius = 40 + Math.sqrt(index + 1) * 34;
      node.x = centerX + Math.cos(angle) * radius + (rng() - 0.5) * 30;
      node.y = centerY + Math.sin(angle) * radius + (rng() - 0.5) * 30;
    });

    const lookup = new Map(nodes.map((node) => [node.key, node]));
    for (let iteration = 0; iteration < 240; iteration += 1) {
      const cooling = 1 - iteration / 260;
      for (let i = 0; i < nodes.length; i += 1) {
        for (let j = i + 1; j < nodes.length; j += 1) {
          const a = nodes[i];
          const b = nodes[j];
          let dx = b.x - a.x;
          let dy = b.y - a.y;
          let dist = Math.sqrt(dx * dx + dy * dy) || 0.1;
          const repulsion = 3600 / (dist * dist);
          dx /= dist;
          dy /= dist;
          a.x -= dx * repulsion * cooling;
          a.y -= dy * repulsion * cooling;
          b.x += dx * repulsion * cooling;
          b.y += dy * repulsion * cooling;
        }
      }
      edges.forEach((edge) => {
        const a = lookup.get(edge.source);
        const b = lookup.get(edge.target);
        if (!a || !b) return;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.1;
        const pull = (dist - 120) * 0.0016 * cooling;
        const fx = (dx / dist) * pull;
        const fy = (dy / dist) * pull;
        a.x += fx;
        a.y += fy;
        b.x -= fx;
        b.y -= fy;
      });
      nodes.forEach((node) => {
        node.x += (centerX - node.x) * 0.0022 * cooling;
        node.y += (centerY - node.y) * 0.0022 * cooling;
        node.x = Math.max(34, Math.min(width - 34, node.x));
        node.y = Math.max(34, Math.min(height - 34, node.y));
      });
    }

    nodes.forEach((node) => {
      node.x = Math.round(node.x * 10) / 10;
      node.y = Math.round(node.y * 10) / 10;
      node.radius = 8 + Math.min(9, node.degree * 1.6);
    });

    return { nodes, edges, width, height };
  }

  function mulberry32(seed) {
    let a = seed;
    return function () {
      a |= 0;
      a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  window.SentinelIntel = {
    types: TYPE_ORDER,
    typeLabel,
    typeColor,
    detectType,
    normalize,
    keyFor,
    idFor,
    extractIndicators,
    analyze,
    buildGraph,
    escapeHtml,
    categoryForType,
  };
})();
