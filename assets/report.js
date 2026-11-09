/* Sentinel AI — report composition
 * Builds a self-contained, print-friendly incident report and downloads it
 * with browser-native APIs. No local paths or internal engine objects leak.
 */
(function () {
  'use strict';

  const intel = window.SentinelIntel;

  function esc(value) {
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function safeTarget(report) {
    if (!report) return 'Untitled source';
    let value = report.displayTarget || report.target || 'Untitled source';
    if (report.type === 'image') {
      value = String(value).split(/[\\/]/).pop() || 'image';
    }
    if (report.type === 'url') {
      value = String(value).replace(/(\/\/)[^/@\s]+@/, '$1[credentials redacted]@');
    }
    return String(value).slice(0, 500);
  }

  function reportId(report) {
    const base = String(report && report.id ? report.id : Date.now()).replace(/[^a-z0-9]/gi, '').toUpperCase();
    return 'SR-' + (base.slice(-12) || 'LOCAL');
  }

  function formatDate(timestamp) {
    const date = new Date(Number(timestamp) || Date.now());
    return date.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  }

  function typeName(type) {
    if (type === 'url') return 'Link analysis';
    if (type === 'image') return 'Image analysis';
    if (type === 'message') return 'Message analysis';
    return 'Analysis';
  }

  function verdictName(report) {
    if (!report || !report.level) return 'Unclassified';
    return report.level.label || String(report.level.key || '').toUpperCase();
  }

  function indicatorsFor(report, provided) {
    if (Array.isArray(provided)) return provided;
    if (!intel) return [];
    try {
      return intel.extractIndicators(report);
    } catch (_) {
      return [];
    }
  }

  function signalRows(report) {
    const signals = report.signals || [];
    if (!signals.length) {
      return '<tr><td colspan="4" class="empty">No detection signals matched the local ruleset.</td></tr>';
    }
    return signals.map((signal) => `
      <tr>
        <td><span class="sev ${esc(signal.severity)}">${esc(String(signal.severity || 'info').toUpperCase())}</span></td>
        <td><strong>${esc(signal.title)}</strong><span class="sub">${esc(signal.description)}</span>${signal.evidence ? `<span class="mono">${esc(signal.evidence)}</span>` : ''}</td>
        <td>${esc(signal.category || '—')}</td>
        <td class="num">+${esc(signal.points || 0)}</td>
      </tr>`).join('');
  }

  function indicatorRows(indicators) {
    if (!indicators.length) {
      return '<tr><td colspan="4" class="empty">No indicators were extracted from this scan.</td></tr>';
    }
    return indicators.map((indicator) => `
      <tr>
        <td><span class="type">${esc(indicator.type ? indicator.type.toUpperCase() : 'INDICATOR')}</span></td>
        <td class="mono break">${esc(indicator.normalized || indicator.value || '')}</td>
        <td>${esc(indicator.category || '—')}</td>
        <td>${indicator.score === null || indicator.score === undefined ? 'UNKNOWN' : esc(indicator.score + '/100')}</td>
      </tr>`).join('');
  }

  function investigationSection(investigation) {
    if (!investigation) {
      return `
        <section class="section">
          <h2>Investigation</h2>
          <p class="muted">This scan is not associated with an investigation.</p>
        </section>`;
    }
    const notes = (investigation.notes || []).slice(0, 12);
    return `
      <section class="section">
        <h2>Investigation</h2>
        <table class="meta">
          <tr><th>Incident ID</th><td>${esc(investigation.id)}</td><th>Status</th><td>${esc(investigation.status)}</td></tr>
          <tr><th>Title</th><td colspan="3">${esc(investigation.title)}</td></tr>
          <tr><th>Severity</th><td>${esc(String(investigation.severity || '').toUpperCase())}</td><th>Opened</th><td>${esc(formatDate(investigation.createdAt))}</td></tr>
        </table>
        ${investigation.description ? `<p class="narrative">${esc(investigation.description)}</p>` : ''}
        ${notes.length ? `
          <h3>Analyst notes</h3>
          <ol class="notes">${notes.map((note) => `<li><span class="note-time">${esc(formatDate(note.createdAt))}</span>${esc(note.text)}</li>`).join('')}</ol>` : ''}
      </section>`;
  }

  function buildReportHtml(report, options) {
    options = options || {};
    if (!report) throw new Error('No report is available.');
    const indicators = indicatorsFor(report, options.indicators);
    const investigation = options.investigation || null;
    const generated = Date.now();
    const score = typeof report.score === 'number' ? report.score + ' / 100' : 'Not scored';
    const confidence = typeof report.confidence === 'number' ? report.confidence + '%' : 'Not available';
    const levelKey = report.level && report.level.key ? report.level.key : 'low';
    const recommendations = report.recommendations || [];
    const affected = safeTarget(report);

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${esc(reportId(report))} — Sentinel AI Incident Report</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 40px 28px 56px; background: #eef2f5; color: #172026; font: 13px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
  .paper { max-width: 880px; margin: 0 auto; background: #fff; border: 1px solid #d7dfe6; border-radius: 10px; overflow: hidden; box-shadow: 0 12px 34px rgba(15, 30, 40, .08); }
  .masthead { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 22px 30px; background: #07131b; color: #eef7f4; }
  .brand { display: flex; align-items: center; gap: 11px; }
  .mark { display: grid; place-items: center; width: 34px; height: 38px; border: 1px solid rgba(88,237,188,.35); border-radius: 8px 8px 12px 12px; background: rgba(88,237,188,.08); color: #58edbc; font-size: 15px; }
  .brand strong { display: block; font-size: 15px; letter-spacing: .12em; }
  .brand span { display: block; color: #8ba39c; font-size: 10px; letter-spacing: .1em; text-transform: uppercase; }
  .masthead .doc { text-align: right; }
  .masthead .doc strong { display: block; font-size: 11px; letter-spacing: .12em; text-transform: uppercase; color: #58edbc; }
  .masthead .doc span { color: #9fb2ad; font-size: 10px; }
  .content { padding: 28px 30px 34px; }
  .title-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 22px; padding-bottom: 18px; border-bottom: 1px solid #e1e7ec; }
  h1 { margin: 0 0 4px; font-size: 23px; font-weight: 600; letter-spacing: -.03em; color: #0a1a22; }
  .subtitle { margin: 0; color: #62727c; font-size: 11.5px; }
  .verdict { min-width: 150px; padding: 12px 14px; border: 1px solid #dbe3e9; border-radius: 8px; background: #f7fafb; text-align: right; }
  .verdict .label { display: block; color: #6a7a84; font-size: 9px; letter-spacing: .12em; text-transform: uppercase; }
  .verdict .value { display: block; margin-top: 3px; font-size: 17px; font-weight: 600; }
  .verdict .score { display: block; color: #62727c; font-size: 11px; }
  .verdict.critical .value { color: #c22b40; } .verdict.high .value { color: #b85c1e; } .verdict.moderate .value { color: #94721a; } .verdict.low .value { color: #147a58; }
  .meta { width: 100%; margin: 18px 0 0; border-collapse: collapse; }
  .meta th, .meta td { padding: 8px 10px; border: 1px solid #e4eaef; text-align: left; vertical-align: top; }
  .meta th { width: 15%; background: #f6f9fb; color: #667680; font-size: 9.5px; letter-spacing: .08em; text-transform: uppercase; font-weight: 600; }
  .meta td { width: 35%; color: #1c2b33; }
  .section { margin-top: 24px; }
  .section h2 { margin: 0 0 10px; padding-bottom: 7px; border-bottom: 1px solid #e1e7ec; font-size: 12px; letter-spacing: .11em; text-transform: uppercase; color: #37505c; }
  .section h3 { margin: 16px 0 7px; font-size: 11px; color: #37505c; letter-spacing: .05em; text-transform: uppercase; }
  .narrative { margin: 12px 0 0; padding: 12px 14px; border-left: 3px solid #58c5a0; background: #f7fafb; color: #293b44; }
  table.data { width: 100%; border-collapse: collapse; }
  table.data th { padding: 7px 9px; border-bottom: 1px solid #d5dee5; color: #667680; font-size: 9.5px; letter-spacing: .07em; text-transform: uppercase; text-align: left; }
  table.data td { padding: 9px; border-bottom: 1px solid #e8edf1; vertical-align: top; }
  table.data td.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
  table.data td.empty { text-align: center; color: #71818a; padding: 16px; }
  .sev { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 8.5px; font-weight: 700; letter-spacing: .05em; white-space: nowrap; }
  .sev.critical { background: #fdeaed; color: #b11f34; } .sev.high { background: #fdf0e6; color: #a85218; } .sev.medium { background: #fbf5df; color: #806114; } .sev.low { background: #e8f7f1; color: #0d6b4d; } .sev.info { background: #edf1f5; color: #4b5d68; }
  .type { display: inline-block; padding: 2px 6px; border-radius: 4px; background: #edf3f7; color: #335666; font-size: 8.5px; font-weight: 700; letter-spacing: .05em; }
  .sub { display: block; color: #5e707a; margin-top: 2px; font-size: 11.5px; }
  .mono { display: block; margin-top: 4px; color: #49636f; font-family: "SFMono-Regular", Consolas, monospace; font-size: 10px; word-break: break-word; }
  .break { word-break: break-all; }
  .muted { color: #6a7a84; }
  ol.actions { margin: 0; padding-left: 20px; }
  ol.actions li { margin-bottom: 6px; }
  ol.notes { margin: 0; padding-left: 20px; }
  ol.notes li { margin-bottom: 8px; }
  .note-time { display: block; color: #71818a; font-size: 9.5px; letter-spacing: .03em; }
  .disclaimer { margin-top: 26px; padding: 13px 15px; border: 1px solid #eadfc2; border-radius: 7px; background: #fdfaf1; color: #6a571f; font-size: 10.5px; }
  .footer { display: flex; justify-content: space-between; gap: 16px; margin-top: 22px; padding-top: 11px; border-top: 1px solid #e1e7ec; color: #7a8992; font-size: 9.5px; }
  @media print {
    body { padding: 0; background: #fff; }
    .paper { max-width: none; border: 0; border-radius: 0; box-shadow: none; }
    .masthead { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .section, .title-row { break-inside: avoid; }
    table.data tr { break-inside: avoid; }
  }
</style>
</head>
<body>
  <div class="paper">
    <header class="masthead">
      <div class="brand">
        <div class="mark">&#9670;</div>
        <div><strong>SENTINEL AI</strong><span>Local threat intelligence</span></div>
      </div>
      <div class="doc"><strong>Incident report</strong><span>${esc(reportId(report))}</span></div>
    </header>
    <main class="content">
      <div class="title-row">
        <div>
          <h1>${esc(typeName(report.type))}</h1>
          <p class="subtitle">Generated ${esc(formatDate(generated))} · Analysis performed on this device</p>
        </div>
        <div class="verdict ${esc(levelKey)}">
          <span class="label">Verdict</span>
          <span class="value">${esc(verdictName(report))}</span>
          <span class="score">${esc(score)} · ${esc(confidence)} confidence</span>
        </div>
      </div>

      <table class="meta">
        <tr><th>Report ID</th><td>${esc(reportId(report))}</td><th>Scan time</th><td>${esc(formatDate(report.timestamp))}</td></tr>
        <tr><th>Scan type</th><td>${esc(typeName(report.type))}</td><th>Score / confidence</th><td>${esc(score)} · ${esc(confidence)}</td></tr>
        <tr><th>Source</th><td colspan="3" class="mono break">${esc(affected)}</td></tr>
        <tr><th>Engine</th><td>${esc(report.engine || 'Sentinel Rule Engine')} ${esc(report.engineVersion || '2.5.0')}</td><th>Data location</th><td>This device only</td></tr>
      </table>

      <section class="section">
        <h2>Assessment</h2>
        <p>${esc(report.summary || 'No assessment was recorded for this scan.')}</p>
      </section>

      <section class="section">
        <h2>Evidence and detection signals</h2>
        <table class="data">
          <thead><tr><th style="width:82px">Severity</th><th>Signal</th><th style="width:120px">Category</th><th style="width:52px">Weight</th></tr></thead>
          <tbody>${signalRows(report)}</tbody>
        </table>
      </section>

      <section class="section">
        <h2>Extracted indicators</h2>
        <table class="data">
          <thead><tr><th style="width:88px">Type</th><th>Normalized indicator</th><th style="width:140px">Category</th><th style="width:88px">Scan score</th></tr></thead>
          <tbody>${indicatorRows(indicators)}</tbody>
        </table>
        <p class="muted" style="margin:8px 0 0;font-size:10.5px">External reputation was not queried. An unknown indicator is not a safe indicator.</p>
      </section>

      <section class="section">
        <h2>Recommended actions</h2>
        ${recommendations.length
          ? `<ol class="actions">${recommendations.map((item) => `<li>${esc(item)}</li>`).join('')}</ol>`
          : '<p class="muted">No specific response actions were recorded.</p>'}
      </section>

      ${investigationSection(investigation)}

      <div class="disclaimer">Sentinel AI uses local, explainable heuristics. It does not provide guaranteed malware detection or live external reputation intelligence. A low score is not a guarantee of safety. Confirm high-stakes requests through a separate trusted channel.</div>

      <div class="footer">
        <span>Sentinel AI · Local-first security workspace</span>
        <span>${esc(reportId(report))} · ${esc(formatDate(generated))}</span>
      </div>
    </main>
  </div>
</body>
</html>`;
  }

  function download(report, options) {
    const html = buildReportHtml(report, options);
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    const stamp = new Date().toISOString().slice(0, 10);
    anchor.href = url;
    anchor.download = `sentinel-${report.type || 'scan'}-${stamp}-${reportId(report).toLowerCase()}.html`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1200);
    return anchor.download;
  }

  function print(report, options) {
    const html = buildReportHtml(report, options);
    const frame = document.createElement('iframe');
    frame.setAttribute('title', 'Sentinel AI printable report');
    frame.style.position = 'fixed';
    frame.style.right = '0';
    frame.style.bottom = '0';
    frame.style.width = '0';
    frame.style.height = '0';
    frame.style.border = '0';
    frame.style.opacity = '0';
    document.body.appendChild(frame);
    const remove = () => setTimeout(() => frame.remove(), 800);
    let printed = false;
    const invokePrint = () => {
      if (printed) return;
      printed = true;
      try {
        frame.contentWindow.focus();
        frame.contentWindow.print();
      } catch (_) { /* ignore */ }
      remove();
    };
    try {
      const doc = frame.contentWindow.document;
      doc.open();
      doc.write(html);
      doc.close();
      frame.onload = invokePrint;
      // Some browsers do not fire onload for document.write; print after layout.
      setTimeout(invokePrint, 500);
    } catch (_) {
      frame.remove();
      throw new Error('The print view could not be opened. Download the report instead.');
    }
  }

  window.SentinelReport = {
    buildReportHtml,
    download,
    print,
    reportId,
    formatDate,
    safeTarget,
  };
})();
