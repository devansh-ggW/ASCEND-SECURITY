(() => {
  'use strict';

  const $ = (s) => document.querySelector(s);
  const tabs = [...document.querySelectorAll('.tab')];
  const input = $('#scanner-input');
  const label = $('#scanner-label');
  const title = $('#scanner-title');
  const help = $('#scanner-help');
  const scanBtn = $('#scan-btn');
  const fileZone = $('#file-zone');
  const fileInput = $('#file-input');
  const result = $('#result');
  const inputMeta = $('#input-meta');
  let mode = 'url';

  const configs = {
    url: {
      label: 'URL ANALYZER', title: 'Check a link before you open it.',
      help: 'Paste a suspicious URL. ASCEND checks transport, structure, obfuscation, domains and common social-engineering patterns.',
      placeholder: 'https://example.com/login'
    },
    message: {
      label: 'MESSAGE ANALYZER', title: 'Check the pressure behind the message.',
      help: 'Paste an SMS, email, DM or support message. ASCEND looks for urgency, credential requests, payment pressure and other scam patterns.',
      placeholder: 'Your account will be suspended today. Verify your details at https://...'
    },
    file: {
      label: 'FILE INSPECTOR', title: 'Inspect a file without running it.',
      help: 'Choose a local file. ASCEND reads safe metadata, checks common suspicious indicators and computes a SHA-256 fingerprint in your browser.',
      placeholder: 'File inspection is available below.'
    }
  };

  function setMode(next) {
    mode = next;
    tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === next));
    const c = configs[next];
    label.textContent = c.label;
    title.textContent = c.title;
    help.textContent = c.help;
    input.placeholder = c.placeholder;
    input.value = '';
    inputMeta.textContent = next === 'file' ? '0 files selected' : '0 characters';
    fileZone.classList.toggle('hidden', next !== 'file');
    input.closest('.input-zone').classList.toggle('hidden', next === 'file');
    scanBtn.classList.toggle('hidden', next === 'file');
    result.classList.add('hidden');
  }

  tabs.forEach(t => t.addEventListener('click', () => setMode(t.dataset.tab)));
  input.addEventListener('input', () => inputMeta.textContent = `${input.value.length.toLocaleString()} characters`);
  fileInput.addEventListener('change', () => {
    const f = fileInput.files[0];
    inputMeta.textContent = f ? f.name : '0 files selected';
    if (f) inspectFile(f);
  });

  const escapeHTML = (s) => String(s).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  const unique = a => [...new Set(a)];

  function addFinding(list, text, severity='review') { list.push({ text, severity }); }

  function analyzeUrl(raw) {
    const findings = [];
    let score = 0;
    let url;
    try { url = new URL(raw.trim()); } catch { return { score: 90, verdict: 'danger', findings: [{text:'The input is not a valid URL.', severity:'danger'}] }; }
    const host = url.hostname.toLowerCase();
    const full = raw.trim();
    if (url.protocol !== 'https:') { score += 18; addFinding(findings, 'Connection is not using HTTPS.', 'review'); }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) { score += 28; addFinding(findings, 'The hostname is a raw IP address.', 'danger'); }
    if (host.includes('xn--')) { score += 25; addFinding(findings, 'Punycode is present in the hostname; verify the domain carefully.', 'review'); }
    if (url.username || url.password) { score += 30; addFinding(findings, 'User-information fields are embedded before the hostname.', 'danger'); }
    if (url.port && !['80','443'].includes(url.port)) { score += 15; addFinding(findings, `Unusual port detected: ${url.port}.`, 'review'); }
    const labels = host.split('.').filter(Boolean);
    if (labels.length >= 4) { score += 10; addFinding(findings, 'The hostname contains many subdomain levels.', 'review'); }
    if (/bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly/i.test(host)) { score += 18; addFinding(findings, 'A URL-shortening service is being used.', 'review'); }
    if (/[\u0000-\u001f\u007f]|%[0-9a-f]{2}/i.test(full)) { score += 8; addFinding(findings, 'Encoded or control characters are present in the URL.', 'review'); }
    if (/[\u200B-\u200F\u2060\uFEFF]/.test(full)) { score += 24; addFinding(findings, 'Invisible Unicode characters were detected.', 'danger'); }
    if (full.length > 180) { score += 8; addFinding(findings, 'The URL is unusually long.', 'review'); }
    if (/[?&](redirect|url|next|return|continue)=/i.test(url.search)) { score += 10; addFinding(findings, 'A redirect-style parameter is present.', 'review'); }
    if (/(login|verify|secure|account|wallet|password|support|claim|reward|refund|invoice)/i.test(full)) { score += 12; addFinding(findings, 'Account, payment or reward language appears in the URL.', 'review'); }
    if ((full.match(/@/g)||[]).length) { score += 10; addFinding(findings, 'The URL contains an @ symbol; confirm where the browser will actually connect.', 'review'); }
    score = Math.min(100, score);
    return { score, verdict: score >= 55 ? 'danger' : score >= 25 ? 'suspicious' : 'safe', findings: unique(findings.map(x=>JSON.stringify(x))).map(x=>JSON.parse(x)), host };
  }

  function analyzeMessage(raw) {
    const findings = []; let score = 0; const text = raw.trim();
    const rules = [
      [/urgent|immediately|act now|last chance|within \d+ (minutes?|hours?)/i, 20, 'Urgency or countdown language is being used.'],
      [/otp|one[- ]time password|verification code|passcode/i, 25, 'The message asks for or references a verification code.'],
      [/password|login|credential|pin|cvv|card number|bank details/i, 28, 'Sensitive credentials or payment details are mentioned.'],
      [/refund|payment|invoice|fee|transfer|send money|pay now/i, 20, 'Payment or money-transfer pressure is present.'],
      [/won|winner|prize|reward|gift card|lottery|free money/i, 22, 'A prize or reward claim is being used as bait.'],
      [/suspend|blocked|locked|deactivated|legal action|police/i, 22, 'Threats of account loss or consequences are present.'],
      [/anydesk|teamviewer|remote access|screen share|install this app/i, 30, 'Remote-access or screen-sharing language is present.'],
      [/https?:\/\/[^\s]+/i, 8, 'A clickable web link is included; verify its destination independently.']
    ];
    rules.forEach(([re, pts, msg]) => { if (re.test(text)) { score += pts; addFinding(findings, msg, pts >= 25 ? 'danger' : 'review'); } });
    if (/[\u200B-\u200F\u2060\uFEFF]/.test(text)) { score += 20; addFinding(findings, 'Invisible Unicode characters were detected.', 'danger'); }
    if (/[А-Яа-яЁё]/.test(text) && /[A-Za-z]/.test(text)) { score += 8; addFinding(findings, 'Mixed writing systems are present; this can sometimes be used for visual impersonation.', 'review'); }
    score = Math.min(100, score);
    if (!findings.length) addFinding(findings, 'No common scam signals were detected by this local ruleset.', 'safe');
    return { score, verdict: score >= 55 ? 'danger' : score >= 25 ? 'suspicious' : 'safe', findings };
  }

  async function sha256(file) {
    const buffer = await file.arrayBuffer();
    const hash = await crypto.subtle.digest('SHA-256', buffer);
    return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2,'0')).join('');
  }

  async function inspectFile(file) {
    result.classList.remove('hidden');
    result.innerHTML = '<div class="result-head"><b>INSPECTING LOCAL FILE…</b><span class="result-score">HASHING</span></div>';
    const findings = []; let score = 0;
    const name = file.name;
    const lower = name.toLowerCase();
    if (/\.(exe|msi|dll|scr|com|bat|cmd|ps1|vbs|vbe|js|jse|hta|wsf|wsh)$/i.test(lower)) { score += 22; addFinding(findings, 'The file is an executable or script type.', 'review'); }
    if (/\.(pdf|docx?|xlsx?|jpg|jpeg|png|zip)\.(exe|scr|bat|cmd|js|vbs)$/i.test(lower)) { score += 45; addFinding(findings, 'The filename uses a suspicious double extension.', 'danger'); }
    if (/[\u0000-\u001f\u007f]/.test(name)) { score += 25; addFinding(findings, 'The filename contains control characters.', 'danger'); }
    if (file.size > 250 * 1024 * 1024) { score += 8; addFinding(findings, 'The file is unusually large for a quick browser inspection.', 'review'); }
    const first = new Uint8Array(await file.slice(0, 4).arrayBuffer());
    if (first[0] === 0x4d && first[1] === 0x5a) { score += 18; addFinding(findings, 'Windows PE/MZ executable signature detected.', 'review'); }
    const hash = await sha256(file);
    if (!findings.length) addFinding(findings, 'No obvious filename or header indicators were detected.', 'safe');
    score = Math.min(100, score);
    renderResult({score, verdict: score >= 55 ? 'danger' : score >= 25 ? 'suspicious' : 'safe', findings, meta: `${escapeHTML(name)} · ${(file.size/1024/1024).toFixed(2)} MB · SHA-256 ${hash}`});
  }

  function renderResult(data) {
    const names = {safe:'LOW SIGNAL', suspicious:'SUSPICIOUS', danger:'HIGH RISK'};
    result.classList.remove('hidden');
    result.innerHTML = `<div class="result-head"><div><b>ANALYSIS COMPLETE</b><div style="color:#68796b;font:10px ui-monospace;margin-top:5px">${data.meta || 'Local heuristic analysis'}</div></div><span class="result-score ${data.verdict}">${names[data.verdict]} · ${data.score}/100</span></div><div class="findings">${data.findings.map(f=>`<div class="finding-row"><b>${f.severity === 'danger' ? '!' : f.severity === 'safe' ? '✓' : '›'}</b><span>${escapeHTML(f.text)}</span></div>`).join('')}</div>`;
    try { localStorage.setItem('ascend:lastScan', JSON.stringify({at:Date.now(),mode,score:data.score,verdict:data.verdict})); } catch (_) {}
  }

  scanBtn.addEventListener('click', () => {
    const raw = input.value.trim();
    if (!raw) { input.focus(); return; }
    scanBtn.disabled = true; scanBtn.innerHTML = 'Analyzing…';
    result.classList.add('hidden');
    window.setTimeout(() => {
      renderResult(mode === 'url' ? analyzeUrl(raw) : analyzeMessage(raw));
      scanBtn.disabled = false; scanBtn.innerHTML = 'Analyze <span>↗</span>';
    }, 480);
  });

  setMode('url');
})();
