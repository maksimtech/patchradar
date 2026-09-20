let allCves = [];
let currentFilter = 'ALL';
let currentSearch = '';

// The key is only needed for write/scan endpoints; reads stay public.
// Stored per-browser so it is never baked into the served HTML.
function apiKey() {
  try { return localStorage.getItem('patchradar_api_key') || ''; }
  catch (e) { return ''; }
}

function setApiKey(v) {
  try { localStorage.setItem('patchradar_api_key', v); } catch (e) { /* private mode */ }
}

async function api(path, method='GET', body=null, retryOn401=true) {
  const headers = {'Content-Type': 'application/json'};
  const key = apiKey();
  if (key) headers['X-API-Key'] = key;
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  try {
    const r = await fetch(path, opts);
    if (r.status === 401 && retryOn401) {
      const entered = prompt('This PatchRadar instance requires an API key (PATCHRADAR_API_KEY):', key);
      if (entered) {
        setApiKey(entered.trim());
        return api(path, method, body, false);
      }
      toast('API key required', '#f85149');
      return null;
    }
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      toast(`Error ${r.status}: ${err.detail || r.statusText}`, '#f85149');
      return null;
    }
    try {
      // awaited here: an unawaited r.json() escaped this try as an
      // unhandled rejection whenever a proxy answered 200 with HTML
      return await r.json();
    } catch (e) {
      toast('Invalid response from PatchRadar', '#f85149');
      return null;
    }
  } catch (e) {
    toast('Network error — is PatchRadar running?', '#f85149');
    return null;
  }
}

// Every failure path of api() returns null after toasting the reason, so
// callers only need `if (!data) return;` — never dereference blindly.

function formatScore(score, missing) {
  // 0.0 is a real CVSS score; only null/undefined/non-numbers are missing
  return (typeof score === 'number' && Number.isFinite(score)) ? score.toFixed(1) : missing;
}

function toast(msg, color='#238636') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.background = color;
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 3000);
}

async function loadWatchlist() {
  const data = await api('/api/watchlist');
  if (!data || !Array.isArray(data.watchlist)) return;
  const el = document.getElementById('watchlist-items');
  if (!data.watchlist.length) {
    el.innerHTML = '<div style="color:#8b949e;font-size:0.85rem;padding:0.5rem 0">No software added yet</div>';
    return;
  }
  // CWE-79 fix: build watchlist via DOM API
  el.innerHTML = '';
  data.watchlist.forEach(sw => {
    const div = document.createElement('div');
    div.className = 'watchlist-item';

    const span = document.createElement('span');
    span.textContent = ' ' + sw;  // textContent prevents XSS

    const btn = document.createElement('button');
    btn.className = 'btn-remove';
    btn.title = 'Remove';
    btn.textContent = '×';  // × symbol
    btn.addEventListener('click', () => removeSoftware(sw));  // closure sicura

    div.appendChild(span);
    div.appendChild(btn);
    el.appendChild(div);
  });

}

async function addSoftware() {
  const input = document.getElementById('add-input');
  const sw = input.value.trim();
  if (!sw) return;
  const data = await api(`/api/watchlist/${encodeURIComponent(sw)}`, 'POST');
  if (!data) return;   // api() already reported the failure
  if (data.added) {
    toast(` Added ${sw}`);
    input.value = '';
    await loadWatchlist();
    await loadStats();
  } else {
    toast(` ${sw} already in watchlist`, '#d29922');
  }
}

async function removeSoftware(sw) {
  const data = await api(`/api/watchlist/${encodeURIComponent(sw)}`, 'DELETE');
  if (!data) return;
  toast(data.removed ? `Removed ${sw}` : `${sw} was not in the watchlist`, '#f85149');
  await loadWatchlist();
  await loadStats();
  await loadCves();
}

async function importFromFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  const text = await file.text();
  const lines = text.split('\n')
    .map(l => l.trim().split(/[ \t]{2,}/)[0].trim().toLowerCase())
    .filter(l => l && l.length > 1 && !l.startsWith('-') && l !== 'name');
  if (!lines.length) { toast('No software found in file', '#d29922'); return; }
  const data = await api('/api/watchlist/import', 'POST', { software: lines });
  if (!data) { event.target.value = ''; return; }   // request failed; api() already reported it
  const parts = [`Imported ${data.added.length}`];
  if (data.skipped.length) parts.push(`${data.skipped.length} already present`);
  if (data.rejected.length) parts.push(`${data.rejected.length} invalid`);
  toast(parts.join(', '), data.rejected.length ? '#d29922' : '#238636');
  await loadWatchlist();
  // Reset file input
  event.target.value = '';
}

async function scanAll() {
  const btn = document.getElementById('scan-btn');
  btn.innerHTML = '<span class="spinner"></span>Scanning...';
  btn.disabled = true;
  try {
    const data = await api('/api/scan?days=30', 'POST');
    if (!data) return;   // finally{} still resets the button
    const failed = Array.isArray(data.errors) ? data.errors : [];
    if (failed.length) {
      // A failed source must not read as "Found 0 CVEs".
      const what = failed.map(e => `${e.source} ${String(e.reason).replace('_', ' ')}` +
                                   (e.status ? ` (${e.status})` : '') + ` for ${e.software}`);
      toast(`Scan incomplete — ${what.join('; ')}. ${data.total} CVEs found so far`, '#d29922');
    } else if (data.timed_out) {
      toast(`Scan timed out — ${data.scanned}/${data.watched} scanned, ${data.total} CVEs so far`, '#d29922');
    } else if (data.total !== undefined) {
      toast(`Found ${data.total} CVEs`);
    }
    await loadCves();
    await loadStats();
  } finally {
    btn.innerHTML = 'Scan All';
    btn.disabled = false;
  }
}

async function loadCves() {
  const data = await api('/api/cves?limit=200');
  if (!data || !Array.isArray(data.cves)) return;
  allCves = data.cves;
  renderTable();
}

function setFilter(severity, btn) {
  currentFilter = severity;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderTable();
}

function severityClass(s) {
  const m = {'CRITICAL':'critical','HIGH':'high','MEDIUM':'medium','LOW':'low'};
  return m[(s||'').toUpperCase()] || '';
}

function scoreClass(score) {
  if (typeof score !== 'number' || !Number.isFinite(score)) return '';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

function renderTable() {
  const searchTerm = currentSearch.toLowerCase().trim();
  const filtered = allCves.filter(c => {
    const matchSeverity = currentFilter === 'ALL' || (c.severity||'').toUpperCase() === currentFilter;
    const matchSearch = !searchTerm || (c.software||'').toLowerCase().includes(searchTerm) || (c.id||'').toLowerCase().includes(searchTerm);
    return matchSeverity && matchSearch;
  });

  const wrap = document.getElementById('cve-table-wrap');
  if (!filtered.length) {
    // CWE-79 fix: the search term is user input, so build the message via DOM API
    const empty = document.createElement('div');
    empty.className = 'empty';
    if (searchTerm) {
      const before = document.createElement('span');
      before.textContent = 'No CVEs found for "';
      const term = document.createElement('strong');
      term.textContent = searchTerm;
      const after = document.createElement('span');
      after.textContent = '". Try a different search term or run a new scan.';
      empty.appendChild(before);
      empty.appendChild(term);
      empty.appendChild(after);
    } else {
      empty.textContent = 'No CVEs found. Run a scan first.';
    }
    wrap.innerHTML = '';
    wrap.appendChild(empty);
    return;
  }

  // CWE-79 fix: build table via DOM API instead of innerHTML
  const table = document.createElement('table');
  
  // Header
  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  ['CVE ID','Software','Score','Severity','Description','Source','Published'].forEach(h => {
    const th = document.createElement('th');
    th.textContent = h;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(thead);

  // Body
  const tbody = document.createElement('tbody');
  filtered.forEach(cve => {
    const tr = document.createElement('tr');

    // CVE ID  link
    const tdId = document.createElement('td');
    const a = document.createElement('a');
    a.className = 'cve-link';
    a.href = '#';
    a.addEventListener('click', (e) => { e.preventDefault(); openCveDetail(cve.id); });
    a.textContent = cve.id || '';
    tdId.appendChild(a);
    tr.appendChild(tdId);

    // Software
    const tdSw = document.createElement('td');
    const spanSw = document.createElement('span');
    spanSw.className = 'source-badge';
    spanSw.textContent = cve.software || '';
    tdSw.appendChild(spanSw);
    tr.appendChild(tdSw);

    // Score
    const tdScore = document.createElement('td');
    const spanScore = document.createElement('span');
    spanScore.className = `score ${scoreClass(cve.cvss_score)}`;
    spanScore.textContent = formatScore(cve.cvss_score, 'N/A');
    tdScore.appendChild(spanScore);
    tr.appendChild(tdScore);

    // Severity
    const tdSev = document.createElement('td');
    const spanSev = document.createElement('span');
    const sev = (cve.severity || 'UNKNOWN').toUpperCase();
    spanSev.className = `severity-badge sev-${sev}`;
    spanSev.textContent = sev;
    tdSev.appendChild(spanSev);
    tr.appendChild(tdSev);

    // Description  textContent prevents XSS
    const tdDesc = document.createElement('td');
    tdDesc.className = 'desc';
    const desc = cve.description || '';
    tdDesc.textContent = desc.length > 120 ? desc.substring(0, 120) + '...' : desc;
    tr.appendChild(tdDesc);

    // Source
    const tdSrc = document.createElement('td');
    const spanSrc = document.createElement('span');
    spanSrc.className = 'source-badge';
    spanSrc.textContent = cve.source || '';
    tdSrc.appendChild(spanSrc);
    tr.appendChild(tdSrc);

    // Published
    const tdPub = document.createElement('td');
    tdPub.style.color = '#8b949e';
    tdPub.style.fontSize = '0.8rem';
    tdPub.textContent = cve.published_at ? cve.published_at.substring(0,10) : '';
    tr.appendChild(tdPub);

    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  wrap.innerHTML = '';
  wrap.appendChild(table);
}


async function loadStats() {
  const data = await api('/api/stats');
  if (!data) return;
  document.getElementById('stat-total').textContent = data.total_cves;
  document.getElementById('stat-watched').textContent = data.watched;
  const sev = data.by_severity || {};
  document.getElementById('stat-critical').textContent = sev['CRITICAL'] || 0;
  document.getElementById('stat-high').textContent = sev['HIGH'] || 0;
  document.getElementById('stat-medium').textContent = sev['MEDIUM'] || 0;
  document.getElementById('stat-low').textContent = sev['LOW'] || 0;

  const total = data.total_cves || 1;
  const sevOrder = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'];
  const sevColors = {'CRITICAL':'critical','HIGH':'high','MEDIUM':'medium','LOW':'low','UNKNOWN':'unknown'};
  // CWE-79 fix: build severity chart via DOM API
  const sevChart = document.getElementById('severity-chart');
  sevChart.innerHTML = '';
  sevOrder
    .filter(s => sev[s])
    .forEach(s => {
      const div = document.createElement('div');
      div.className = 'chart-bar';

      const label = document.createElement('div');
      label.className = 'label';
      label.textContent = s;  // hardcoded  safe

      const barWrap = document.createElement('div');
      barWrap.className = 'bar-wrap';

      const bar = document.createElement('div');
      bar.className = `bar bar-${sevColors[s]}`;  // hardcoded  safe
      bar.style.width = Math.round((sev[s]/total)*100) + '%';
      bar.textContent = String(Number.parseInt(sev[s]) || 0);  // sanitized integer

      barWrap.appendChild(bar);
      div.appendChild(label);
      div.appendChild(barWrap);
      sevChart.appendChild(div);
    });

  const bySw = data.by_software || {};
  // CWE-79 fix: build software chart via DOM API
  const swChart = document.getElementById('software-chart');
  swChart.innerHTML = '';
  const maxSw = Math.max(...Object.values(bySw), 1);
  Object.entries(bySw)
    .sort((a,b) => b[1]-a[1])
    .forEach(([sw, count]) => {
      const div = document.createElement('div');
      div.className = 'chart-bar';

      const label = document.createElement('div');
      label.className = 'label';
      label.textContent = sw;  // textContent prevents XSS

      const barWrap = document.createElement('div');
      barWrap.className = 'bar-wrap';

      const bar = document.createElement('div');
      bar.className = 'bar bar-high';
      bar.style.width = Math.round((count/maxSw)*100) + '%';
      bar.textContent = count;

      barWrap.appendChild(bar);
      div.appendChild(label);
      div.appendChild(barWrap);
      swChart.appendChild(div);
    });

}


async function openCveDetail(cveId) {
  try {
    const data = await api(`/api/cves/${encodeURIComponent(cveId)}`);
    if (!data) return;   // don't open an empty modal on a 404
    
    document.getElementById('modal-cve-id').textContent = data.id || cveId;
    document.getElementById('modal-software').textContent = data.software || '';
    document.getElementById('modal-source').textContent = data.source || '';
    document.getElementById('modal-score').textContent = formatScore(data.cvss_score, '');
    document.getElementById('modal-cvss-version').textContent = data.cvss_version || '';
    document.getElementById('modal-description').textContent = data.description || '';
    
    const sev = (data.severity || 'UNKNOWN').toUpperCase();
    const sevEl = document.getElementById('modal-severity');
    sevEl.textContent = sev;
    sevEl.className = `value severity-badge sev-${sev}`;
    
    const pub = data.published_at ? data.published_at.substring(0, 10) : '';
    document.getElementById('modal-published').textContent = pub;
    
    // Links
    const linksEl = document.getElementById('modal-links');
    linksEl.innerHTML = '';
    if (data.url) {
      const a = document.createElement('a');
      a.className = 'modal-link';
      a.href = data.url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = 'View on NVD';
      linksEl.appendChild(a);
    }
    if (data.id && data.id.startsWith('CVE-')) {
      const a2 = document.createElement('a');
      a2.className = 'modal-link';
      a2.href = `https://msrc.microsoft.com/update-guide/en-US/vulnerability/${data.id}`;
      a2.target = '_blank';
      a2.rel = 'noopener noreferrer';
      a2.textContent = 'View on MSRC';
      linksEl.appendChild(a2);
    }
    
    document.getElementById('cve-modal').classList.add('active');
  } catch(e) {
    console.error('Error loading CVE detail:', e);
  }
}

function closeModal() {
  document.getElementById('cve-modal').classList.remove('active');
}

// Close on Escape key
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});

// Every handler is bound here: the CSP is script-src 'self', so on*=
// attributes in the markup would simply never run.
function bindControls() {
  const addInput = document.getElementById('add-input');
  addInput.addEventListener('keydown', e => { if (e.key === 'Enter') addSoftware(); });
  document.getElementById('add-btn').addEventListener('click', () => addSoftware());
  document.getElementById('scan-btn').addEventListener('click', () => scanAll());
  document.getElementById('import-btn').addEventListener('click',
    () => document.getElementById('import-file').click());
  document.getElementById('import-file').addEventListener('change', e => importFromFile(e));

  document.querySelectorAll('[data-filter]').forEach(btn =>
    btn.addEventListener('click', () => setFilter(btn.dataset.filter, btn)));

  const search = document.getElementById('search-input');
  search.addEventListener('input', () => { currentSearch = search.value; renderTable(); });
  search.addEventListener('keydown', e => { if (e.key === 'Enter') e.preventDefault(); });

  const modal = document.getElementById('cve-modal');
  modal.addEventListener('click', e => { if (e.target === modal) closeModal(); });
  document.getElementById('modal-close').addEventListener('click', () => closeModal());
}

async function init() {
  await loadWatchlist();
  await loadStats();
  await loadCves();
}

bindControls();
init();
