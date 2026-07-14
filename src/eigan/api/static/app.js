/* EIGAN — SPA do dashboard SOC. Vanilla JS, sem build.
   Roteamento por hash · componentes reutilizáveis · gráficos SVG inline (sem dep).
   ZERO regra de negócio: tudo vem de /api/v1 (CLAUDE.md §10/§18). */
'use strict';

// ── Helpers de API ───────────────────────────────────────────────────────────
const API = '/api/v1';
const api = (p) => fetch(API + p).then((r) => (r.ok ? r.json() : Promise.reject(r.status)));
const apiPost = (p, body) =>
  fetch(API + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
    .then(async (r) => { const d = await r.json().catch(() => ({})); if (!r.ok) throw { status: r.status, detail: d.detail || r.statusText }; return d; });

const el = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim() || '#888';
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEVKEY = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' };
const SEV_VAR = { critical: '--crit', high: '--high', medium: '--med', low: '--low', info: '--info' };
const fmtDate = (s) => esc((s || '').slice(0, 16).replace('T', ' '));

// ── Tema (dark/light, persistido) ────────────────────────────────────────────
const Theme = {
  cur: () => document.documentElement.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'),
  toggle() {
    const next = this.cur() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('eigan-theme', next);
    this.icon();
  },
  icon() { const b = el('themebtn'); if (b) b.textContent = this.cur() === 'dark' ? '🌙' : '☀️'; },
  init() { this.icon(); const b = el('themebtn'); if (b) b.onclick = () => this.toggle(); },
};

// ── Componentes reutilizáveis ─────────────────────────────────────────────────
const sevPill = (s) => `<span class="pill s-${esc(s)}">${esc(s)}</span>`;
const kpi = (n, l, ic, accent) => `<div class="kpi ${accent ? 'accent' : ''}">${ic ? `<span class="ic">${ic}</span>` : ''}<div class="n">${n}</div><div class="l">${esc(l)}</div></div>`;
const kevCell = (r) => (r ? (r.kev ? '<span class="kev">KEV</span>' : r.kev_verified ? 'não' : '<span class="unv">?</span>') : '<span class="unv">?</span>');

function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.innerHTML = esc(msg);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3400);
}

// Score de postura — MESMA fórmula do PDF (report/corporate.py), no cliente.
function securityScore(sev, kev = 0) {
  const P = { critical: 22, high: 11, medium: 4, low: 1, info: 0 };
  let s = 100;
  for (const k in P) s -= (sev[k] || 0) * P[k];
  s -= 8 * (kev || 0);
  s = Math.max(0, Math.min(100, Math.round(s)));
  const g = s >= 90 ? ['A', 'Excelente', '--ok'] : s >= 80 ? ['B', 'Boa', '--ok'] : s >= 70 ? ['C', 'Aceitável', '--med']
    : s >= 55 ? ['D', 'Frágil', '--high'] : s >= 35 ? ['E', 'Crítica', '--crit'] : ['F', 'Severa', '--crit'];
  return { score: s, grade: g[0], label: g[1], color: cssVar(g[2]) };
}

// Donut de severidade (SVG puro, adapta ao tema via cssVar).
function donutSVG(counts, size = 132) {
  const total = SEV.reduce((a, s) => a + (counts[s] || 0), 0);
  const r = size / 2 - 12, c = size / 2, circ = 2 * Math.PI * r;
  const track = `<circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${cssVar('--bg2')}" stroke-width="13"/>`;
  if (!total) return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${track}<text x="${c}" y="${c + 4}" text-anchor="middle" font-size="12" fill="${cssVar('--muted')}">sem findings</text></svg>`;
  let off = 0, segs = '';
  for (const s of SEV) {
    const n = counts[s] || 0; if (!n) continue;
    const seg = (n / total) * circ;
    segs += `<circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${cssVar(SEV_VAR[s])}" stroke-width="13" stroke-dasharray="${seg.toFixed(2)} ${(circ - seg).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 ${c} ${c})" style="transition:stroke-dasharray .5s"/>`;
    off += seg;
  }
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${track}${segs}<text x="${c}" y="${c - 1}" text-anchor="middle" font-size="25" font-weight="800" fill="${cssVar('--text')}">${total}</text><text x="${c}" y="${c + 15}" text-anchor="middle" font-size="10" fill="${cssVar('--muted')}">findings</text></svg>`;
}

// Gauge semicircular do score.
function gaugeSVG(sc, size = 150) {
  const r = size / 2 - 15, cx = size / 2, cy = size / 2 + 8;
  const a = Math.PI - (sc.score / 100) * Math.PI;
  const x1 = cx - r, y1 = cy, x2 = cx + r * Math.cos(a), y2 = cy - r * Math.sin(a), bx = cx + r;
  return `<svg width="${size}" height="${size / 2 + 26}" viewBox="0 0 ${size} ${size / 2 + 26}">
    <path d="M ${x1} ${y1} A ${r} ${r} 0 0 1 ${bx} ${cy}" fill="none" stroke="${cssVar('--bg2')}" stroke-width="12" stroke-linecap="round"/>
    <path d="M ${x1} ${y1} A ${r} ${r} 0 0 1 ${x2.toFixed(1)} ${y2.toFixed(1)}" fill="none" stroke="${sc.color}" stroke-width="12" stroke-linecap="round" style="transition:stroke-dasharray .6s"/>
    <text x="${cx}" y="${cy - 4}" text-anchor="middle" font-size="29" font-weight="800" fill="${sc.color}">${sc.score}</text>
    <text x="${cx}" y="${cy + 12}" text-anchor="middle" font-size="10.5" fill="${cssVar('--muted')}">/100 · nota ${sc.grade}</text></svg>`;
}

function sevLegend(counts) {
  return `<div class="legend">${SEV.map((s) => `<div class="li"><span class="dot" style="background:${cssVar(SEV_VAR[s])}"></span>${s}<span class="n">${counts[s] || 0}</span></div>`).join('')}</div>`;
}

function scanRow(s) {
  const st = s.finished_at ? 'completed' : 'running';
  const ic = s.finished_at ? '✅' : '⏳';
  return `<tr class="clickable" onclick="location.hash='#/scan/${s.id}'">
    <td class="mono">#${s.id}</td><td>${esc(s.engagement || '—')}</td><td>${esc(s.profile)}</td>
    <td><span class="badge st-${st}">${ic} ${s.finished_at ? 'concluído' : 'em curso'}</span></td>
    <td class="mono small">${fmtDate(s.started_at)}</td></tr>`;
}

// ── Chat com a IA (Conversation Engine) — durante e depois do scan ────────────
const CHAT_SUGGEST = ['Qual o risco mais crítico?', 'Como corrijo o mais grave?', 'Tem exploit público?', 'Quais os próximos passos?'];
function chatPanel(mount, chatUrl, { placeholder = 'Pergunte à IA sobre este scan…', live = false } = {}) {
  const history = [];
  mount.innerHTML = `<div class="chat">
    <div class="chat-log" id="chatlog"><div class="muted small">${live ? '💬 Converse com a IA enquanto ela escaneia — ela responde com o que já achou.' : '💬 Pergunte sobre os resultados: risco, exploit, correção, priorização.'}</div></div>
    <div class="chat-suggest">${CHAT_SUGGEST.map((s) => `<button class="chip" data-q="${esc(s)}">${esc(s)}</button>`).join('')}</div>
    <div class="row" style="margin-top:8px"><input type="text" id="chatq" placeholder="${esc(placeholder)}" style="flex:1"><button class="btn-primary" id="chatsend">Enviar</button></div></div>`;
  const log = el('chatlog');
  const add = (role, text) => { const d = document.createElement('div'); d.className = 'chat-msg ' + role; d.innerHTML = (role === 'user' ? '🧑 ' : '🤖 ') + esc(text).replace(/\n/g, '<br>'); log.appendChild(d); log.scrollTop = log.scrollHeight; return d; };
  async function send(q) {
    q = (q || el('chatq').value).trim(); if (!q) return;
    el('chatq').value = ''; add('user', q); history.push({ role: 'user', content: q });
    const wait = add('ai', '⏳ pensando…');
    try { const r = await apiPost(chatUrl, { question: q, history }); wait.remove(); add('ai', r.answer || '(sem resposta)'); history.push({ role: 'assistant', content: r.answer || '' }); }
    catch (e) { wait.remove(); add('ai', e.status === 428 ? 'Configure um provedor de IA para conversar (menu → Configuração).' : ('Erro: ' + (e.detail || e.status))); }
  }
  el('chatsend').onclick = () => send();
  el('chatq').addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
  mount.querySelectorAll('.chip').forEach((b) => (b.onclick = () => send(b.dataset.q)));
}
async function aiAnalysisPanel(mount, scanId) {
  const render = (text) => {
    mount.innerHTML = `<div class="ai-analysis">${esc(text || 'Sem análise ainda.').replace(/\n/g, '<br>')}</div>
      <button class="btn-ghost" id="anregen" style="margin-top:8px">↻ Regerar análise</button>`;
    el('anregen').onclick = async () => {
      mount.innerHTML = '<div class="muted small">⏳ regerando…</div>';
      try { const r = await apiPost('/scans/' + scanId + '/analysis', {}); render(r.analysis); }
      catch (e) { render(e.status === 428 ? 'Configure um provedor de IA (menu → Configuração).' : 'Falha ao regerar.'); }
    };
  };
  mount.innerHTML = '<div class="muted small">⏳ a IA correlacionou e concluiu — carregando…</div>';
  try { const r = await api('/scans/' + scanId + '/analysis'); render(r.analysis); }  // auto (usa a análise do fim do scan)
  catch (e) { mount.innerHTML = `<div class="muted small">${e === 428 ? 'Configure um provedor de IA (menu → Configuração).' : 'Análise indisponível.'}</div>`; }
}

const PRIO_CLASS = { P1: 's-critical', P2: 's-high', P3: 's-medium', P4: 's-low' };
function remediationHTML(plan) {
  if (!plan || (!plan.items || !plan.items.length) && !plan.summary && !plan.text)
    return '<div class="muted small">Sem plano de remediação (nenhum achado acionável ou IA indisponível).</div>';
  let h = '';
  if (plan.summary) h += `<p class="rem-summary">${esc(plan.summary).replace(/\n/g, '<br>')}</p>`;
  if (plan.items && plan.items.length) {
    h += `<div class="tablewrap"><table class="rem-table">
      <thead><tr><th>Prio.</th><th>Problema / Ativo</th><th>O que corrigir</th><th>Como corrigir</th><th>Esforço</th></tr></thead>
      <tbody>${plan.items.map((it) => `<tr>
        <td><span class="pill ${PRIO_CLASS[(it.priority || '').toUpperCase()] || 's-info'}">${esc(it.priority || '—')}</span></td>
        <td><strong>${esc(it.title || '—')}</strong>${it.asset ? `<br><span class="mono small">${esc(it.asset)}</span>` : ''}</td>
        <td>${esc(it.what || '—').replace(/\n/g, '<br>')}</td>
        <td>${esc(it.how || '—').replace(/\n/g, '<br>')}</td>
        <td>${esc(it.effort || '—')}</td></tr>`).join('')}</tbody></table></div>`;
  } else if (plan.text) {
    h += `<div class="ai-analysis">${esc(plan.text).replace(/\n/g, '<br>')}</div>`;
  }
  return h;
}
async function aiRemediationPanel(mount, scanId) {
  const render = (plan) => {
    mount.innerHTML = remediationHTML(plan) +
      `<button class="btn-ghost" id="remregen" style="margin-top:8px">↻ Regerar plano</button>`;
    el('remregen').onclick = async () => {
      mount.innerHTML = '<div class="muted small">⏳ a IA está remontando o plano…</div>';
      try { const r = await apiPost('/scans/' + scanId + '/remediation', {}); render(r.remediation); }
      catch (e) { mount.innerHTML = `<div class="muted small">${e.status === 428 ? 'Configure um provedor de IA (menu → Configuração).' : 'Falha ao regerar.'}</div>`; }
    };
  };
  mount.innerHTML = '<div class="muted small">⏳ a IA está montando o plano de correção priorizado…</div>';
  try { const r = await api('/scans/' + scanId + '/remediation'); render(r.remediation); }
  catch (e) { mount.innerHTML = `<div class="muted small">${e === 428 ? 'Configure um provedor de IA (menu → Configuração).' : 'Plano de remediação indisponível.'}</div>`; }
}

// ── Shell / router ────────────────────────────────────────────────────────────
const ROUTES = [
  { re: /^#\/new/, view: viewWizard },
  { re: /^#\/job\/(.+)/, view: viewProgress },
  { re: /^#\/merge\/(.+)/, view: viewMerge },
  { re: /^#\/scan\/(\d+)/, view: viewScanDetail },
  { re: /^#\/scans/, view: viewHistory },
  { re: /^#?\/?$/, view: viewDashboard },
];

let _cleanup = null;
async function router() {
  if (_cleanup) { _cleanup(); _cleanup = null; }
  const hash = location.hash || '#/';
  document.querySelectorAll('header nav a').forEach((a) =>
    a.classList.toggle('active', a.getAttribute('href') === hash.replace(/\/(job|scan)\/.*/, '/')));
  for (const r of ROUTES) {
    const m = hash.match(r.re);
    if (!m) continue;
    el('view').innerHTML = '<div class="empty"><span class="spin"></span> carregando…</div>';
    try {
      const box = document.createElement('div');
      box.className = 'view-enter';
      el('view').innerHTML = '';
      el('view').appendChild(box);
      await r.view(box, m[1]);
    } catch (e) {
      el('view').innerHTML = `<div class="empty">Erro ao carregar. Verifique se a API está ativa.<br><span class="mono">${esc(e)}</span></div>`;
    }
    return;
  }
}

async function boot() {
  Theme.init();
  try {
    const m = await api('/meta');
    el('ver').textContent = 'v' + m.tool_version;
    if (m.ai_enabled) {
      const b = el('ai');
      b.style.display = '';
      b.textContent = '🤖 ' + (m.ai_model || 'IA ativa');
      b.title = 'Provedor: ' + (m.ai_provider || '—') + ' · nível ' + (m.ai_tier || '—');
    }
  } catch (e) {}
  window.addEventListener('hashchange', router);
  router();
}

// ── VIEW: Dashboard ────────────────────────────────────────────────────────────
function setupBanner(s) {
  if (!s) return '';
  const items = [];
  if (s.ai && !s.ai.enabled) items.push(`🤖 <b>Provedor de IA obrigatório</b> — sem provedor o scan é recusado. ${esc(s.ai.hint || '')}`);
  if (s.pdf && !s.pdf.available) items.push(`📄 <b>PDF indisponível</b> — relatórios saem em HTML. ${esc(s.pdf.detail || '')}`);
  const miss = (s.tools && s.tools.missing_real) || [];
  if (miss.length) items.push(`🛠️ <b>${miss.length} ferramenta(s) ausente(s)</b> (${miss.slice(0, 6).map(esc).join(', ')}) — <span class="mono">${esc(s.tools.hint || '')}</span>`);
  if (!items.length) return '';
  return `<div class="banner"><b>Primeiros passos</b> — itens opcionais (nada bloqueia o uso):<ul>${items.map((i) => `<li>${i}</li>`).join('')}</ul></div>`;
}

async function viewDashboard(root) {
  const [stats, scans, assets, setup, jobs] = await Promise.all([
    api('/stats').catch(() => ({ scans: 0, findings: 0, severity: {}, kev: 0 })),
    api('/scans').catch(() => []),
    api('/assets').catch(() => ({ assets: [] })),
    api('/setup').catch(() => null),
    api('/jobs').catch(() => []),
  ]);
  const active = (jobs || []).filter((j) => j.status === 'running' || j.status === 'queued');
  const sev = stats.severity || {};
  const score = securityScore(sev, stats.kev || 0);
  const latest = scans[0];
  root.innerHTML = `
    <div class="between" style="margin-bottom:16px">
      <div><h1>Painel de operações</h1><p class="sub">Postura de segurança da sua superfície e do último scan.</p></div>
      <button class="btn-primary" onclick="location.hash='#/new'">+ Novo Scan</button>
    </div>
    ${setupBanner(setup)}
    ${active.length ? `<div class="card" style="margin-bottom:14px;border-left:3px solid var(--ok)">
      <div class="between"><h2 style="margin:0">⚡ ${active.length} scan(s) em andamento</h2>
        <span class="muted small">vários scans rodam em paralelo</span></div>
      <div style="margin-top:8px">${active.map((j) => `<div class="between clickable" style="padding:6px 0;border-bottom:1px solid var(--border)" onclick="location.hash='#/job/${esc(j.id)}'">
        <span><span class="badge live st-running">${esc(j.status)}</span> <span class="mono">${esc((j.targets || []).join(', '))}</span></span>
        <span class="muted small">${esc(j.profile)} · ${j.events || 0} eventos →</span></div>`).join('')}</div></div>` : ''}
    <div class="grid" style="margin-bottom:14px">
      ${kpi(stats.scans || 0, 'scans', '🛰️')}
      ${kpi(stats.findings || 0, 'findings', '🐛')}
      ${kpi((sev.critical || 0) + (sev.high || 0), 'críticos + altos', '🔥', true)}
      ${kpi(stats.kev || 0, 'em CISA KEV', '💥')}
    </div>
    <div class="cols-3" style="margin-bottom:14px">
      <div class="card"><h2>Distribuição por severidade</h2>
        <div class="chartbox">${donutSVG(sev)}${sevLegend(sev)}</div></div>
      <div class="card"><h2>Score de postura</h2>
        <div style="text-align:center">${gaugeSVG(score)}<div class="muted small">${esc(score.label)} · heurístico</div></div></div>
      <div class="card"><h2>Ativos em risco</h2><div id="risk"></div></div>
    </div>
    ${latest ? `<div class="card between" style="margin-bottom:14px">
      <div>📌 <b>Último scan</b> · <span class="mono">#${latest.id} ${esc(latest.engagement || '')}</span>
        <span class="muted">· ${esc(latest.profile)}</span></div>
      <button class="btn-ghost" onclick="location.hash='#/scan/${latest.id}'">Ver detalhes →</button></div>` : ''}
    <h2>Histórico recente</h2>
    <div class="tablewrap"><table>
      <thead><tr><th>ID</th><th>Alvo</th><th>Perfil</th><th>Status</th><th>Início</th></tr></thead>
      <tbody>${scans.length ? scans.slice(0, 8).map(scanRow).join('') : '<tr><td colspan="5" class="empty">Nenhum scan ainda. Clique em “Novo Scan”.</td></tr>'}</tbody>
    </table></div>`;

  const risky = (assets.assets || []).filter((a) => a.finding_count > 0).slice(0, 6);
  el('risk').innerHTML = risky.length
    ? risky.map((a) => {
        const lvl = a.max_risk >= 90 ? '🔴' : a.max_risk >= 70 ? '🟠' : a.max_risk >= 40 ? '🟡' : '🟢';
        return `<div class="between" style="padding:6px 0;border-bottom:1px solid var(--border)">
          <span>${lvl} <span class="mono">${esc(a.host)}</span> <span class="muted small">(${a.finding_count})</span></span>
          <span class="muted small">risco ${Math.round(a.max_risk)}</span></div>`;
      }).join('')
    : '<div class="empty">Sem ativos com findings.</div>';
}

// ── VIEW: Detalhe do scan (com tabela de findings interativa) ─────────────────
async function viewScanDetail(root, scanId) {
  const [detail, fnd, inv, atk] = await Promise.all([
    api('/scans/' + scanId), api('/scans/' + scanId + '/findings'),
    api('/scans/' + scanId + '/inventory'), api('/scans/' + scanId + '/attack'),
  ]);
  const sev = detail.severity || {};
  const kev = (fnd.findings || []).filter((f) => f.risk && f.risk.kev).length;
  const score = securityScore(sev, kev);
  const assets = inv.assets || [];
  const summ = inv.summary || {};
  root.innerHTML = `
    <div class="between wrap" style="margin-bottom:14px">
      <div><h1>Scan #${esc(scanId)}</h1><p class="sub mono">${esc(detail.scan.engagement || '')} · ${esc(detail.scan.profile)}</p></div>
      <div class="row wrap">
        <select id="expStyle" style="width:auto"><option value="executive">Executivo</option><option value="technical">Técnico</option></select>
        <select id="expClass" style="width:auto" title="Classificação da informação">
          <option value="confidential">Confidencial</option><option value="restricted">Restrito</option>
          <option value="internal">Uso interno</option><option value="public">Público</option></select>
        <select id="expFmt" style="width:auto"><option value="pdf">PDF</option><option value="html">HTML</option><option value="md">Markdown</option><option value="json">JSON</option><option value="csv">CSV</option><option value="sarif">SARIF</option></select>
        <button class="btn-primary" onclick="exportReport(${esc(scanId)})">⬇ Relatório</button>
        <button class="btn-ghost" onclick="location.hash='#/'">‹ Painel</button>
      </div>
    </div>
    <div class="cols-3" style="margin-bottom:14px">
      <div class="grid" style="grid-template-columns:1fr 1fr">
        ${kpi(detail.count, 'findings', '🐛')}${kpi(sev.critical || 0, 'críticos', '🔴', true)}
        ${kpi(sev.high || 0, 'altos', '🟠')}${kpi((atk.hits || []).length, 'técnicas ATT&CK', '🎯')}
      </div>
      <div class="card"><h2>Severidade</h2><div class="chartbox">${donutSVG(sev)}${sevLegend(sev)}</div></div>
      <div class="card"><h2>Score</h2><div style="text-align:center">${gaugeSVG(score)}
        <div class="muted small">${esc(score.label)}</div></div></div>
    </div>
    <div class="cols" style="margin-bottom:14px">
      <div class="card"><h2>✨ Análise da IA</h2><div id="aianalysis"></div></div>
      <div class="card"><h2>💬 Converse com a IA</h2><div id="aichat"></div></div>
    </div>
    <div class="card" style="margin-bottom:14px"><h2>🛠️ Plano de remediação (IA) — o que arrumar e como</h2>
      <div id="airemediation"></div></div>
    <div class="card" style="margin-bottom:14px"><div class="between wrap"><h2 style="margin:0">Findings</h2></div>
      <div id="ftable"></div></div>
    <div class="card"><div class="between"><h2 style="margin:0">Inventário de ativos</h2>
      <span class="muted small">${summ.assets || assets.length} ativo(s) · ${summ.with_open_ports || 0} com portas · ${summ.with_web || 0} com web</span></div>
      <div class="tablewrap" style="margin-top:10px"><table>
        <thead><tr><th>Ativo</th><th>Portas</th><th>Web</th><th>Perspectivas</th><th>Findings</th><th>Risco máx.</th></tr></thead>
        <tbody>${assets.length ? assets.map((a) => `<tr><td class="mono">${esc(a.host)}</td>
          <td class="mono small">${(a.ports || []).join(', ') || '—'}</td><td>${(a.web_endpoints || []).length}</td>
          <td>${(a.perspectives || []).map(esc).join(', ')}</td><td>${a.finding_count}</td>
          <td>${Math.round(a.max_risk)}</td></tr>`).join('') : '<tr><td colspan="6" class="empty">Sem ativos.</td></tr>'}</tbody>
      </table></div></div>`;
  findingsTable(el('ftable'), fnd.findings || []);
  aiAnalysisPanel(el('aianalysis'), scanId);
  aiRemediationPanel(el('airemediation'), scanId);
  chatPanel(el('aichat'), '/scans/' + scanId + '/chat');
}

// Tabela de findings: busca instantânea, filtro, ordenação, paginação, drill-down.
function findingsTable(mount, findings) {
  findings.forEach((f, i) => (f._i = i));
  const riskOf = (f) => (f.risk ? f.risk.score : ({ critical: 80, high: 60, medium: 40, low: 20, info: 5 }[f.severity] || 0));
  const st = { q: '', sev: '', key: 'risk', dir: -1, page: 1, per: 12, open: new Set() };

  function filtered() {
    const q = st.q.toLowerCase();
    let rows = findings.filter((f) => (!st.sev || f.severity === st.sev)
      && (!q || (f.title + ' ' + f.affected_asset + ' ' + (f.cwe || '') + ' ' + (f.owasp || '') + ' ' + f.source_tool).toLowerCase().includes(q)));
    const keyFn = { risk: riskOf, sev: (f) => SEV.length - SEV.indexOf(f.severity), title: (f) => f.title.toLowerCase(), asset: (f) => f.affected_asset.toLowerCase() }[st.key];
    rows.sort((a, b) => { const A = keyFn(a), B = keyFn(b); return (A < B ? -1 : A > B ? 1 : 0) * st.dir; });
    return rows;
  }
  const arrow = (k) => (st.key === k ? `<span class="arr">${st.dir < 0 ? '▼' : '▲'}</span>` : '');
  const th = (k, label) => `<th class="sortable" data-k="${k}">${label} ${arrow(k)}</th>`;

  function detailHtml(f) {
    const r = f.risk || {};
    const row = (k, v) => (v ? `<div class="k">${k}</div><div>${v}</div>` : '');
    return `<div class="detail"><div class="kv">
      ${row('Descrição', esc(f.description || '—'))}
      ${row('CVSS', f.cvss ? `${esc(f.cvss.version)} · <b>${f.cvss.score}</b>${f.cvss.vector ? ` <span class="mono small">${esc(f.cvss.vector)}</span>` : ''}` : '')}
      ${row('Risco composto', `${Math.round(riskOf(f))}/100 ${r.rationale ? `<span class="muted small">— ${esc(r.rationale)}</span>` : ''}`)}
      ${row('EPSS', r.epss_verified ? (r.epss).toFixed(3) : '<span class="unv">UNVERIFIED</span>')}
      ${row('CISA KEV', r.kev ? '<span class="kev">exploração ativa</span>' : r.kev_verified ? 'não consta' : '<span class="unv">UNVERIFIED</span>')}
      ${row('CWE · OWASP', `${esc(f.cwe || '—')} · ${esc(f.owasp || '—')}`)}
      ${row('Técnica ATT&CK', esc(f.attack_technique || '—'))}
      ${row('Confiança', esc(f.confidence))}
      ${row('Fonte', esc(f.source_tool) + (f.correlated_sources && f.correlated_sources.length ? ' (+ ' + f.correlated_sources.map(esc).join(', ') + ')' : ''))}
    </div>
    ${f.evidence ? `<div class="k muted small">Evidência</div><pre>${esc(f.evidence)}</pre>` : ''}
    ${f.reproduction ? `<div class="k muted small">Reprodução</div><pre>${esc(f.reproduction)}</pre>` : ''}
    ${f.references && f.references.length ? `<div class="k muted small">Referências</div><div class="small">${f.references.map((u) => `<a href="${esc(u)}" target="_blank" rel="noopener" class="mono">${esc(u)}</a>`).join('<br>')}</div>` : ''}
    </div>`;
  }
  function rowHtml(f) {
    const open = st.open.has(f._i);
    const r = f.risk;
    return `<tr class="clickable" data-i="${f._i}"><td>${sevPill(f.severity)}</td>
      <td><b>${r ? Math.round(r.score) : '—'}</b></td><td>${esc(f.title)}${f.ai_generated ? ' <span class="tag ai">IA</span>' : ''}</td>
      <td class="mono small">${esc(f.affected_asset)}</td><td>${esc(f.perspective)}</td>
      <td class="small">${esc(f.cwe || '—')}</td><td>${kevCell(r)}</td><td class="small">${esc(f.source_tool)}</td></tr>
      ${open ? `<tr class="expand-row"><td colspan="8">${detailHtml(f)}</td></tr>` : ''}`;
  }

  function render() {
    const rows = filtered();
    const pages = Math.max(1, Math.ceil(rows.length / st.per));
    if (st.page > pages) st.page = pages;
    const slice = rows.slice((st.page - 1) * st.per, st.page * st.per);
    mount.innerHTML = `
      <div class="between wrap" style="margin:10px 0">
        <div class="search" style="max-width:320px;flex:1"><input type="search" id="ftq" placeholder="Buscar título, ativo, CWE, OWASP, fonte…" value="${esc(st.q)}"></div>
        <div class="row"><select id="ftsev" style="width:auto">${['', ...SEV].map((s) => `<option value="${s}" ${st.sev === s ? 'selected' : ''}>${s || 'todas severidades'}</option>`).join('')}</select>
          <span class="muted small">${rows.length} finding(s)</span></div>
      </div>
      <div class="tablewrap"><table><thead><tr>
        ${th('sev', 'Sev.')}${th('risk', 'Risco')}${th('title', 'Título')}${th('asset', 'Ativo')}
        <th>Persp.</th><th>CWE</th><th>KEV</th><th>Fonte</th></tr></thead>
        <tbody>${slice.length ? slice.map(rowHtml).join('') : '<tr><td colspan="8" class="empty">Nenhum finding com esses filtros.</td></tr>'}</tbody>
      </table></div>
      <div class="pagination"><span class="muted small">Página ${st.page} de ${pages}</span>
        <button class="btn-ghost" id="ftprev" ${st.page <= 1 ? 'disabled' : ''}>‹</button>
        <button class="btn-ghost" id="ftnext" ${st.page >= pages ? 'disabled' : ''}>›</button></div>`;

    el('ftq').addEventListener('input', (e) => { st.q = e.target.value; st.page = 1; const p = e.target.selectionStart; render(); const q = el('ftq'); q.focus(); q.setSelectionRange(p, p); });
    el('ftsev').onchange = (e) => { st.sev = e.target.value; st.page = 1; render(); };
    el('ftprev').onclick = () => { st.page--; render(); };
    el('ftnext').onclick = () => { st.page++; render(); };
    mount.querySelectorAll('th.sortable').forEach((h) => (h.onclick = () => { const k = h.dataset.k; if (st.key === k) st.dir *= -1; else { st.key = k; st.dir = -1; } render(); }));
    mount.querySelectorAll('tr[data-i]').forEach((tr) => (tr.onclick = () => { const i = +tr.dataset.i; st.open.has(i) ? st.open.delete(i) : st.open.add(i); render(); }));
  }
  render();
}

window.exportReport = (scanId) => {
  const fmt = el('expFmt').value, style = el('expStyle').value, cls = el('expClass').value;
  toast('Gerando relatório ' + fmt.toUpperCase() + '…');
  window.location.href = `${API}/scans/${scanId}/report?format=${fmt}&style=${style}&classification=${cls}`;
};

// ── VIEW: Histórico (busca + filtro + correlação multi-scan) ──────────────────
async function viewHistory(root) {
  const scans = await api('/scans').catch(() => []);
  const st = { q: '', status: '', sel: new Set() };
  root.innerHTML = `<div class="between" style="margin-bottom:6px"><h1>Histórico de scans</h1>
      <div class="row"><button class="btn-ghost" id="hmerge" disabled>🔗 Correlacionar (0)</button>
      <button class="btn-primary" onclick="location.hash='#/new'">+ Novo Scan</button></div></div>
    <p class="muted small" style="margin-bottom:12px">Marque 2+ scans (ex.: os que rodaram em paralelo) e clique em <b>Correlacionar</b> para uma visão unificada + análise da IA da superfície inteira.</p>
    <div class="between wrap" style="margin-bottom:10px">
      <div class="search" style="max-width:320px;flex:1"><input type="search" id="hq" placeholder="Buscar por alvo/engajamento/perfil…"></div>
      <select id="hst" style="width:auto"><option value="">todos os status</option><option value="done">concluídos</option><option value="running">em curso</option></select></div>
    <div class="tablewrap"><table>
      <thead><tr><th></th><th>ID</th><th>Alvo</th><th>Perfil</th><th>Status</th><th>Início</th></tr></thead>
      <tbody id="hbody"></tbody></table></div>`;
  const mergeBtn = el('hmerge');
  const updBtn = () => { mergeBtn.textContent = `🔗 Correlacionar (${st.sel.size})`; mergeBtn.disabled = st.sel.size < 2; };
  mergeBtn.onclick = () => { if (st.sel.size >= 2) location.hash = '#/merge/' + [...st.sel].join(','); };
  const render = () => {
    const q = st.q.toLowerCase();
    const rows = scans.filter((s) => (!q || (`#${s.id} ${s.engagement || ''} ${s.profile}`).toLowerCase().includes(q))
      && (!st.status || (st.status === 'done' ? s.finished_at : !s.finished_at)));
    el('hbody').innerHTML = rows.length ? rows.map((s) => {
      const stt = s.finished_at ? 'completed' : 'running', ic = s.finished_at ? '✅' : '⏳';
      return `<tr><td><input type="checkbox" data-id="${s.id}" ${st.sel.has(s.id) ? 'checked' : ''} style="width:auto"></td>
        <td class="mono clickable" onclick="location.hash='#/scan/${s.id}'">#${s.id}</td>
        <td class="clickable" onclick="location.hash='#/scan/${s.id}'">${esc(s.engagement || '—')}</td>
        <td>${esc(s.profile)}</td><td><span class="badge st-${stt}">${ic} ${s.finished_at ? 'concluído' : 'em curso'}</span></td>
        <td class="mono small">${fmtDate(s.started_at)}</td></tr>`;
    }).join('') : '<tr><td colspan="6" class="empty">Nenhum scan.</td></tr>';
    el('hbody').querySelectorAll('input[type=checkbox]').forEach((cb) => (cb.onchange = () => { const id = +cb.dataset.id; cb.checked ? st.sel.add(id) : st.sel.delete(id); updBtn(); }));
  };
  el('hq').addEventListener('input', (e) => { st.q = e.target.value; render(); });
  el('hst').onchange = (e) => { st.status = e.target.value; render(); };
  render(); updBtn();
}

// ── VIEW: Correlação entre scans (merge) ──────────────────────────────────────
async function viewMerge(root, idsStr) {
  const ids = idsStr.split(',').map(Number).filter(Boolean);
  root.innerHTML = '<div class="empty"><span class="spin"></span> correlacionando scans…</div>';
  let data;
  try { data = await apiPost('/scans/merge', { scan_ids: ids }); }
  catch (e) { root.innerHTML = `<div class="empty">Falha ao correlacionar: <span class="mono">${esc(e.detail || e.status)}</span></div>`; return; }
  const sev = data.severity || {}, score = securityScore(sev);
  root.innerHTML = `
    <div class="between wrap" style="margin-bottom:14px">
      <div><h1>🔗 Correlação de ${ids.length} scans</h1><p class="sub mono">${esc((data.targets || []).join(', '))}</p></div>
      <button class="btn-ghost" onclick="location.hash='#/scans'">‹ Histórico</button></div>
    <div class="cols-3" style="margin-bottom:14px">
      <div class="grid" style="grid-template-columns:1fr 1fr">
        ${kpi(data.count, 'findings únicos', '🐛')}${kpi(data.correlated, 'correlacionados', '🔗', true)}
        ${kpi(ids.length, 'scans', '🛰️')}${kpi((sev.critical || 0) + (sev.high || 0), 'críticos/altos', '🔥')}</div>
      <div class="card"><h2>Severidade (unificada)</h2><div class="chartbox">${donutSVG(sev)}${sevLegend(sev)}</div></div>
      <div class="card"><h2>Score</h2><div style="text-align:center">${gaugeSVG(score)}</div></div>
    </div>
    <div class="card" style="margin-bottom:14px"><h2>✨ Correlação da IA (superfície unificada)</h2><div id="mergean"></div></div>
    <div class="card"><h2 style="margin:0 0 8px">Findings unificados (dedup entre scans)</h2><div id="mftable"></div></div>`;
  findingsTable(el('mftable'), data.findings || []);
  const an = el('mergean');
  an.innerHTML = `<button class="btn-ghost" id="manbtn">✨ Gerar correlação da IA</button>`;
  el('manbtn').onclick = async () => {
    an.innerHTML = '<div class="muted small">⏳ a IA está correlacionando os scans…</div>';
    try { const r = await apiPost('/scans/merge/analysis', { scan_ids: ids }); an.innerHTML = `<div class="ai-analysis">${esc(r.analysis || '').replace(/\n/g, '<br>')}</div>`; }
    catch (e) { an.innerHTML = `<div class="muted small">${e.status === 428 ? 'Configure um provedor de IA (menu → Configuração).' : 'Falha ao gerar correlação.'}</div>`; }
  };
}

// ── VIEW: Wizard (4 passos) ────────────────────────────────────────────────────
// Perspectiva é 'unified' por padrão: um só scan avalia público E privado e
// documenta o que achar (sem obrigar o usuário a escolher external/internal).
const wiz = { step: 1, targets: '', perspective: 'unified', objective: 'standard', use_ai: true, authorized: false };
// Perfis = amplitude/velocidade. A IA comanda o scan em TODOS eles (planeja e
// aprofunda conforme descobre) — por isso não há um perfil "IA" à parte.
const OBJECTIVES = [
  { id: 'quick', t: '🎯 Rápido', d: 'Portas + serviços + web essencial. Poucos minutos, superfície principal.' },
  { id: 'standard', t: '🔍 Padrão', d: 'Portas + serviços + templates de vulnerabilidade + cadeia web. Equilíbrio profundidade × tempo.', reco: true },
  { id: 'deep', t: '🔬 Profundo', d: 'Tudo acima + varredura ativa e validação autorizada (gated). Mais demorado.' },
];
function viewWizard(root) { wiz.step = 1; renderWizard(root); }
function renderWizard(root) {
  root.innerHTML = `<div class="wizard"><h1>Novo Scan</h1>
    <div class="steps">${[1, 2, 3, 4].map((n) => `<div class="step ${n <= wiz.step ? 'done' : ''}"></div>`).join('')}</div>
    <div id="wstep"></div></div>`;
  const s = el('wstep');
  [stepTarget, stepObjective, stepAdvanced, stepConfirm][wiz.step - 1](s);
}
const navButtons = (backOk, nextLabel, nextFn, nextOk = true) => `<div class="wizard-nav">
  <button class="btn-ghost" ${backOk ? '' : 'disabled'} onclick="wizBack()">‹ Voltar</button>
  <button class="btn-primary" id="wnext" ${nextOk ? '' : 'disabled'} onclick="(${nextFn})()">${nextLabel}</button></div>`;
function stepTarget(s) {
  s.innerHTML = `<label>Qual alvo você quer escanear?</label>
    <input type="text" id="wtarget" placeholder="192.168.1.10 · 192.168.1.0/24 · exemplo.com" value="${esc(wiz.targets)}">
    <p class="muted small" style="margin-top:8px">Vários alvos: separe por vírgula ou espaço.</p>
    ${navButtons(false, 'Próximo ›', 'wizToStep2')}`;
  el('wtarget').focus();
  el('wtarget').addEventListener('input', (e) => { wiz.targets = e.target.value; el('wnext').disabled = !e.target.value.trim(); });
  el('wnext').disabled = !wiz.targets.trim();
}
function stepObjective(s) {
  s.innerHTML = `<label>O que você quer descobrir?</label>
    ${OBJECTIVES.map((o) => `<div class="choice ${wiz.objective === o.id ? 'sel' : ''}" onclick="wizObj('${o.id}')">
      <div class="t">${o.t}${o.reco ? '<span class="reco">RECOMENDADO</span>' : ''}</div><div class="d">${o.d}</div></div>`).join('')}
    <p class="muted small" style="margin-top:8px">🤖 Em qualquer perfil, a IA comanda o scan — planeja as capacidades e aprofunda conforme descobre.</p>
    ${navButtons(true, 'Próximo ›', 'wizToStep3', !!wiz.objective)}`;
}
function stepAdvanced(s) {
  s.innerHTML = `<label>Opções avançadas</label>
    <div class="choice ${wiz.use_ai ? 'sel' : ''}" onclick="wizToggleAI()"><div class="between"><div class="t">🤖 Orquestração inteligente (cascata)</div><div>${wiz.use_ai ? '✓ ligada' : 'desligada'}</div></div>
      <div class="d">A cada descoberta, a IA/engine dispara as ferramentas certas (ex.: porta 445 → enum4linux). Cada disparo é registrado e justificado.</div></div>
    <div class="choice"><div class="t">⚙️ Rate limit</div><div class="d">Conservador (padrão) — respeita a produção. Ajuste fino via scope.yaml/CLI.</div></div>
    <div class="choice"><div class="t">🔒 Exploração / Validação</div><div class="d">Modo “validar apenas” (PoC seguro). Exploração real só com autorização explícita (gated).</div></div>
    ${navButtons(true, 'Próximo ›', 'wizToStep4')}`;
}
function stepConfirm(s) {
  const objLabel = (OBJECTIVES.find((o) => o.id === wiz.objective) || {}).t || wiz.objective;
  s.innerHTML = `<label>Confirmação</label>
    <div class="card"><table class="summary-tbl"><tbody>
      <tr><td>Alvo</td><td class="mono">${esc(wiz.targets)}</td></tr>
      <tr><td>Modo</td><td>Unificado — avalia público e privado; documenta IPs internos que encontrar</td></tr>
      <tr><td>Objetivo</td><td>${esc(objLabel)}</td></tr>
      <tr><td>Cascata IA</td><td>${wiz.use_ai ? 'Sim' : 'Não'}</td></tr></tbody></table></div>
    <div class="consent"><b>⚠️ Confirmação de autorização</b>
      <p style="margin:8px 0">Confirmo que tenho permissão para escanear <span class="mono">${esc(wiz.targets)}</span>. Scan não autorizado pode ser ilegal.</p>
      <label class="row" style="cursor:pointer;font-weight:400"><input type="checkbox" id="wconsent" style="width:auto" ${wiz.authorized ? 'checked' : ''}> <span>Sim, tenho autorização e aceito os riscos.</span></label></div>
    <div class="wizard-nav"><button class="btn-ghost" onclick="wizBack()">‹ Voltar</button>
      <button class="btn-primary" id="wstart" ${wiz.authorized ? '' : 'disabled'} onclick="wizStart()">Iniciar Scan ✓</button></div>`;
  el('wconsent').addEventListener('change', (e) => { wiz.authorized = e.target.checked; el('wstart').disabled = !e.target.checked; });
}
window.wizBack = () => { if (wiz.step > 1) wiz.step--; renderWizard(el('view').firstChild); };
window.wizToStep2 = () => wiz.targets.trim() && ((wiz.step = 2), renderWizard(el('view').firstChild));
window.wizToStep3 = () => ((wiz.step = 3), renderWizard(el('view').firstChild));
window.wizToStep4 = () => ((wiz.step = 4), renderWizard(el('view').firstChild));
window.wizObj = (id) => { wiz.objective = id; renderWizard(el('view').firstChild); };
window.wizToggleAI = () => { wiz.use_ai = !wiz.use_ai; renderWizard(el('view').firstChild); };
window.wizStart = async () => {
  const targets = wiz.targets.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
  el('wstart').disabled = true; el('wstart').innerHTML = '<span class="spin"></span> iniciando…';
  try {
    const job = await apiPost('/scans', { targets, perspective: wiz.perspective, objective: wiz.objective, use_ai: wiz.use_ai, authorized: wiz.authorized });
    location.hash = '#/job/' + job.id;
  } catch (e) {
    toast('Não foi possível iniciar: ' + (e.detail || e.status));
    el('wstart').disabled = false; el('wstart').innerHTML = 'Iniciar Scan ✓';
  }
};

// ── VIEW: Progresso em tempo real (WebSocket, SOC) ────────────────────────────
const PHASE_LABELS = {
  subdomain: 'Enumeração de subdomínios', resolve: 'Resolução DNS', 'host-discovery': 'Descoberta de hosts',
  ports: 'Descoberta de portas', 'service-auth': 'Detecção de serviço', 'web-probe': 'Sondagem web',
  screenshot: 'Screenshots', crawl: 'Crawl web', params: 'Descoberta de parâmetros',
  'vuln-templates': 'Templates de vulnerabilidade', cms: 'Scan de CMS', tls: 'Avaliação TLS', 'cloud-api': 'Exposição em nuvem',
};
const STAGE_ORDER = Object.keys(PHASE_LABELS);
const BUDGET = { quick: 900, standard: 2400, deep: 7200 }; // segundos (estimativa de ETA)

async function viewProgress(root, jobId) {
  const job = await api('/jobs/' + jobId);
  const state = { phases: {}, discoveries: [], reasoning: [], tools: {}, currentTool: '', sev: {}, status: job.status, startMs: Date.now(), progress: 0.04, scanId: null };
  const budget = BUDGET[job.profile] || BUDGET.standard;
  root.innerHTML = `
    <div class="between wrap" style="margin-bottom:14px">
      <div><h1>Scan em andamento</h1><p class="sub mono">${esc(job.targets.join(', '))} · ${esc(job.perspective)}/${esc(job.profile)}</p></div>
      <div class="row"><span class="badge live st-running" id="pstatus">${esc(job.status)}</span>
        <button class="btn-danger" id="pcancel" onclick="cancelJob('${jobId}')">Cancelar</button>
        <button class="btn-ghost" onclick="location.hash='#/'">Painel</button></div>
    </div>
    <div class="grid" style="margin-bottom:14px">
      ${kpi('<span id="kf">0</span>', 'findings', '🐛')}
      ${kpi('<span id="kc">0</span>', 'críticos/altos', '🔥', true)}
      ${kpi('<span id="kt">—</span>', 'ferramenta atual', '🛠️')}
      ${kpi('<span id="ke">00:00</span>', 'decorrido', '⏱️')}
    </div>
    <div class="card" style="margin-bottom:14px"><div class="between" style="margin-bottom:8px">
      <b>Progresso</b><span class="muted small mono"><span id="ppct">4</span>% · restante ~<span id="peta">—</span></span></div>
      <div class="progressbar"><span id="pbar" style="width:4%"></span></div></div>
    <div class="cols" style="margin-bottom:14px">
      <div class="card"><h2>🧠 Raciocínio do agente</h2><div class="timeline" id="reasoning"><div class="muted small">o agente ainda não decidiu nada…</div></div></div>
      <div class="card"><h2>🛠️ Ferramentas &amp; capacidades</h2><div id="phases"><div class="muted small">aguardando o agente disparar…</div></div></div>
    </div>
    <div class="cols" style="margin-bottom:14px">
      <div class="card"><h2>📡 Descobertas em tempo real</h2><div class="feed" id="feed"><div class="empty">aguardando descobertas…</div></div></div>
      <div class="card"><h2>💬 Fale com a IA (ao vivo)</h2><div id="livechat"></div></div>
    </div>
    <p class="muted small" style="margin-top:14px">O agente decide capacidade a capacidade e justifica cada passo (plano · replan · seleção · execução) — sem caixa-preta. A execução passa pelo gate de escopo; <span class="unv">UNVERIFIED</span> = não confirmado contra fonte oficial.</p>`;

  chatPanel(el('livechat'), '/jobs/' + jobId + '/chat', { live: true });

  const timer = setInterval(() => {
    const secs = Math.floor((Date.now() - state.startMs) / 1000);
    const e = el('ke'); if (e) e.textContent = mmss(secs);
    if (state.status === 'running') {
      const remain = Math.max(0, Math.round(budget * (1 - state.progress)));
      const p = el('peta'); if (p) p.textContent = mmss(remain);
    }
  }, 1000);

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/scans/${jobId}/progress`);
  let closed = false;
  ws.onmessage = (m) => handleEvent(JSON.parse(m.data), state);
  ws.onerror = () => !closed && pollFallback(jobId, state);
  _cleanup = () => { closed = true; clearInterval(timer); try { ws.close(); } catch (e) {} };
}
const mmss = (s) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;

function handleEvent(e, state) {
  if (e.type === 'phase_started') { state.phases[e.phase] = 'active'; renderPhases(state); }
  else if (e.type === 'phase_finished') { state.phases[e.phase] = 'done'; renderPhases(state); bumpBar(state); }
  else if (e.type === 'discovery') {
    state.discoveries.push(e); renderFeed(state);
    const sv = e.finding.severity; state.sev[sv] = (state.sev[sv] || 0) + 1;
    setText('kf', state.discoveries.length);
    setText('kc', (state.sev.critical || 0) + (state.sev.high || 0));
  } else if (e.type === 'log') { state.reasoning.push(e); renderReasoning(state); }
  else if (e.type === 'tool_execution') {
    const prev = state.tools[e.tool];
    state.tools[e.tool] = e.status;
    if (e.status === 'in_progress') { state.currentTool = e.tool; setText('kt', e.tool); }
    else if (state.currentTool === e.tool) { setText('kt', '—'); }
    // A barra avança a cada ferramenta concluída (o CognitiveEngine emite
    // tool_execution, não phase_*): aproximação assintótica que sempre se move
    // sem saber o total do plano antecipadamente.
    if (prev !== e.status && (e.status === 'completed' || e.status === 'failed' || e.status === 'skipped')) {
      state.progress = Math.min(0.95, state.progress + (0.95 - state.progress) * 0.28);
      setBar(Math.round(state.progress * 100));
    }
    renderTools(state);
  } else if (e.type === 'analysis') { toast('✨ Análise da IA concluída'); state.analysis = e.text; }
  else if (e.type === 'scan_status') setStatus(state, e.status);
  else if (e.type === 'analysis_complete') { state.progress = 1; setBar(100); }
  else if (e.type === 'stream_end') {
    setStatus(state, e.status);
    // Ao terminar, leva ao detalhe do scan mesmo sem findings (antes ficava preso
    // na tela de progresso quando o scan não achava nada).
    if (state.scanId) setTimeout(() => (location.hash = '#/scan/' + state.scanId), 1200);
  }
  if (e.scan_id) state.scanId = e.scan_id;
}
const setText = (id, v) => { const n = el(id); if (n) n.textContent = v; };
function setBar(pct) { const b = el('pbar'); if (b) b.style.width = pct + '%'; setText('ppct', Math.round(pct)); }
function setStatus(state, status) {
  state.status = status;
  const b = el('pstatus'); if (b) { b.textContent = status; b.className = 'badge st-' + status + (status === 'running' ? ' live' : ''); }
  const c = el('pcancel'); if (c && status !== 'running') c.style.display = 'none';
  if (status === 'completed') { state.progress = 1; setBar(100); setText('peta', '00:00'); toast('Scan concluído.'); }
  if (status === 'failed') toast('Scan falhou.');
  if (status === 'cancelled') toast('Scan cancelado.');
}
function renderPhases(state) {
  const known = STAGE_ORDER.filter((p) => state.phases[p]);
  el('phases').innerHTML = known.length ? known.map((p) => {
    const s = state.phases[p], ic = s === 'done' ? '✅' : '⏳';
    return `<div class="phase ${s}"><span class="ic">${ic}</span><span>${esc(PHASE_LABELS[p] || p)}</span></div>`;
  }).join('') : '<div class="muted small">aguardando…</div>';
}
// Painel de ferramentas dirigido por tool_execution (o que o CognitiveEngine emite).
const _TOOL_ICON = { completed: '✅', failed: '⚠️', skipped: '⤳', in_progress: '⏳', queued: '·' };
function renderTools(state) {
  const box = el('phases'); if (!box) return;
  const entries = Object.entries(state.tools);
  box.innerHTML = entries.length ? entries.map(([tool, status]) => {
    const cls = status === 'in_progress' ? 'active' : status === 'completed' ? 'done' : '';
    return `<div class="phase ${cls}"><span class="ic">${_TOOL_ICON[status] || '•'}</span>
      <span class="mono">${esc(tool)}</span>
      <span class="muted small" style="margin-left:auto">${esc(status)}</span></div>`;
  }).join('') : '<div class="muted small">aguardando o agente disparar…</div>';
}
function bumpBar(state) {
  const done = STAGE_ORDER.filter((p) => state.phases[p] === 'done').length;
  const total = Math.max(done + 1, Object.keys(state.phases).length);
  state.progress = Math.min(0.96, done / total);
  setBar(Math.round(state.progress * 100));
}
const _REASON_KIND = (msg) => {
  const m = /\[([a-z-]+)(?::([a-z]+))?\]/.exec(msg || '');
  if (!m) return { tag: 'log', cls: '' };
  return { tag: m[2] ? `${m[1]}:${m[2]}` : m[1], cls: m[2] === 'ai' || m[1] === 'stop-hint' ? 'ai' : m[1] === 'planned' ? 'plan' : '' };
};
function renderReasoning(state) {
  el('reasoning').innerHTML = state.reasoning.slice(-50).reverse().map((e) => {
    const { tag, cls } = _REASON_KIND(e.message);
    const text = esc((e.message || '').replace(/^#\d+\s*\[[^\]]+\]\s*/, ''));
    return `<div class="tl-line ${cls}"><span class="tool">${esc(tag)}</span><span class="txt">${text}</span></div>`;
  }).join('');
}
function renderFeed(state) {
  el('feed').innerHTML = state.discoveries.slice(-40).reverse().map((d) => {
    const f = d.finding, cls = SEVKEY[f.severity] || 'info';
    const casc = (d.cascade_triggered || []).length ? `<div class="casc">↳ cascata: ${d.cascade_triggered.map(esc).join(', ')}</div>` : '';
    return `<div class="feeditem ${cls}"><div>${sevPill(f.severity)} <b>${esc(f.title)}</b>
      <span class="muted mono small">${esc(f.affected_asset)}</span> <span class="muted small">· ${esc(f.source_tool)}</span></div>${casc}</div>`;
  }).join('') || '<div class="empty">aguardando descobertas…</div>';
}
window.cancelJob = async (jobId) => {
  try { await apiPost('/jobs/' + jobId + '/cancel', {}); toast('Cancelamento solicitado…'); }
  catch (e) { toast('Falha ao cancelar.'); }
};
async function pollFallback(jobId, state) {
  let cursor = 0;
  const tick = async () => {
    let data; try { data = await api(`/jobs/${jobId}/progress?since=${cursor}`); } catch (e) { return; }
    cursor = data.cursor; data.events.forEach((e) => handleEvent(e, state));
    if (data.status === 'running') setTimeout(tick, 700);
  };
  tick();
}

boot();
