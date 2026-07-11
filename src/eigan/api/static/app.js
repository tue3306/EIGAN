/* EIGAN — SPA da interface web (§3 do prompt de interface).
   Vanilla JS, sem build: roteamento por hash, componentes reutilizáveis e views.
   ZERO regra de negócio aqui — tudo vem de /api/v1 (CLAUDE.md §10). */
'use strict';

// ── helpers de API ───────────────────────────────────────────────────────────
const API = '/api/v1';
const api = (p) => fetch(API + p).then((r) => (r.ok ? r.json() : Promise.reject(r.status)));
const apiPost = (p, body) =>
  fetch(API + p, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  }).then(async (r) => {
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw { status: r.status, detail: data.detail || r.statusText };
    return data;
  });

const $ = (s, root = document) => root.querySelector(s);
const el = (id) => document.getElementById(id);
const esc = (s) =>
  String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEVKEY = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' };
const sevColor = (s) => getComputedStyle(document.documentElement).getPropertyValue('--' + (SEVKEY[s] || 'info'));

// ── componentes reutilizáveis (§4) ───────────────────────────────────────────
const sevPill = (s) => `<span class="pill s-${s}">${esc(s)}</span>`;
const kpiCard = (v, l) => `<div class="card"><div class="kpi">${v}<small>${esc(l)}</small></div></div>`;
const kevCell = (r) =>
  r
    ? r.kev
      ? '<span class="kev">KEV</span>'
      : r.kev_verified
      ? 'não'
      : '<span class="unv">?</span>'
    : '<span class="unv">?</span>';

function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.innerHTML = esc(msg);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3200);
}

function scanCard(s) {
  const done = s.finished_at ? '✅' : '⏳';
  return `<tr class="clickable" onclick="location.hash='#/scan/${s.id}'">
    <td class="mono">#${s.id}</td><td>${esc(s.engagement || '—')}</td>
    <td>${esc(s.profile)}</td><td>${done}</td>
    <td class="mono">${esc((s.started_at || '').slice(0, 16).replace('T', ' '))}</td></tr>`;
}

// ── shell / router ───────────────────────────────────────────────────────────
const ROUTES = [
  { re: /^#\/new/, view: viewWizard },
  { re: /^#\/job\/(.+)/, view: viewProgress },
  { re: /^#\/scan\/(\d+)/, view: viewScanDetail },
  { re: /^#\/scans/, view: viewHistory },
  { re: /^#?\/?$/, view: viewDashboard },
];

let _cleanup = null;
async function router() {
  if (_cleanup) {
    _cleanup();
    _cleanup = null;
  }
  const hash = location.hash || '#/';
  document.querySelectorAll('nav a').forEach((a) => a.classList.toggle('active', a.getAttribute('href') === hash.replace(/\/(job|scan)\/.*/, '/')));
  for (const r of ROUTES) {
    const m = hash.match(r.re);
    if (m) {
      el('view').innerHTML = '<div class="empty"><span class="spin"></span> carregando…</div>';
      try {
        await r.view(el('view'), m[1]);
      } catch (e) {
        el('view').innerHTML = `<div class="empty">Erro ao carregar. Verifique se a API está ativa.<br><span class="mono">${esc(e)}</span></div>`;
      }
      return;
    }
  }
}

async function boot() {
  try {
    const m = await api('/meta');
    el('ver').textContent = 'v' + m.tool_version;
    if (m.ai_enabled) el('ai').style.display = '';
  } catch (e) {}
  window.addEventListener('hashchange', router);
  router();
}

// ── VIEW: Dashboard ──────────────────────────────────────────────────────────
function setupBanner(s) {
  if (!s) return '';
  const items = [];
  if (!s.ai.enabled) items.push(`🤖 <b>Provedor de IA obrigatório</b> — o EIGAN é um agente de IA; sem provedor o scan é recusado. ${esc(s.ai.hint)}`);
  if (s.pdf && !s.pdf.available) items.push(`📄 <b>PDF indisponível</b> — relatórios saem em HTML. ${esc(s.pdf.detail)}`);
  const miss = (s.tools && s.tools.missing_real) || [];
  if (miss.length) items.push(`🛠️ <b>${miss.length} ferramenta(s) ausente(s)</b> (${miss.slice(0, 6).map(esc).join(', ')}) — <span class="mono">${esc(s.tools.hint)}</span>`);
  if (!items.length) return '';
  return `<div class="card" style="border-left:3px solid var(--med);margin-bottom:8px">
    <b>Primeiros passos</b> — itens opcionais degradados (nada bloqueia o uso):
    <ul style="margin:6px 0 0 18px">${items.map((i) => `<li>${i}</li>`).join('')}</ul></div>`;
}

async function viewDashboard(root) {
  const [stats, scans, assets, setup] = await Promise.all([
    api('/stats').catch(() => ({ scans: 0, findings: 0, severity: {}, kev: 0 })),
    api('/scans').catch(() => []),
    api('/assets').catch(() => ({ assets: [] })),
    api('/setup').catch(() => null),
  ]);
  const sev = stats.severity || {};
  const latest = scans[0];
  root.innerHTML = `
    <div class="between">
      <div><h1>Painel</h1><p class="sub">Visão geral da sua superfície e do último scan.</p></div>
      <button class="btn-primary" onclick="location.hash='#/new'">+ Novo Scan</button>
    </div>
    ${setupBanner(setup)}
    <div class="grid" style="margin-bottom:8px">
      ${kpiCard(stats.scans || 0, 'scans')}
      ${kpiCard(stats.findings || 0, 'findings')}
      ${kpiCard((sev.critical || 0) + (sev.high || 0), 'críticos/altos')}
      ${kpiCard(stats.kev || 0, 'em CISA KEV')}
    </div>
    ${latest ? `<div class="card between" style="margin-top:14px">
        <div><b>Último scan</b> · <span class="mono">#${latest.id} ${esc(latest.engagement || '')}</span>
          <span class="muted">· ${esc(latest.profile)}</span></div>
        <div class="row"><button class="btn-ghost" onclick="location.hash='#/scan/${latest.id}'">Ver detalhes</button>
          <button class="btn-ghost" onclick="location.hash='#/new'">🔄 Novo</button></div>
      </div>` : ''}

    <div class="cols" style="margin-top:8px">
      <div class="card"><h2 style="margin-top:0">Distribuição por severidade</h2><div class="bars" id="sevbars"></div></div>
      <div class="card"><h2 style="margin-top:0">Ativos em risco</h2><div id="risk"></div></div>
    </div>

    <h2>Histórico de scans</h2>
    <div class="tablewrap"><table>
      <thead><tr><th>ID</th><th>Alvo</th><th>Perfil</th><th>Status</th><th>Início</th></tr></thead>
      <tbody>${scans.length ? scans.slice(0, 12).map(scanCard).join('') : '<tr><td colspan="5" class="empty">Nenhum scan ainda. Clique em “Novo Scan”.</td></tr>'}</tbody>
    </table></div>`;

  const max = Math.max(1, ...SEV.map((s) => sev[s] || 0));
  el('sevbars').innerHTML = SEV.map(
    (s) => `<div class="barrow"><span class="lbl">${s}</span>
      <span class="bar" style="width:${Math.round(((sev[s] || 0) / max) * 100)}%;background:${sevColor(s)}"></span>
      <span class="n">${sev[s] || 0}</span></div>`
  ).join('');

  const risky = (assets.assets || []).filter((a) => a.finding_count > 0).slice(0, 6);
  el('risk').innerHTML = risky.length
    ? risky
        .map((a) => {
          const lvl = a.max_risk >= 90 ? '🔴' : a.max_risk >= 70 ? '🟠' : a.max_risk >= 40 ? '🟡' : '🟢';
          return `<div class="between" style="padding:6px 0;border-bottom:1px dashed var(--border)">
            <span>${lvl} <span class="mono">${esc(a.host)}</span> <span class="muted">(${a.finding_count} findings)</span></span>
            <span class="muted">risco ${Math.round(a.max_risk)}</span></div>`;
        })
        .join('')
    : '<div class="empty">Sem ativos com findings.</div>';
}

// ── VIEW: Wizard (5 passos) ──────────────────────────────────────────────────
const wiz = { step: 1, targets: '', perspective: '', objective: 'standard', use_ai: true, authorized: false };

const OBJECTIVES = [
  { id: 'quick', t: '🎯 Rápido (5–15 min)', d: 'Portscanning + identificação de serviço. Cobertura ~60%.' },
  { id: 'standard', t: '🔍 Padrão (30–60 min)', d: 'Portscan + service detection + templates de vuln. Cobertura ~85%.', reco: true },
  { id: 'deep', t: '🔬 Profundo (1–4 h)', d: 'Tudo acima + varredura ativa + validação (gated).' },
  { id: 'ai', t: '🤖 Deixe a IA decidir', d: 'A IA orquestra a estratégia sobre o pipeline determinístico.' },
];

function viewWizard(root) {
  wiz.step = 1;
  renderWizard(root);
}

function renderWizard(root) {
  const steps = [1, 2, 3, 4, 5]
    .map((n) => `<div class="step ${n <= wiz.step ? 'done' : ''}"></div>`)
    .join('');
  root.innerHTML = `<div class="wizard">
    <h1>Novo Scan</h1>
    <div class="steps">${steps}</div>
    <div id="wstep"></div></div>`;
  const s = el('wstep');
  if (wiz.step === 1) stepTarget(s);
  else if (wiz.step === 2) stepPerspective(s);
  else if (wiz.step === 3) stepObjective(s);
  else if (wiz.step === 4) stepAdvanced(s);
  else stepConfirm(s);
}

const navButtons = (backOk, nextLabel, nextFn, nextOk = true) => `
  <div class="wizard-nav">
    <button class="btn-ghost" ${backOk ? '' : 'disabled'} onclick="wizBack()">‹ Voltar</button>
    <button class="btn-primary" id="wnext" ${nextOk ? '' : 'disabled'} onclick="(${nextFn})()">${nextLabel}</button>
  </div>`;

function stepTarget(s) {
  s.innerHTML = `<label>Qual alvo você quer escanear?</label>
    <input type="text" id="wtarget" placeholder="192.168.1.10 · 192.168.1.0/24 · exemplo.com" value="${esc(wiz.targets)}">
    <p class="muted" style="font-size:12px;margin-top:8px">Vários alvos: separe por vírgula ou espaço.</p>
    ${navButtons(false, 'Próximo ›', 'wizToStep2')}`;
  el('wtarget').focus();
  el('wtarget').addEventListener('input', (e) => {
    wiz.targets = e.target.value;
    el('wnext').disabled = !e.target.value.trim();
  });
  el('wnext').disabled = !wiz.targets.trim();
}

function stepPerspective(s) {
  const opt = (id, t, d) =>
    `<div class="choice ${wiz.perspective === id ? 'sel' : ''}" onclick="wizPersp('${id}')"><div class="t">${t}</div><div class="d">${d}</div></div>`;
  s.innerHTML = `<label>De onde você está olhando a rede?</label>
    ${opt('external', '🌐 EXTERNA (Outside-In)', 'Visão de atacante na internet: subdomínios, portas expostas, apps públicas.')}
    ${opt('internal', '🏢 INTERNA (Inside-Out)', 'Dentro da rede: servidores internos, AD, SMB, LDAP (assumed breach).')}
    ${navButtons(true, 'Próximo ›', 'wizToStep3', !!wiz.perspective)}`;
}

function stepObjective(s) {
  s.innerHTML = `<label>O que você quer descobrir?</label>
    ${OBJECTIVES.map(
      (o) => `<div class="choice ${wiz.objective === o.id ? 'sel' : ''}" onclick="wizObj('${o.id}')">
        <div class="t">${o.t}${o.reco ? '<span class="reco">RECOMENDADO</span>' : ''}</div><div class="d">${o.d}</div></div>`
    ).join('')}
    ${navButtons(true, 'Próximo ›', 'wizToStep4', !!wiz.objective)}`;
}

function stepAdvanced(s) {
  s.innerHTML = `<label>Opções avançadas</label>
    <div class="choice ${wiz.use_ai ? 'sel' : ''}" onclick="wizToggleAI()">
      <div class="between"><div class="t">🤖 Orquestração inteligente (cascata)</div><div>${wiz.use_ai ? '✓ ligada' : 'desligada'}</div></div>
      <div class="d">A cada descoberta, a IA/engine dispara automaticamente as ferramentas certas (ex.: porta 445 → enum4linux). Cada disparo é registrado e justificado.</div>
    </div>
    <div class="choice"><div class="t">⚙️ Rate limit</div><div class="d">Conservador (padrão, recomendado) — respeita a produção. Ajuste fino via scope.yaml/CLI.</div></div>
    <div class="choice"><div class="t">🔒 Exploração / Validação</div><div class="d">Modo “validar apenas” (PoC seguro). Exploração real só com autorização explícita (gated).</div></div>
    ${navButtons(true, 'Próximo ›', 'wizToStep5')}`;
}

function stepConfirm(s) {
  const objLabel = (OBJECTIVES.find((o) => o.id === wiz.objective) || {}).t || wiz.objective;
  s.innerHTML = `<label>Confirmação</label>
    <div class="card"><table class="summary-tbl"><tbody>
      <tr><td>Alvo</td><td class="mono">${esc(wiz.targets)}</td></tr>
      <tr><td>Perspectiva</td><td>${esc((wiz.perspective || '').toUpperCase())}</td></tr>
      <tr><td>Objetivo</td><td>${esc(objLabel)}</td></tr>
      <tr><td>Cascata IA</td><td>${wiz.use_ai ? 'Sim' : 'Não'}</td></tr>
    </tbody></table></div>
    <div class="consent">
      <b>⚠️ Confirmação de autorização</b>
      <p style="margin:8px 0">Confirmo que tenho permissão para escanear <span class="mono">${esc(wiz.targets)}</span>.
      Scan não autorizado pode ser ilegal.</p>
      <label class="row" style="cursor:pointer"><input type="checkbox" id="wconsent" style="width:auto" ${wiz.authorized ? 'checked' : ''}>
        <span>Sim, tenho autorização e aceito os riscos.</span></label>
    </div>
    <div class="wizard-nav">
      <button class="btn-ghost" onclick="wizBack()">‹ Voltar</button>
      <button class="btn-primary" id="wstart" ${wiz.authorized ? '' : 'disabled'} onclick="wizStart()">Iniciar Scan ✓</button>
    </div>`;
  el('wconsent').addEventListener('change', (e) => {
    wiz.authorized = e.target.checked;
    el('wstart').disabled = !e.target.checked;
  });
}

// wizard actions (globais p/ onclick inline)
window.wizBack = () => {
  if (wiz.step > 1) wiz.step--;
  renderWizard(el('view'));
};
window.wizToStep2 = () => wiz.targets.trim() && (wiz.step = 2, renderWizard(el('view')));
window.wizToStep3 = () => (wiz.step = 3, renderWizard(el('view')));
window.wizToStep4 = () => (wiz.step = 4, renderWizard(el('view')));
window.wizToStep5 = () => (wiz.step = 5, renderWizard(el('view')));
window.wizPersp = (id) => {
  wiz.perspective = id;
  renderWizard(el('view'));
};
window.wizObj = (id) => {
  wiz.objective = id;
  renderWizard(el('view'));
};
window.wizToggleAI = () => {
  wiz.use_ai = !wiz.use_ai;
  renderWizard(el('view'));
};
window.wizStart = async () => {
  const targets = wiz.targets.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
  el('wstart').disabled = true;
  el('wstart').innerHTML = '<span class="spin"></span> iniciando…';
  try {
    const job = await apiPost('/scans', {
      targets,
      perspective: wiz.perspective,
      objective: wiz.objective,
      use_ai: wiz.use_ai,
      authorized: wiz.authorized,
    });
    location.hash = '#/job/' + job.id;
  } catch (e) {
    toast('Não foi possível iniciar: ' + (e.detail || e.status));
    el('wstart').disabled = false;
    el('wstart').innerHTML = 'Iniciar Scan ✓';
  }
};

// ── VIEW: Progresso em tempo real (WebSocket) ────────────────────────────────
const PHASE_LABELS = {
  subdomain: 'Enumeração de subdomínios',
  resolve: 'Resolução DNS',
  'host-discovery': 'Descoberta de hosts',
  ports: 'Descoberta de portas',
  'service-auth': 'Detecção de serviço',
  'web-probe': 'Sondagem web',
  screenshot: 'Screenshots',
  crawl: 'Crawl web',
  params: 'Descoberta de parâmetros',
  'vuln-templates': 'Templates de vulnerabilidade',
  cms: 'Scan de CMS',
  tls: 'Avaliação TLS',
  'cloud-api': 'Exposição em nuvem',
};

async function viewProgress(root, jobId) {
  const job = await api('/jobs/' + jobId);
  const state = { phases: {}, discoveries: [], reasoning: [], tools: {}, status: job.status };
  root.innerHTML = `
    <div class="between">
      <div><h1>Scan em andamento</h1><p class="sub mono">${esc(job.targets.join(', '))} · ${esc(job.perspective)}/${esc(job.profile)}</p></div>
      <div class="row">
        <span class="badge" id="pstatus">${esc(job.status)}</span>
        <button class="btn-danger" id="pcancel" onclick="cancelJob('${jobId}')">Cancelar</button>
        <button class="btn-ghost" onclick="location.hash='#/'">Painel</button>
      </div>
    </div>
    <div class="card"><div class="between" style="margin-bottom:8px">
      <b>Progresso</b><span class="muted mono" id="pcount">0 findings</span></div>
      <div class="progressbar"><span id="pbar" style="width:4%"></span></div>
    </div>
    <div class="cols" style="margin-top:8px">
      <div class="card"><h2 style="margin-top:0">Raciocínio do agente (timeline)</h2><div id="reasoning"><div class="muted">o agente ainda não decidiu nada…</div></div></div>
      <div class="card"><h2 style="margin-top:0">Fases</h2><div id="phases"><div class="muted">aguardando…</div></div></div>
    </div>
    <h2>Descobertas em tempo real</h2>
    <div class="feed card" id="feed"><div class="empty">aguardando descobertas…</div></div>
    <p class="muted" style="font-size:12px;margin-top:14px">O agente decide capacidade a capacidade e justifica cada passo (plano · replan · seleção · execução) — sem caixa-preta. A execução passa pelo gate de escopo; findings <span class="unv">UNVERIFIED</span> não foram confirmados contra fonte oficial.</p>`;

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/scans/${jobId}/progress`);
  let closed = false;
  ws.onmessage = (m) => handleEvent(JSON.parse(m.data), state, jobId);
  ws.onerror = () => !closed && pollFallback(jobId, state);
  _cleanup = () => {
    closed = true;
    try {
      ws.close();
    } catch (e) {}
  };
}

const STAGE_ORDER = Object.keys(PHASE_LABELS);
function handleEvent(e, state, jobId) {
  if (e.type === 'phase_started') {
    state.phases[e.phase] = 'active';
    renderPhases(state);
  } else if (e.type === 'phase_finished') {
    state.phases[e.phase] = 'done';
    renderPhases(state);
    bumpBar(state);
  } else if (e.type === 'discovery') {
    state.discoveries.push(e);
    renderFeed(state);
    el('pcount').textContent = state.discoveries.length + ' findings';
  } else if (e.type === 'log') {
    state.reasoning.push(e);
    renderReasoning(state);
  } else if (e.type === 'tool_execution') {
    state.tools[e.tool] = e.status;
  } else if (e.type === 'scan_status') {
    setStatus(state, e.status);
  } else if (e.type === 'analysis_complete') {
    el('pbar').style.width = '100%';
  } else if (e.type === 'stream_end') {
    setStatus(state, e.status);
    if (state.discoveries.length && state._scanId)
      setTimeout(() => (location.hash = '#/scan/' + state._scanId), 900);
  }
  if (e.scan_id) state._scanId = e.scan_id;
}

function setStatus(state, status) {
  state.status = status;
  const badge = el('pstatus');
  if (badge) badge.textContent = status;
  const cancel = el('pcancel');
  if (cancel && status !== 'running') cancel.style.display = 'none';
  if (status === 'completed') {
    el('pbar').style.width = '100%';
    toast('Scan concluído.');
  }
  if (status === 'failed') toast('Scan falhou.');
  if (status === 'cancelled') toast('Scan cancelado.');
}

function renderPhases(state) {
  const known = STAGE_ORDER.filter((p) => state.phases[p]);
  el('phases').innerHTML = known.length
    ? known
        .map((p) => {
          const st = state.phases[p];
          const ic = st === 'done' ? '✅' : '⏳';
          return `<div class="phase ${st}"><span class="ic">${ic}</span><span>${esc(PHASE_LABELS[p] || p)}</span></div>`;
        })
        .join('')
    : '<div class="muted">aguardando…</div>';
}

function bumpBar(state) {
  const done = STAGE_ORDER.filter((p) => state.phases[p] === 'done').length;
  const total = Math.max(done + 1, Object.keys(state.phases).length);
  el('pbar').style.width = Math.min(96, Math.round((done / total) * 100)) + '%';
}

// Timeline de raciocínio do agente: renderiza os eventos `log` (plano · replan ·
// seleção · execução · stop-hint) — cada passo justificado, sem caixa-preta.
const _REASON_KIND = (msg) => {
  const m = /\[([a-z-]+)(?::([a-z]+))?\]/.exec(msg || '');
  if (!m) return { tag: 'log', cls: '' };
  const tag = m[2] ? `${m[1]}:${m[2]}` : m[1];
  const cls = m[2] === 'ai' || m[1] === 'stop-hint' ? 'ai' : m[1] === 'planned' ? 'plan' : '';
  return { tag, cls };
};
function renderReasoning(state) {
  el('reasoning').innerHTML = state.reasoning
    .slice(-40)
    .reverse()
    .map((e) => {
      const { tag, cls } = _REASON_KIND(e.message);
      const text = esc((e.message || '').replace(/^#\d+\s*\[[^\]]+\]\s*/, ''));
      return `<div class="cascade-line ${cls}"><span class="tool">${esc(tag)}</span> — ${text}</div>`;
    })
    .join('');
}

function renderFeed(state) {
  const rows = state.discoveries
    .slice(-30)
    .reverse()
    .map((d) => {
      const f = d.finding;
      const cls = SEVKEY[f.severity] || 'info';
      const casc = (d.cascade_triggered || []).length
        ? `<div class="casc">↳ cascata: dispara ${d.cascade_triggered.map(esc).join(', ')}</div>`
        : '';
      return `<div class="feeditem ${cls}"><div>${sevPill(f.severity)}
        <b>${esc(f.title)}</b> <span class="muted mono">${esc(f.affected_asset)}</span>
        <span class="muted">· ${esc(f.source_tool)}</span></div>${casc}</div>`;
    })
    .join('');
  el('feed').innerHTML = rows || '<div class="empty">aguardando descobertas…</div>';
}

window.cancelJob = async (jobId) => {
  try {
    await apiPost('/jobs/' + jobId + '/cancel', {});
    toast('Cancelamento solicitado…');
  } catch (e) {
    toast('Falha ao cancelar.');
  }
};

async function pollFallback(jobId, state) {
  // fallback se o WebSocket falhar: polling do buffer de eventos.
  let cursor = 0;
  const tick = async () => {
    let data;
    try {
      data = await api(`/jobs/${jobId}/progress?since=${cursor}`);
    } catch (e) {
      return;
    }
    cursor = data.cursor;
    data.events.forEach((e) => handleEvent(e, state, jobId));
    if (data.status === 'running') setTimeout(tick, 600);
  };
  tick();
}

// ── VIEW: Detalhe do scan (persistido) ───────────────────────────────────────
async function viewScanDetail(root, scanId) {
  const [detail, fnd, inv, atk] = await Promise.all([
    api('/scans/' + scanId),
    api('/scans/' + scanId + '/findings'),
    api('/scans/' + scanId + '/inventory'),
    api('/scans/' + scanId + '/attack'),
  ]);
  const sev = detail.severity;
  root.innerHTML = `
    <div class="between">
      <div><h1>Scan #${scanId}</h1><p class="sub">${esc(detail.scan.engagement || '')} · ${esc(detail.scan.profile)}</p></div>
      <div class="row">
        <select id="expStyle" style="width:auto"><option value="executive">Executivo</option><option value="technical">Técnico</option></select>
        <select id="expFmt" style="width:auto"><option value="pdf">PDF</option><option value="html">HTML</option><option value="json">JSON</option><option value="csv">CSV</option><option value="sarif">SARIF</option></select>
        <button class="btn-primary" onclick="exportReport(${scanId})">⬇ Exportar relatório</button>
        <button class="btn-ghost" onclick="location.hash='#/'">‹ Painel</button>
      </div>
    </div>
    <div class="grid" style="margin-bottom:8px">
      ${kpiCard(detail.count, 'findings')}
      ${kpiCard((sev.critical || 0), 'críticos')}
      ${kpiCard((sev.high || 0), 'altos')}
      ${kpiCard((atk.hits || []).length, 'técnicas ATT&CK')}
    </div>
    <h2>Findings <select id="sevFilter" style="width:auto;margin-left:8px">
      <option value="">todas as severidades</option>
      ${SEV.map((s) => `<option value="${s}">${s}</option>`).join('')}
    </select></h2>
    <div class="tablewrap"><table>
      <thead><tr><th>Sev.</th><th>Risco</th><th>Título</th><th>Ativo</th><th>Persp.</th><th>CWE</th><th>KEV</th><th>Fonte</th></tr></thead>
      <tbody id="fbody"></tbody></table></div>
    <h2>Inventário de ativos</h2>
    <div class="tablewrap"><table>
      <thead><tr><th>Ativo</th><th>Portas</th><th>Web</th><th>Perspectivas</th><th>Findings</th><th>Risco máx.</th></tr></thead>
      <tbody>${(inv.assets || []).length
        ? inv.assets.map((a) => `<tr><td class="mono">${esc(a.host)}</td><td>${(a.ports || []).join(', ') || '—'}</td>
          <td>${(a.web_endpoints || []).length}</td><td>${(a.perspectives || []).join(', ')}</td>
          <td>${a.finding_count}</td><td>${Math.round(a.max_risk)}</td></tr>`).join('')
        : '<tr><td colspan="6" class="empty">Sem ativos.</td></tr>'}</tbody></table></div>`;

  window._fnd = fnd.findings || [];
  const renderF = () => {
    const filt = el('sevFilter').value;
    const rows = window._fnd.filter((f) => !filt || f.severity === filt);
    el('fbody').innerHTML = rows.length
      ? rows
          .map((f) => {
            const r = f.risk;
            return `<tr><td>${sevPill(f.severity)}</td><td>${r ? Math.round(r.score) : '—'}</td>
          <td>${esc(f.title)}</td><td class="mono">${esc(f.affected_asset)}</td>
          <td>${esc(f.perspective)}</td><td>${esc(f.cwe || '—')}</td><td>${kevCell(r)}</td><td>${esc(f.source_tool)}</td></tr>`;
          })
          .join('')
      : '<tr><td colspan="8" class="empty">Nenhum finding.</td></tr>';
  };
  el('sevFilter').onchange = renderF;
  renderF();
}

// exportar relatório (PDF/HTML/JSON/CSV/SARIF). PDF sem libs degrada p/ HTML no backend.
window.exportReport = (scanId) => {
  const fmt = el('expFmt').value;
  const style = el('expStyle').value;
  toast('Gerando relatório ' + fmt.toUpperCase() + '…');
  // navegação direta dispara o download (FileResponse define Content-Disposition).
  window.location.href = `${API}/scans/${scanId}/report?format=${fmt}&style=${style}`;
};

// ── VIEW: Histórico ──────────────────────────────────────────────────────────
async function viewHistory(root) {
  const scans = await api('/scans').catch(() => []);
  root.innerHTML = `<div class="between"><h1>Histórico de scans</h1>
      <button class="btn-primary" onclick="location.hash='#/new'">+ Novo Scan</button></div>
    <div class="tablewrap"><table>
      <thead><tr><th>ID</th><th>Alvo</th><th>Perfil</th><th>Status</th><th>Início</th></tr></thead>
      <tbody>${scans.length ? scans.map(scanCard).join('') : '<tr><td colspan="5" class="empty">Nenhum scan.</td></tr>'}</tbody>
    </table></div>`;
}

boot();
