// Interceptor UI — vanilla JS, no build step. Talks to the Flask API and
// listens on /ws for live pushes as traffic is captured.

const state = {
  requests: [],       // most-recent-first, mirrors server order
  selectedId: null,
  methodFilter: "",
  query: "",
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ---------------------------------------------------------------------
// WebSocket — live updates
// ---------------------------------------------------------------------
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.type === "request") {
      state.requests.unshift(msg.request);
      if (state.requests.length > 500) state.requests.pop();
      renderTrafficList();
    } else if (msg.type === "cleared") {
      state.requests = [];
      state.selectedId = null;
      renderTrafficList();
      renderDetail(null);
    } else if (msg.type === "blocked_domains") {
      renderBlockList(msg.domains);
    } else if (msg.type === "proxy_status") {
      renderProxyStatus(msg.status);
    }
  };

  ws.onclose = () => setTimeout(connectWS, 2000); // auto-reconnect
}

// ---------------------------------------------------------------------
// Proxy status + toggle
// ---------------------------------------------------------------------
function renderProxyStatus(status) {
  const dot = $("#proxyDot");
  const label = $("#proxyLabel");
  const btn = $("#proxyToggleBtn");

  dot.classList.toggle("on", status.running);
  dot.classList.toggle("off", !status.running);
  label.textContent = status.running
    ? `proxy on ${status.host}:${status.port}`
    : "proxy stopped";
  btn.textContent = status.running ? "Stop" : "Start";
  btn.dataset.running = status.running ? "1" : "0";
}

async function fetchProxyStatus() {
  const res = await fetch("/api/proxy-status");
  renderProxyStatus(await res.json());
}

async function toggleProxy() {
  const running = $("#proxyToggleBtn").dataset.running === "1";
  const res = await fetch("/api/toggle-proxy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: running ? "stop" : "start" }),
  });
  const data = await res.json();
  await fetchProxyStatus();
  if (!data.success) toast(data.message);
}

// ---------------------------------------------------------------------
// Traffic list
// ---------------------------------------------------------------------
function statusClass(code) {
  if (!code) return "";
  if (code < 300) return "status-2xx";
  if (code < 400) return "status-3xx";
  return "status-4xx";
}

function shortUrl(url) {
  try {
    const u = new URL(url);
    return u.host + u.pathname + u.search;
  } catch {
    return url;
  }
}

function renderTrafficList() {
  const list = $("#trafficList");
  const filtered = state.requests.filter((r) => {
    if (state.methodFilter && r.method !== state.methodFilter) return false;
    if (state.query) {
      const hay = (r.url + " " + (r.host || "")).toLowerCase();
      if (!hay.includes(state.query)) return false;
    }
    return true;
  });

  $("#reqCount").textContent = `${state.requests.length} request${state.requests.length === 1 ? "" : "s"}`;

  if (filtered.length === 0) {
    list.innerHTML = `<div class="empty-state">${
      state.requests.length === 0
        ? "No traffic captured yet.<br>Start the proxy, or use Forge to send a request."
        : "No requests match your filter."
    }</div>`;
    return;
  }

  list.innerHTML = "";
  for (const r of filtered) {
    const row = document.createElement("div");
    row.className = "traffic-row" + (r.id === state.selectedId ? " selected" : "");
    row.dataset.id = r.id;

    const code = r.response && r.response.status_code;
    const err = r.response && r.response.error;

    row.innerHTML = `
      <span class="method-chip method-${r.method}">${r.method}</span>
      <span class="traffic-row-url" title="${escapeHtml(r.url)}">${escapeHtml(shortUrl(r.url))}</span>
      <span class="traffic-row-status ${statusClass(code)}">${code || (err ? "ERR" : "…")}</span>
      ${r.source !== "proxy" ? `<span class="traffic-row-badge">${r.source}</span>` : ""}
    `;
    row.addEventListener("click", () => selectRequest(r.id));
    list.appendChild(row);
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// ---------------------------------------------------------------------
// Detail pane
// ---------------------------------------------------------------------
function headerTable(headers) {
  if (!headers || Object.keys(headers).length === 0) {
    return `<div class="empty-state" style="padding:10px 0;text-align:left;">none</div>`;
  }
  const rows = Object.entries(headers)
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`)
    .join("");
  return `<table class="header-table">${rows}</table>`;
}

function bodyBlock(body) {
  if (body === null || body === undefined || body === "") {
    return `<pre class="code-block">(empty)</pre>`;
  }
  const text = typeof body === "string" ? body : JSON.stringify(body, null, 2);
  return `<pre class="code-block">${escapeHtml(text)}</pre>`;
}

function selectRequest(id) {
  state.selectedId = id;
  renderTrafficList();
  const req = state.requests.find((r) => r.id === id);
  renderDetail(req);
}

function renderDetail(req) {
  const body = $("#detailBody");
  const actions = $("#detailActions");

  if (!req) {
    actions.hidden = true;
    body.innerHTML = `<div class="empty-state">Select a request from the traffic list to inspect it.</div>`;
    return;
  }

  actions.hidden = false;
  const resp = req.response;

  let responseSection;
  if (!resp) {
    responseSection = `<div class="empty-state" style="padding:10px 0;text-align:left;">pending / no response captured</div>`;
  } else if (resp.error) {
    responseSection = `<pre class="code-block" style="color:var(--danger)">${escapeHtml(resp.error)}</pre>`;
  } else {
    responseSection = `
      <div class="result-status ${statusClass(resp.status_code)}">
        ${resp.status_code}${resp.elapsed_ms ? ` · ${resp.elapsed_ms}ms` : ""}
      </div>
      <div class="detail-section-title">Response headers</div>
      ${headerTable(resp.headers)}
      <div class="detail-section-title" style="margin-top:12px;">Response body</div>
      ${bodyBlock(resp.body)}
    `;
  }

  body.innerHTML = `
    <div class="detail-title">${req.method} ${escapeHtml(req.url)}</div>
    <div class="detail-meta">#${req.id} · ${req.timestamp} · via ${req.source}</div>

    <div class="detail-section">
      <div class="detail-section-title">Note</div>
      <input class="note-input" id="noteInput" type="text" placeholder="add a note (e.g. 'IDOR candidate')" value="${escapeHtml(req.note || "")}">
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Request headers</div>
      ${headerTable(req.headers)}
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Request body</div>
      ${bodyBlock(req.body)}
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Response</div>
      ${responseSection}
    </div>
  `;

  const noteInput = $("#noteInput");
  let noteTimer;
  noteInput.addEventListener("input", () => {
    clearTimeout(noteTimer);
    noteTimer = setTimeout(() => {
      fetch(`/api/request/${req.id}/note`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note: noteInput.value }),
      });
      const local = state.requests.find((r) => r.id === req.id);
      if (local) local.note = noteInput.value;
    }, 400);
  });
}

// ---------------------------------------------------------------------
// Tool tabs (Repeater / Forge / Rules)
// ---------------------------------------------------------------------
function switchTool(name) {
  $$(".tool-tab").forEach((t) => t.classList.toggle("active", t.dataset.tool === name));
  $$(".tool-panel").forEach((p) => (p.hidden = p.id !== `tool-${name}`));
}

function sendRequestToRepeater(req) {
  switchTool("repeater");
  $("#sendMethod").value = req.method === "CONNECT" ? "GET" : req.method;
  $("#sendUrl").value = req.url;
  $("#sendHeaders").value = JSON.stringify(req.headers || {}, null, 2);
  $("#sendBody").value = req.body || "";
  $("#sendResult").innerHTML = "";
}

async function submitSendForm(e) {
  e.preventDefault();
  const method = $("#sendMethod").value;
  const url = $("#sendUrl").value.trim();
  let headers = {};
  const headersRaw = $("#sendHeaders").value.trim();
  if (headersRaw) {
    try {
      headers = JSON.parse(headersRaw);
    } catch {
      $("#sendResult").innerHTML = `<pre class="code-block" style="color:var(--danger)">Headers must be valid JSON</pre>`;
      return;
    }
  }
  const body = $("#sendBody").value;

  const btn = e.target.querySelector("button[type=submit]");
  btn.disabled = true;
  btn.textContent = "Sending…";

  try {
    const res = await fetch("/api/forge-request", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ method, url, headers, body }),
    });
    const data = await res.json();
    renderSendResult(data);
  } finally {
    btn.disabled = false;
    btn.textContent = "Send";
  }
}

function renderSendResult(req) {
  const el = $("#sendResult");
  const resp = req.response;
  if (!resp) {
    el.innerHTML = "";
    return;
  }
  if (resp.error) {
    el.innerHTML = `<div class="result-card"><div class="result-status" style="color:var(--danger)">Error</div>${bodyBlock(resp.error)}</div>`;
    return;
  }
  el.innerHTML = `
    <div class="result-card">
      <div class="result-status ${statusClass(resp.status_code)}">${resp.status_code}${resp.elapsed_ms ? ` · ${resp.elapsed_ms}ms` : ""}</div>
      ${bodyBlock(resp.body)}
    </div>
  `;
}

// ---------------------------------------------------------------------
// Block rules
// ---------------------------------------------------------------------
function renderBlockList(domains) {
  const list = $("#blockList");
  if (!domains.length) {
    list.innerHTML = `<li style="justify-content:center;color:var(--text-2);">no blocked domains</li>`;
    return;
  }
  list.innerHTML = domains
    .map(
      (d) => `<li><span>${escapeHtml(d)}</span><button data-domain="${escapeHtml(d)}">✕</button></li>`
    )
    .join("");
  list.querySelectorAll("button").forEach((btn) => {
    btn.addEventListener("click", () => unblockDomain(btn.dataset.domain));
  });
}

async function fetchBlockList() {
  const res = await fetch("/api/blocked-domains");
  renderBlockList(await res.json());
}

async function blockDomain(domain) {
  await fetch("/api/block-domain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
  });
  fetchBlockList();
}

async function unblockDomain(domain) {
  await fetch("/api/unblock-domain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
  });
  fetchBlockList();
}

// ---------------------------------------------------------------------
// Misc UI helpers
// ---------------------------------------------------------------------
let toastTimer;
function toast(msg) {
  let el = $("#toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "toast";
    el.className = "toast";
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.style.display = "none"), 2500);
}

async function copyCurl() {
  if (state.selectedId == null) return;
  const res = await fetch(`/api/request/${state.selectedId}/curl`);
  const data = await res.json();
  if (data.curl) {
    await navigator.clipboard.writeText(data.curl);
    toast("curl command copied to clipboard");
  }
}

async function clearTraffic() {
  if (!confirm("Clear all captured traffic? This cannot be undone.")) return;
  await fetch("/api/requests", { method: "DELETE" });
}

async function loadInitialRequests() {
  const res = await fetch("/api/requests");
  state.requests = await res.json();
  renderTrafficList();
}

// ---------------------------------------------------------------------
// Wire up event listeners
// ---------------------------------------------------------------------
function init() {
  $("#proxyToggleBtn").addEventListener("click", toggleProxy);
  $("#clearBtn").addEventListener("click", clearTraffic);

  $("#searchInput").addEventListener("input", (e) => {
    state.query = e.target.value.trim().toLowerCase();
    renderTrafficList();
  });
  $("#methodFilter").addEventListener("change", (e) => {
    state.methodFilter = e.target.value;
    renderTrafficList();
  });

  $$(".tool-tab").forEach((tab) => {
    tab.addEventListener("click", () => switchTool(tab.dataset.tool));
  });

  $("#sendForm").addEventListener("submit", submitSendForm);
  $("#sendToRepeaterBtn").addEventListener("click", () => {
    const req = state.requests.find((r) => r.id === state.selectedId);
    if (req) sendRequestToRepeater(req);
  });
  $("#copyCurlBtn").addEventListener("click", copyCurl);

  $("#blockForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("#domainInput");
    const domain = input.value.trim();
    if (domain) {
      blockDomain(domain);
      input.value = "";
    }
  });

  connectWS();
  fetchProxyStatus();
  fetchBlockList();
  loadInitialRequests();
}

document.addEventListener("DOMContentLoaded", init);
