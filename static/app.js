"use strict";

/* ---------- Settings (tenant + API key), persisted in localStorage ---------- */

const settings = {
  tenant: localStorage.getItem("sentinelos.tenant") || "default",
  apiKey: localStorage.getItem("sentinelos.apiKey") || "",
  // Recorded on every approve/deny decision — an audit-trail label the
  // analyst types in, not an authenticated identity (see README Known
  // Gaps: no per-user accounts/logins yet).
  analystName: localStorage.getItem("sentinelos.analystName") || "",
};

function saveSettings() {
  localStorage.setItem("sentinelos.tenant", settings.tenant);
  localStorage.setItem("sentinelos.apiKey", settings.apiKey);
  localStorage.setItem("sentinelos.analystName", settings.analystName);
}

/* ---------- HTML escaping — everything rendered here can contain
   LLM-generated or attacker-influenced text (incident descriptions,
   agent findings), so nothing goes into the DOM unescaped. ---------- */

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value === null || value === undefined ? "" : String(value);
  return div.innerHTML;
}

// Only ever called AFTER escapeHtml — the regexes below only add safe tags
// around already-escaped text, so they can't introduce raw HTML.
function lightMarkdown(value) {
  let escaped = escapeHtml(value);
  escaped = escaped.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  escaped = escaped.replace(/\n/g, "<br>");
  return escaped;
}

function timeAgo(isoString) {
  if (!isoString) return "";
  const then = new Date(isoString).getTime();
  const diffSeconds = Math.round((Date.now() - then) / 1000);
  if (diffSeconds < 5) return "just now";
  if (diffSeconds < 60) return `${diffSeconds}s ago`;
  if (diffSeconds < 3600) return `${Math.round(diffSeconds / 60)}m ago`;
  if (diffSeconds < 86400) return `${Math.round(diffSeconds / 3600)}h ago`;
  return `${Math.round(diffSeconds / 86400)}d ago`;
}

/* ---------- API helpers ---------- */

function tenantPrefix() {
  return `/tenants/${encodeURIComponent(settings.tenant || "default")}`;
}

function authHeaders(extra) {
  const headers = Object.assign({}, extra || {});
  if (settings.apiKey) headers["Authorization"] = `Bearer ${settings.apiKey}`;
  return headers;
}

async function apiGet(path) {
  const response = await fetch(path, { headers: authHeaders() });
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
  return response.json();
}

async function apiPost(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body || {}),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
  return response.json();
}

/** Consumes a POST endpoint that returns text/event-stream (our SSE
 * format), calling onEvent(parsedJson) for each `data: ...` line. Native
 * EventSource can't do POST bodies or custom headers, so this reads the
 * fetch Response body manually. */
async function streamPost(path, body, onEvent) {
  const response = await fetch(path, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body || {}),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const rawEvent = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 2);
      if (rawEvent.startsWith("data: ")) {
        try {
          onEvent(JSON.parse(rawEvent.slice(6)));
        } catch (err) {
          console.error("Failed to parse SSE event", err, rawEvent);
        }
      }
    }
  }
}

/* ---------- Connection status ---------- */

async function checkConnection() {
  const pill = document.getElementById("connection-status");
  try {
    const response = await fetch("/health");
    if (response.ok) {
      pill.textContent = "connected";
      pill.className = "status-pill status-ok";
    } else {
      throw new Error("unhealthy");
    }
  } catch (err) {
    pill.textContent = "unreachable";
    pill.className = "status-pill status-error";
  }
}

/* ---------- Tabs ---------- */

function initTabs() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    });
  });
}

/* ---------- Incident list ---------- */

let selectedThreadId = null;

function severityBadge(severity) {
  return `<span class="badge badge-${escapeHtml(severity)}">${escapeHtml(severity)}</span>`;
}

function statusBadge(status) {
  return `<span class="badge-status ${escapeHtml(status)}">${escapeHtml(status)}</span>`;
}

let currentRows = [];
let keyboardFocusIndex = -1;

function activeFilters() {
  return {
    search: document.getElementById("filter-search").value.trim(),
    severity: document.getElementById("filter-severity").value,
    status: document.getElementById("filter-status").value,
  };
}

function buildIncidentsQuery() {
  const { search, severity, status } = activeFilters();
  const params = new URLSearchParams({ limit: "100" });
  if (search) params.set("search", search);
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  return params.toString();
}

async function loadIncidents() {
  const tbody = document.getElementById("incident-list-body");
  try {
    const rows = await apiGet(`${tenantPrefix()}/incidents?${buildIncidentsQuery()}`);
    currentRows = rows;
    // Drop selections for incidents no longer in view (resolved, filtered
    // out, etc.) so the bulk bar's count never lies about what a click
    // would actually act on.
    const visibleIds = new Set(rows.map((r) => r.thread_id));
    for (const id of bulkSelected) {
      if (!visibleIds.has(id)) bulkSelected.delete(id);
    }
    if (!rows.length) {
      const { search, severity, status } = activeFilters();
      const filtered = search || severity || status;
      tbody.innerHTML = `<tr><td colspan="5" class="empty-row">${
        filtered
          ? "No incidents match the current filters."
          : `No incidents yet for tenant "${escapeHtml(settings.tenant)}".` +
            `<span class="empty-hint">Submit one from the "New Incident" tab, or point an ingestion source at this tenant — see GETTING_STARTED.md.</span>`
      }</td></tr>`;
      updateBulkBar();
      return;
    }
    tbody.innerHTML = rows
      .map((r, idx) => {
        const selected = r.thread_id === selectedThreadId ? "row-selected" : "";
        const kbdFocus = idx === keyboardFocusIndex ? "row-keyboard-focus" : "";
        const pendingMark = r.has_pending_actions ? " ⏳" : "";
        const checkboxCell = r.has_pending_actions
          ? `<input type="checkbox" class="bulk-checkbox" data-thread-id="${escapeHtml(r.thread_id)}" ${
              bulkSelected.has(r.thread_id) ? "checked" : ""
            }>`
          : "";
        return `
          <tr class="row-clickable ${selected} ${kbdFocus}" data-thread-id="${escapeHtml(r.thread_id)}" data-idx="${idx}">
            <td class="td-checkbox">${checkboxCell}</td>
            <td>${severityBadge(r.severity)}</td>
            <td>${statusBadge(r.status)}${pendingMark}</td>
            <td class="desc-cell" title="${escapeHtml(r.description)}">${escapeHtml(r.description)}</td>
            <td>${escapeHtml(timeAgo(r.updated_at))}</td>
          </tr>`;
      })
      .join("");
    tbody.querySelectorAll("tr[data-thread-id]").forEach((tr) => {
      tr.addEventListener("click", (evt) => {
        if (evt.target.classList.contains("bulk-checkbox")) return;
        keyboardFocusIndex = Number(tr.dataset.idx);
        openIncident(tr.dataset.threadId);
      });
    });
    tbody.querySelectorAll("input.bulk-checkbox").forEach((cb) => {
      cb.addEventListener("click", (evt) => evt.stopPropagation());
      cb.addEventListener("change", () => {
        if (cb.checked) bulkSelected.add(cb.dataset.threadId);
        else bulkSelected.delete(cb.dataset.threadId);
        updateBulkBar();
      });
    });
    updateBulkBar();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-row">Failed to load: ${escapeHtml(err.message)}</td></tr>`;
  }
}

/* ---------- Bulk approve/deny across selected incidents ---------- */

const bulkSelected = new Set();

function updateBulkBar() {
  const bar = document.getElementById("bulk-bar");
  const count = bulkSelected.size;
  bar.hidden = count === 0;
  document.getElementById("bulk-count").textContent = `${count} selected`;
}

async function bulkDecide(approve) {
  if (!settings.analystName) {
    alert(
      "Set your analyst name in the top bar first — it's recorded in the audit trail for every " +
        "approve/deny decision, so \"who approved this\" is never unanswerable."
    );
    return;
  }
  const ids = Array.from(bulkSelected);
  if (!ids.length) return;
  const verb = approve ? "approve" : "deny";
  if (!confirm(`${approve ? "Approve" : "Deny"} the pending action(s) on ${ids.length} incident(s) as "${settings.analystName}"?`)) {
    return;
  }

  const results = await Promise.allSettled(
    ids.map((id) =>
      apiPost(`${tenantPrefix()}/incidents/${encodeURIComponent(id)}/${verb}`, { approved_by: settings.analystName })
    )
  );
  const failures = results.filter((r) => r.status === "rejected");
  bulkSelected.clear();
  await loadIncidents();
  await loadStats();
  if (selectedThreadId) await renderIncidentDetail(selectedThreadId);
  if (failures.length) {
    alert(`${failures.length} of ${ids.length} failed to ${verb}. Check the incident list for what went through.`);
  }
}

/* ---------- First-visit onboarding banner ---------- */

function initOnboardingBanner() {
  const banner = document.getElementById("onboarding-banner");
  let dismissed = false;
  try {
    dismissed = localStorage.getItem("sentinelos.onboardingDismissed") === "true";
  } catch (err) {
    // Private browsing / storage blocked -- fail open (show it once per
    // page load) rather than crash the whole dashboard over a banner.
  }
  banner.hidden = dismissed;
  document.getElementById("onboarding-dismiss-btn").addEventListener("click", () => {
    banner.hidden = true;
    try {
      localStorage.setItem("sentinelos.onboardingDismissed", "true");
    } catch (err) {
      // Ignore -- worst case it reappears next visit, not a functional problem.
    }
  });
}

function initBulkActions() {
  document.getElementById("bulk-approve-btn").addEventListener("click", () => bulkDecide(true));
  document.getElementById("bulk-deny-btn").addEventListener("click", () => bulkDecide(false));
  document.getElementById("bulk-clear-btn").addEventListener("click", () => {
    bulkSelected.clear();
    loadIncidents();
  });
}

/* ---------- Summary stats bar ---------- */

async function loadStats() {
  try {
    const stats = await apiGet(`${tenantPrefix()}/incidents/stats`);
    document.getElementById("stat-total").textContent = stats.total;
    document.getElementById("stat-open").textContent = stats.open;
    document.getElementById("stat-pending").textContent = stats.pending_approval;
    document.getElementById("stat-low").textContent = stats.by_severity.low;
    document.getElementById("stat-medium").textContent = stats.by_severity.medium;
    document.getElementById("stat-high").textContent = stats.by_severity.high;
  } catch (err) {
    // Stats are a summary convenience, not core functionality -- a
    // failure here shouldn't block the incident list from working.
    console.error("Failed to load incident stats", err);
  }
}

/* ---------- Search/filter wiring ---------- */

let searchDebounceTimer = null;

function initFilters() {
  const search = document.getElementById("filter-search");
  search.addEventListener("input", () => {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => {
      keyboardFocusIndex = -1;
      loadIncidents();
    }, 250);
  });
  ["filter-severity", "filter-status"].forEach((id) => {
    document.getElementById(id).addEventListener("change", () => {
      keyboardFocusIndex = -1;
      loadIncidents();
    });
  });
}

/* ---------- Keyboard shortcuts ---------- */

function isTypingInField() {
  const tag = document.activeElement && document.activeElement.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

function moveKeyboardFocus(delta) {
  if (!currentRows.length) return;
  keyboardFocusIndex = Math.max(0, Math.min(currentRows.length - 1, keyboardFocusIndex + delta));
  document.querySelectorAll(".incident-table tr[data-idx]").forEach((tr) => {
    tr.classList.toggle("row-keyboard-focus", Number(tr.dataset.idx) === keyboardFocusIndex);
  });
  const focused = document.querySelector(`.incident-table tr[data-idx="${keyboardFocusIndex}"]`);
  if (focused) focused.scrollIntoView({ block: "nearest" });
}

function initKeyboardShortcuts() {
  document.addEventListener("keydown", (evt) => {
    if (isTypingInField()) {
      if (evt.key === "Escape") document.activeElement.blur();
      return;
    }
    // Only active on the Incidents tab.
    if (!document.getElementById("tab-incidents").classList.contains("active")) return;

    if (evt.key === "/") {
      evt.preventDefault();
      document.getElementById("filter-search").focus();
    } else if (evt.key === "j" || evt.key === "ArrowDown") {
      evt.preventDefault();
      moveKeyboardFocus(1);
    } else if (evt.key === "k" || evt.key === "ArrowUp") {
      evt.preventDefault();
      moveKeyboardFocus(-1);
    } else if (evt.key === "Enter") {
      const row = currentRows[keyboardFocusIndex];
      if (row) openIncident(row.thread_id);
    } else if (evt.key === "a" || evt.key === "d") {
      const row = currentRows[keyboardFocusIndex];
      if (row && row.thread_id === selectedThreadId) {
        const btn = document.querySelector(
          evt.key === "a" ? "button.btn-approve" : "button.btn-deny"
        );
        if (btn) btn.click();
      }
    }
  });
}

/* ---------- Incident detail ---------- */

function renderFindings(messages) {
  if (!messages || !messages.length) return "<p>No agent findings yet.</p>";
  return messages
    .map(
      (m) => `
      <div class="finding-block">
        <div class="finding-agent">${escapeHtml(m.agent)}</div>
        <div class="finding-content">${lightMarkdown(m.content)}</div>
      </div>`
    )
    .join("");
}

function renderThreatIntel(results) {
  if (!results || !results.length) {
    return "<p>No verified threat-intel lookups (no lookupable IOCs, or no provider API key configured).</p>";
  }
  return results
    .map(
      (r) => `
      <div class="ti-row">
        <strong>${escapeHtml(r.indicator)}</strong> (${escapeHtml(r.indicator_type)}) — ${escapeHtml(r.source)}
        <span class="verdict verdict-${escapeHtml(r.verdict)}">${escapeHtml(r.verdict)}</span>
        <div>${escapeHtml(r.detail)}</div>
      </div>`
    )
    .join("");
}

function renderAttackTechnique(technique) {
  if (!technique) return "<p>No ATT&CK technique cited.</p>";
  if (technique.verified) {
    return `<p class="attack-verified">✅ <strong>${escapeHtml(technique.id)}</strong> — ${escapeHtml(technique.name)} (${escapeHtml(technique.tactic)}) — verified against local dataset</p>`;
  }
  return `<p class="attack-unverified">⚠️ <strong>${escapeHtml(technique.id)}</strong> — not found in local ATT&CK dataset. May be hallucinated, a typo, or a real technique outside our curated subset.</p>`;
}

function renderProposedActions(actions, threadId) {
  if (!actions || !actions.length) return "<p>No actions proposed.</p>";

  const cardsHtml = actions
    .map(
      (a) => `
        <div class="action-card">
          <div class="action-title">${escapeHtml(a.action)}</div>
          <div class="action-target">→ ${escapeHtml(a.target)}</div>
          <div class="action-rationale">${escapeHtml(a.rationale)}</div>
        </div>`
    )
    .join("");

  // Approval is all-or-nothing per incident -- resolve_proposed_actions
  // sets the same decision on every proposed action in one call, there
  // is no independent per-action approval. One decision control for the
  // whole set, not one per card, so the UI doesn't imply a capability
  // that doesn't exist.
  const decided = actions.find((a) => a.approved !== null && a.approved !== undefined);
  let decisionHtml;
  if (decided) {
    const byLabel = decided.approved_by ? ` by ${escapeHtml(decided.approved_by)}` : " by (unspecified)";
    const countNote = actions.length > 1 ? ` (all ${actions.length} actions)` : "";
    decisionHtml = decided.approved
      ? `<span class="action-decided approved">✔ Approved${byLabel}${countNote}</span>`
      : `<span class="action-decided denied">✘ Denied${byLabel}${countNote}</span>`;
  } else {
    const approveLabel = actions.length > 1 ? `Approve All (${actions.length})` : "Approve";
    const denyLabel = actions.length > 1 ? `Deny All (${actions.length})` : "Deny";
    decisionHtml = `
      <div class="action-buttons">
        <button class="btn-approve" data-approve="true" data-thread-id="${escapeHtml(threadId)}">${approveLabel}</button>
        <button class="btn-deny" data-approve="false" data-thread-id="${escapeHtml(threadId)}">${denyLabel}</button>
      </div>`;
  }

  return `<div class="action-cards">${cardsHtml}</div><div class="action-decision">${decisionHtml}</div>`;
}

function renderTokenUsage(usage) {
  if (!usage || !usage.total_tokens) return "<p>No usage recorded.</p>";
  const byAgent = Object.entries(usage.by_agent || {})
    .map(([name, u]) => `<div class="token-usage-line">${escapeHtml(name)}: ${u.total_tokens} tokens</div>`)
    .join("");
  return `<div class="token-usage-line"><strong>Total: ${usage.total_tokens} tokens</strong> (${usage.input_tokens} in / ${usage.output_tokens} out)</div>${byAgent}`;
}

/** Every audit_log entry across this project follows "<Actor> -> <detail>"
 * (see agents/*.py, workflows/incident_pipeline.py) -- split on the first
 * occurrence so the actor can be styled distinctly, with a safe fallback
 * for anything that doesn't match rather than breaking the render. */
function parseAuditEntry(entry) {
  const idx = entry.indexOf(" -> ");
  if (idx === -1) return { actor: "Event", detail: entry };
  return { actor: entry.slice(0, idx), detail: entry.slice(idx + 4) };
}

function auditEntryKind(actor, detail) {
  if (/ERROR:/.test(detail)) return "error";
  if (/^Human Reviewer/.test(actor)) return "human";
  if (/^Correlation/.test(actor)) return "correlation";
  return "agent";
}

function renderAuditLog(entries) {
  if (!entries || !entries.length) return "<p>Empty.</p>";
  return `<div class="audit-timeline">${entries
    .map((e) => {
      const { actor, detail } = parseAuditEntry(e);
      const kind = auditEntryKind(actor, detail);
      return `
        <div class="audit-entry audit-kind-${kind}">
          <div class="audit-actor">${escapeHtml(actor)}</div>
          <div class="audit-detail">${escapeHtml(detail)}</div>
        </div>`;
    })
    .join("")}</div>`;
}

async function openIncident(threadId) {
  selectedThreadId = threadId;
  document.querySelectorAll(".incident-table tr[data-thread-id]").forEach((tr) => {
    tr.classList.toggle("row-selected", tr.dataset.threadId === threadId);
  });
  await renderIncidentDetail(threadId);
}

async function renderIncidentDetail(threadId) {
  const pane = document.getElementById("detail-pane");
  try {
    const data = await apiGet(`${tenantPrefix()}/incidents/${encodeURIComponent(threadId)}`);
    const incident = data.incident;
    pane.innerHTML = `
      <div class="detail-header">
        <h2>${severityBadge(incident.severity)} ${statusBadge(incident.status)}</h2>
        <span class="detail-id">${escapeHtml(incident.id)}</span>
      </div>
      <div class="detail-desc">${escapeHtml(incident.description)}</div>
      <div class="detail-section"><h3>Affected Assets</h3><p>${incident.affected_assets.map(escapeHtml).join(", ") || "none"}</p></div>
      <div class="detail-section"><h3>Indicators of Compromise</h3><p>${incident.iocs.map(escapeHtml).join(", ") || "none"}</p></div>
      <div class="detail-section"><h3>Agent Findings</h3>${renderFindings(data.messages)}</div>
      <div class="detail-section"><h3>Threat Intelligence</h3>${renderThreatIntel(data.threat_intel)}</div>
      <div class="detail-section"><h3>ATT&amp;CK Mapping</h3>${renderAttackTechnique(data.attack_technique)}</div>
      <div class="detail-section"><h3>Proposed Actions</h3>${renderProposedActions(data.proposed_actions, threadId)}</div>
      <div class="detail-section"><h3>Token Usage</h3>${renderTokenUsage(data.token_usage)}</div>
      <div class="detail-section"><h3>Audit Log</h3>${renderAuditLog(data.audit_log)}</div>
    `;
    pane.querySelectorAll("button[data-approve]").forEach((btn) => {
      btn.addEventListener("click", () => decideAction(btn.dataset.threadId, btn.dataset.approve === "true"));
    });
  } catch (err) {
    pane.innerHTML = `<div class="empty-state">Failed to load incident: ${escapeHtml(err.message)}</div>`;
  }
}

async function decideAction(threadId, approve) {
  const verb = approve ? "approve" : "deny";
  if (!settings.analystName) {
    alert(
      "Set your analyst name in the top bar first — it's recorded in the audit trail for every " +
        "approve/deny decision, so \"who approved this\" is never unanswerable."
    );
    return;
  }
  try {
    await apiPost(`${tenantPrefix()}/incidents/${encodeURIComponent(threadId)}/${verb}`, {
      approved_by: settings.analystName,
    });
    await renderIncidentDetail(threadId);
    await loadIncidents();
    await loadStats();
  } catch (err) {
    alert(`Failed to ${verb} actions: ${err.message}`);
  }
}

/* ---------- New incident (live streaming) ---------- */

function appendLiveEvent(container, event) {
  const div = document.createElement("div");
  div.className = `live-event event-${event.event}`;
  if (event.event === "started") {
    div.innerHTML = `<div class="live-event-label">Started</div>Incident <code>${escapeHtml(event.thread_id)}</code> created.`;
  } else if (event.event === "agent_step") {
    div.innerHTML = `<div class="live-event-label">${escapeHtml(event.agent)}</div>${lightMarkdown(event.content)}`;
  } else if (event.event === "complete") {
    const actionsHtml = renderProposedActions(event.proposed_actions, event.thread_id);
    div.innerHTML = `<div class="live-event-label">Complete — status: ${escapeHtml(event.status)}</div>${actionsHtml}`;
    div.querySelectorAll("button[data-approve]").forEach((btn) => {
      btn.addEventListener("click", () => decideAction(btn.dataset.threadId, btn.dataset.approve === "true"));
    });
  }
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

async function submitNewIncident(evt) {
  evt.preventDefault();
  const submitBtn = document.getElementById("ni-submit-btn");
  const output = document.getElementById("ni-live-output");
  output.hidden = false;
  output.innerHTML = "";
  submitBtn.disabled = true;

  const payload = {
    description: document.getElementById("ni-description").value,
    severity: document.getElementById("ni-severity").value,
    source: document.getElementById("ni-source").value || null,
    affected_assets: document.getElementById("ni-assets").value.split(",").map((s) => s.trim()).filter(Boolean),
    iocs: document.getElementById("ni-iocs").value.split(",").map((s) => s.trim()).filter(Boolean),
  };

  try {
    await streamPost(`${tenantPrefix()}/incidents/stream`, payload, (event) => appendLiveEvent(output, event));
    await loadIncidents();
    await loadStats();
  } catch (err) {
    const div = document.createElement("div");
    div.className = "live-event";
    div.textContent = `Error: ${err.message}`;
    output.appendChild(div);
  } finally {
    submitBtn.disabled = false;
  }
}

/* ---------- Threat hunt ---------- */

async function submitHunt(evt) {
  evt.preventDefault();
  const submitBtn = document.getElementById("hunt-submit-btn");
  const output = document.getElementById("hunt-output");
  output.hidden = false;
  output.innerHTML = "<div class=\"live-event\">Running…</div>";
  submitBtn.disabled = true;

  try {
    const query = document.getElementById("hunt-query").value;
    const data = await apiPost(`${tenantPrefix()}/hunts`, { query });
    output.innerHTML = `
      <div class="detail-section"><h3>Findings</h3>${renderFindings(data.messages)}</div>
      <div class="detail-section"><h3>ATT&amp;CK Mapping</h3>${renderAttackTechnique(data.attack_technique)}</div>
    `;
  } catch (err) {
    output.innerHTML = `<div class="live-event">Error: ${escapeHtml(err.message)}</div>`;
  } finally {
    submitBtn.disabled = false;
  }
}

/* ---------- Standalone IOC lookup ---------- */

async function submitIocLookup(evt) {
  evt.preventDefault();
  const submitBtn = document.getElementById("ioc-lookup-submit-btn");
  const output = document.getElementById("ioc-lookup-output");
  output.hidden = false;
  output.innerHTML = "<div class=\"live-event\">Looking up…</div>";
  submitBtn.disabled = true;

  const iocs = document
    .getElementById("ioc-lookup-input")
    .value.split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  try {
    const results = await apiPost(`${tenantPrefix()}/enrichment/lookup`, { iocs });
    output.innerHTML = `<div class="detail-section"><h3>Threat Intelligence</h3>${renderThreatIntel(results)}</div>`;
  } catch (err) {
    output.innerHTML = `<div class="live-event">Error: ${escapeHtml(err.message)}</div>`;
  } finally {
    submitBtn.disabled = false;
  }
}

/* ---------- Wiring ---------- */

function initSettingsForm() {
  document.getElementById("tenant-input").value = settings.tenant;
  document.getElementById("apikey-input").value = settings.apiKey;
  document.getElementById("analyst-name-input").value = settings.analystName;
  document.getElementById("apply-settings-btn").addEventListener("click", () => {
    settings.tenant = document.getElementById("tenant-input").value.trim() || "default";
    settings.apiKey = document.getElementById("apikey-input").value.trim();
    settings.analystName = document.getElementById("analyst-name-input").value.trim();
    saveSettings();
    selectedThreadId = null;
    keyboardFocusIndex = -1;
    document.getElementById("detail-pane").innerHTML = '<div class="empty-state">Select an incident to view details.</div>';
    loadIncidents();
    loadStats();
    checkConnection();
  });
}

function initAutoRefresh() {
  document.getElementById("refresh-btn").addEventListener("click", () => {
    loadIncidents();
    loadStats();
  });
  setInterval(() => {
    if (document.getElementById("auto-refresh-toggle").checked) {
      loadIncidents();
      loadStats();
      if (selectedThreadId) renderIncidentDetail(selectedThreadId);
    }
  }, 15000);
}

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initSettingsForm();
  initAutoRefresh();
  initFilters();
  initKeyboardShortcuts();
  initBulkActions();
  initOnboardingBanner();
  document.getElementById("new-incident-form").addEventListener("submit", submitNewIncident);
  document.getElementById("hunt-form").addEventListener("submit", submitHunt);
  document.getElementById("ioc-lookup-form").addEventListener("submit", submitIocLookup);
  checkConnection();
  loadIncidents();
  loadStats();
});
