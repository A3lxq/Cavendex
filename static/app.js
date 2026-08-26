"use strict";

/* ---------- Settings (tenant + API key), persisted in localStorage ---------- */

const settings = {
  tenant: localStorage.getItem("sentinelos.tenant") || "default",
  apiKey: localStorage.getItem("sentinelos.apiKey") || "",
  // Recorded on every approve/deny decision. Freely typed unless a real
  // session is active (below), in which case it's locked to the
  // authenticated username instead — a real identity is strictly better
  // attribution than a typed label.
  analystName: localStorage.getItem("sentinelos.analystName") || "",
  // A real per-user session (see utils/user_accounts.py) — optional.
  // Unset, the dashboard behaves exactly as it always did (API key +
  // freely-typed analyst name). Logging in issues a token used as the
  // Authorization bearer credential in place of the API key.
  sessionToken: localStorage.getItem("sentinelos.sessionToken") || "",
  sessionUsername: localStorage.getItem("sentinelos.sessionUsername") || "",
  sessionRole: localStorage.getItem("sentinelos.sessionRole") || "",
};

function saveSettings() {
  localStorage.setItem("sentinelos.tenant", settings.tenant);
  localStorage.setItem("sentinelos.apiKey", settings.apiKey);
  localStorage.setItem("sentinelos.analystName", settings.analystName);
  localStorage.setItem("sentinelos.sessionToken", settings.sessionToken);
  localStorage.setItem("sentinelos.sessionUsername", settings.sessionUsername);
  localStorage.setItem("sentinelos.sessionRole", settings.sessionRole);
}

function clearSession() {
  settings.sessionToken = "";
  settings.sessionUsername = "";
  settings.sessionRole = "";
  saveSettings();
}

/* ---------- HTML escaping — everything rendered here can contain
   LLM-generated or attacker-influenced text (incident descriptions,
   agent findings), so nothing goes into the DOM unescaped. ---------- */

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value === null || value === undefined ? "" : String(value);
  // The DOM's own text-node serialization (div.innerHTML above) escapes
  // & < > but NOT quote characters -- quotes have no special meaning in
  // text-node content, only inside an HTML attribute value. Every call
  // site in this file uses escapeHtml() output in both contexts (plain
  // text AND inside title="..."/class="..." attributes), so this must
  // be attribute-safe too, or a value containing a literal " breaks out
  // of the attribute and lets arbitrary attributes/handlers be injected
  // (a real, confirmed stored-XSS via incident description/assigned_to).
  return div.innerHTML.replace(/"/g, "&quot;").replace(/'/g, "&#39;");
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
  // A real session token takes priority over the static API key when
  // both happen to be set — it's the more specific, authenticated
  // credential, and login() overwrites the API key on the wire either
  // way, so this only matters if the two disagree.
  const token = settings.sessionToken || settings.apiKey;
  if (token) headers["Authorization"] = `Bearer ${token}`;
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

/* ---------- Live push updates (SSE, polling stays as a fallback) ----------
   Reuses the manual fetch-stream reader pattern from streamPost() above,
   not native EventSource, for the same reason: EventSource can't send
   an Authorization header, and this API is bearer-token protected.
   Reconnects with exponential backoff on any drop (a proxy that kills
   long-lived connections is a real, already-documented deployment risk
   -- see DEPLOYMENT.md) -- initAutoRefresh()'s polling interval keeps
   the list eventually-correct even if this never reconnects at all. */

let eventsAbortController = null;
let eventsReconnectDelay = 1000;
const EVENTS_MAX_RECONNECT_DELAY_MS = 30000;

async function connectIncidentEvents() {
  if (eventsAbortController) eventsAbortController.abort();
  const controller = new AbortController();
  eventsAbortController = controller;

  try {
    const response = await fetch(`${tenantPrefix()}/incidents/events`, {
      headers: authHeaders(),
      signal: controller.signal,
    });
    if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`);
    eventsReconnectDelay = 1000; // reset backoff once a connection actually succeeds

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
        if (!rawEvent.startsWith("data: ")) continue; // heartbeat comments -- nothing to do
        let event;
        try {
          event = JSON.parse(rawEvent.slice(6));
        } catch (err) {
          continue;
        }
        if (event.type === "incident_updated") {
          loadIncidents();
          loadStats();
          if (selectedThreadId && event.thread_id === selectedThreadId) renderIncidentDetail(selectedThreadId);
          const strandPanel = document.getElementById("tab-strand-map");
          if (strandPanel && strandPanel.classList.contains("active")) loadStrandMap();
        }
      }
    }
  } catch (err) {
    if (controller.signal.aborted) return; // deliberate disconnect (settings changed) -- no retry
    console.error("Incident event stream dropped, will reconnect", err);
  }

  if (controller.signal.aborted) return;
  setTimeout(() => {
    if (eventsAbortController === controller) connectIncidentEvents();
  }, eventsReconnectDelay);
  eventsReconnectDelay = Math.min(eventsReconnectDelay * 2, EVENTS_MAX_RECONNECT_DELAY_MS);
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
      if (btn.dataset.tab === "attack-overview") loadAttackOverview();
      if (btn.dataset.tab === "strand-map") loadStrandMap();
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
        const assignedTag = r.assigned_to
          ? `<span class="assigned-tag" title="Assigned to ${escapeHtml(r.assigned_to)}">👤 ${escapeHtml(r.assigned_to)}</span>`
          : "";
        return `
          <tr class="row-clickable ${selected} ${kbdFocus}" data-thread-id="${escapeHtml(r.thread_id)}" data-idx="${idx}">
            <td class="td-checkbox">${checkboxCell}</td>
            <td>${severityBadge(r.severity)}</td>
            <td>${statusBadge(r.status)}${pendingMark}</td>
            <td class="desc-cell" title="${escapeHtml(r.description)}">${escapeHtml(r.description)}${assignedTag}</td>
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

  // Total step count per playbook_id, computed client-side from sibling
  // actions rather than carried on each action itself -- the backend
  // only stamps each action with its own chain_step (see
  // playbooks/expander.py), not the chain's total length.
  const chainTotals = {};
  actions.forEach((a) => {
    if (a.playbook_id) chainTotals[a.playbook_id] = (chainTotals[a.playbook_id] || 0) + 1;
  });

  const cardsHtml = actions
    .map((a) => {
      const typeBadge =
        a.action_type && a.action_type !== "other"
          ? `<span class="action-type-badge">${escapeHtml(a.action_type.replace(/_/g, " "))}</span>`
          : "";
      const chainBadge = a.playbook_id
        ? `<span class="action-type-badge">playbook: ${escapeHtml(a.playbook_id)} · step ${a.chain_step}/${chainTotals[a.playbook_id]}</span>`
        : "";
      let execHtml = "";
      if (a.executed === true) {
        execHtml = `<div class="action-executed success">⚡ Executed — ${escapeHtml(a.execution_detail || "")}</div>`;
      } else if (a.executed === false) {
        execHtml = `<div class="action-executed failed">⚠ Execution failed — ${escapeHtml(a.execution_detail || "")}</div>`;
      } else if (a.playbook_id && a.execution_detail) {
        // executed === null with a real execution_detail only happens for a
        // playbook chain step skipped after an earlier step's real failure
        // (see resolve_proposed_actions) -- distinct from the ordinary
        // "not automatable" case, which never sets execution_detail at all.
        execHtml = `<div class="action-executed">○ ${escapeHtml(a.execution_detail)}</div>`;
      }
      return `
        <div class="action-card">
          <div class="action-title">${escapeHtml(a.action)} ${typeBadge}${chainBadge}</div>
          <div class="action-target">→ ${escapeHtml(a.target)}</div>
          <div class="action-rationale">${escapeHtml(a.rationale)}</div>
          ${execHtml}
        </div>`;
    })
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

function renderAssignment(threadId, assignedTo) {
  if (assignedTo) {
    return `
      <div class="assignment-row">
        <span>Assigned to <strong>${escapeHtml(assignedTo)}</strong></span>
        <button class="btn-unassign" data-thread-id="${escapeHtml(threadId)}">Unassign</button>
      </div>`;
  }
  return `
    <div class="assignment-row">
      <span class="text-dim">Unassigned</span>
      <button class="btn-assign-me" data-thread-id="${escapeHtml(threadId)}">Assign to me</button>
    </div>`;
}

function renderNotes(notes) {
  if (!notes || !notes.length) return "<p>No notes yet.</p>";
  return notes
    .map(
      (n) => `
      <div class="note-card">
        <div class="note-meta">${escapeHtml(n.author || "(unspecified)")} · ${escapeHtml(timeAgo(n.created_at))}</div>
        <div class="note-text">${escapeHtml(n.text)}</div>
      </div>`
    )
    .join("");
}

async function renderIncidentDetail(threadId) {
  const pane = document.getElementById("detail-pane");
  try {
    const [data, notes] = await Promise.all([
      apiGet(`${tenantPrefix()}/incidents/${encodeURIComponent(threadId)}`),
      apiGet(`${tenantPrefix()}/incidents/${encodeURIComponent(threadId)}/notes`).catch(() => []),
    ]);
    const incident = data.incident;
    const row = currentRows.find((r) => r.thread_id === threadId);
    const assignedTo = row ? row.assigned_to : null;
    pane.innerHTML = `
      <div class="detail-header">
        <h2>${severityBadge(incident.severity)} ${statusBadge(incident.status)}</h2>
        <span class="detail-id">${escapeHtml(incident.id)}</span>
      </div>
      <div class="detail-desc">${escapeHtml(incident.description)}</div>
      <div class="detail-section"><h3>Assignment</h3>${renderAssignment(threadId, assignedTo)}</div>
      <div class="detail-section"><h3>Affected Assets</h3><p>${incident.affected_assets.map(escapeHtml).join(", ") || "none"}</p></div>
      <div class="detail-section"><h3>Indicators of Compromise</h3><p>${incident.iocs.map(escapeHtml).join(", ") || "none"}</p></div>
      <div class="detail-section"><h3>Agent Findings</h3>${renderFindings(data.messages)}</div>
      <div class="detail-section"><h3>Threat Intelligence</h3>${renderThreatIntel(data.threat_intel)}</div>
      <div class="detail-section"><h3>ATT&amp;CK Mapping</h3>${renderAttackTechnique(data.attack_technique)}</div>
      <div class="detail-section"><h3>Proposed Actions</h3>${renderProposedActions(data.proposed_actions, threadId)}</div>
      <div class="detail-section"><h3>Token Usage</h3>${renderTokenUsage(data.token_usage)}</div>
      <div class="detail-section"><h3>Audit Log</h3>${renderAuditLog(data.audit_log)}</div>
      <div class="detail-section">
        <h3>Analyst Notes</h3>
        <div id="notes-list">${renderNotes(notes)}</div>
        <form class="note-form" data-thread-id="${escapeHtml(threadId)}">
          <textarea class="note-input" rows="2" placeholder="Add a note for other analysts…" maxlength="2000"></textarea>
          <button type="submit">Add Note</button>
        </form>
      </div>
    `;
    pane.querySelectorAll("button[data-approve]").forEach((btn) => {
      btn.addEventListener("click", () => decideAction(btn.dataset.threadId, btn.dataset.approve === "true"));
    });
    const assignBtn = pane.querySelector("button.btn-assign-me");
    if (assignBtn) {
      assignBtn.addEventListener("click", () => {
        if (!settings.analystName) {
          alert("Set your analyst name in the top bar first, so assignment means something.");
          return;
        }
        setAssignment(threadId, settings.analystName);
      });
    }
    const unassignBtn = pane.querySelector("button.btn-unassign");
    if (unassignBtn) unassignBtn.addEventListener("click", () => setAssignment(threadId, null));
    const noteForm = pane.querySelector("form.note-form");
    if (noteForm) noteForm.addEventListener("submit", submitNote);
  } catch (err) {
    pane.innerHTML = `<div class="empty-state">Failed to load incident: ${escapeHtml(err.message)}</div>`;
  }
}

/* ---------- Assignment ---------- */

async function setAssignment(threadId, assignedTo) {
  try {
    await apiPost(`${tenantPrefix()}/incidents/${encodeURIComponent(threadId)}/assign`, { assigned_to: assignedTo });
    await loadIncidents();
    await renderIncidentDetail(threadId);
  } catch (err) {
    alert(`Failed to update assignment: ${err.message}`);
  }
}

/* ---------- Notes ---------- */

async function submitNote(evt) {
  evt.preventDefault();
  const form = evt.target;
  const threadId = form.dataset.threadId;
  const textarea = form.querySelector(".note-input");
  const text = textarea.value.trim();
  if (!text) return;

  const submitBtn = form.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  try {
    await apiPost(`${tenantPrefix()}/incidents/${encodeURIComponent(threadId)}/notes`, {
      text,
      author: settings.analystName || null,
    });
    textarea.value = "";
    const notes = await apiGet(`${tenantPrefix()}/incidents/${encodeURIComponent(threadId)}/notes`);
    document.getElementById("notes-list").innerHTML = renderNotes(notes);
  } catch (err) {
    alert(`Failed to add note: ${err.message}`);
  } finally {
    submitBtn.disabled = false;
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

/* ---------- ATT&CK technique overview ---------- */

async function loadAttackOverview() {
  const body = document.getElementById("attack-overview-body");
  body.innerHTML = '<div class="empty-state">Loading…</div>';
  try {
    const data = await apiGet(`${tenantPrefix()}/incidents/attack-overview`);
    body.innerHTML = renderAttackOverview(data.tactics);
  } catch (err) {
    body.innerHTML = `<div class="live-event">Error: ${escapeHtml(err.message)}</div>`;
  }
}

function renderAttackOverview(tactics) {
  if (!tactics || !tactics.length) {
    return '<div class="empty-state">No verified ATT&amp;CK techniques cited yet for this tenant.</div>';
  }
  return tactics
    .map(
      (t) => `
      <div class="attack-tactic-group">
        <h3 class="attack-tactic-name">${escapeHtml(t.tactic)}</h3>
        <div class="attack-technique-grid">
          ${t.techniques
            .map(
              (tech) => `
            <div class="attack-technique-tile">
              <span class="attack-technique-id">${escapeHtml(tech.id)}</span>
              <span class="attack-technique-name">${escapeHtml(tech.name)}</span>
              <span class="attack-technique-count">${escapeHtml(tech.count)}</span>
            </div>`
            )
            .join("")}
        </div>
      </div>`
    )
    .join("");
}

/* ---------- Strand Map (graph-canvas view) ----------
   A hand-rolled force-directed layout, deliberately not a library --
   this project has a hard no-CDN/no-build-step constraint (see
   Design Lineage in README), so there's no D3 to reach for. Runs a
   bounded number of physics steps to let the layout settle, then stops
   animating rather than spinning every frame forever -- a dashboard
   tab left open all day shouldn't burn CPU/battery on a static graph. */

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

const STRAND_SIM = {
  repulsion: 2600,
  springLength: 70,
  springStrength: 0.02,
  centerStrength: 0.008,
  damping: 0.82,
  maxVelocity: 10,
  maxFrames: 300,
  settleThreshold: 0.4, // average per-node speed below which the layout is considered settled
};

function stepStrandSimulation(nodes, edges, width, height) {
  for (const n of nodes) {
    n.fx = 0;
    n.fy = 0;
  }

  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      const dx = a.x - b.x;
      const dy = a.y - b.y;
      let distSq = dx * dx + dy * dy;
      if (distSq < 1) distSq = 1;
      const dist = Math.sqrt(distSq);
      const force = STRAND_SIM.repulsion / distSq;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      a.fx += fx;
      a.fy += fy;
      b.fx -= fx;
      b.fy -= fy;
    }
  }

  for (const e of edges) {
    const dx = e.target.x - e.source.x;
    const dy = e.target.y - e.source.y;
    const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
    const displacement = dist - STRAND_SIM.springLength;
    const force = STRAND_SIM.springStrength * displacement;
    const fx = (dx / dist) * force;
    const fy = (dy / dist) * force;
    e.source.fx += fx;
    e.source.fy += fy;
    e.target.fx -= fx;
    e.target.fy -= fy;
  }

  const cx = width / 2;
  const cy = height / 2;
  let totalSpeed = 0;
  for (const n of nodes) {
    n.fx += (cx - n.x) * STRAND_SIM.centerStrength;
    n.fy += (cy - n.y) * STRAND_SIM.centerStrength;
    n.vx = (n.vx + n.fx) * STRAND_SIM.damping;
    n.vy = (n.vy + n.fy) * STRAND_SIM.damping;
    n.vx = Math.max(-STRAND_SIM.maxVelocity, Math.min(STRAND_SIM.maxVelocity, n.vx));
    n.vy = Math.max(-STRAND_SIM.maxVelocity, Math.min(STRAND_SIM.maxVelocity, n.vy));
    n.x += n.vx;
    n.y += n.vy;
    totalSpeed += Math.abs(n.vx) + Math.abs(n.vy);
  }
  return nodes.length ? totalSpeed / nodes.length : 0;
}

function strandNodeStyle(node) {
  if (node.type === "incident") {
    return { radius: 9, fill: cssVar(`--${node.severity}`) || cssVar("--pulse") };
  }
  if (node.type === "ioc") {
    return { radius: 5, fill: cssVar("--pulse") };
  }
  return { radius: 5, fill: cssVar("--text-faint") };
}

function renderStrandMap(ctx, canvas, dpr, view, nodes, edges) {
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.setTransform(dpr * view.scale, 0, 0, dpr * view.scale, dpr * view.offsetX, dpr * view.offsetY);

  ctx.strokeStyle = cssVar("--border-soft");
  ctx.lineWidth = 1 / view.scale;
  ctx.beginPath();
  for (const e of edges) {
    ctx.moveTo(e.source.x, e.source.y);
    ctx.lineTo(e.target.x, e.target.y);
  }
  ctx.stroke();

  const fontFamily = cssVar("--font-sans");
  const textColor = cssVar("--text");
  const pulse = cssVar("--pulse");

  for (const n of nodes) {
    const { radius, fill } = strandNodeStyle(n);
    ctx.beginPath();
    ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = fill;
    ctx.fill();
    if (n.id === strandSelectedId) {
      ctx.lineWidth = 2 / view.scale;
      ctx.strokeStyle = pulse;
      ctx.stroke();
    }
  }

  // Incident labels drawn in a second pass so no dot ever draws over a label.
  ctx.font = `11px ${fontFamily}`;
  ctx.fillStyle = textColor;
  for (const n of nodes) {
    if (n.type !== "incident") continue;
    const label = n.label.length > 30 ? `${n.label.slice(0, 30)}…` : n.label;
    ctx.fillText(label, n.x + 13, n.y + 4);
  }
}

let strandMapAnimFrame = null;
let strandMapSim = null; // { nodes, edges, byId }
let strandSelectedId = null;
const strandView = { offsetX: 0, offsetY: 0, scale: 1 };
let strandDpr = window.devicePixelRatio || 1;

function sizeStrandCanvas(canvas) {
  const rect = canvas.parentElement.getBoundingClientRect();
  strandDpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.round(rect.width * strandDpr));
  canvas.height = Math.max(1, Math.round(rect.height * strandDpr));
  return { width: rect.width, height: rect.height };
}

function drawStrandFrame(canvas) {
  if (!strandMapSim) return;
  renderStrandMap(canvas.getContext("2d"), canvas, strandDpr, strandView, strandMapSim.nodes, strandMapSim.edges);
}

function runStrandSimulation(canvas, width, height) {
  if (strandMapAnimFrame) cancelAnimationFrame(strandMapAnimFrame);
  const { nodes, edges } = strandMapSim;
  let frame = 0;

  function tick() {
    const avgSpeed = nodes.length ? stepStrandSimulation(nodes, edges, width, height) : 0;
    drawStrandFrame(canvas);
    frame++;
    if (frame < STRAND_SIM.maxFrames && avgSpeed > STRAND_SIM.settleThreshold) {
      strandMapAnimFrame = requestAnimationFrame(tick);
    } else {
      strandMapAnimFrame = null;
    }
  }
  tick();
}

/** Screen (CSS-pixel, canvas-relative) coordinates -> simulation-space
 * coordinates, inverting the pan/zoom transform applied in
 * renderStrandMap -- used for both click hit-testing and drag panning. */
function strandScreenToSim(canvas, clientX, clientY) {
  const rect = canvas.getBoundingClientRect();
  const cssX = clientX - rect.left;
  const cssY = clientY - rect.top;
  return { x: (cssX - strandView.offsetX) / strandView.scale, y: (cssY - strandView.offsetY) / strandView.scale };
}

function strandNodeAt(simX, simY) {
  if (!strandMapSim) return null;
  let closest = null;
  let closestDist = Infinity;
  for (const n of strandMapSim.nodes) {
    const { radius } = strandNodeStyle(n);
    const dx = n.x - simX;
    const dy = n.y - simY;
    const dist = Math.sqrt(dx * dx + dy * dy);
    const hitRadius = radius + 4; // a little generous, easier to click a small IOC/asset dot
    if (dist <= hitRadius && dist < closestDist) {
      closest = n;
      closestDist = dist;
    }
  }
  return closest;
}

function jumpToIncidentFromStrandMap(threadId) {
  document.querySelector('.tab-btn[data-tab="incidents"]').click();
  openIncident(threadId);
}

function showStrandSelection(node) {
  const panel = document.getElementById("strand-map-selection");
  if (!node) {
    panel.hidden = true;
    panel.innerHTML = "";
    return;
  }
  if (node.type === "incident") {
    panel.hidden = true; // clicking an incident jumps straight to its detail -- no panel needed
    return;
  }
  const connected = strandMapSim.edges
    .filter((e) => e.source.id === node.id || e.target.id === node.id)
    .map((e) => (e.source.id === node.id ? e.target : e.source))
    .filter((n) => n.type === "incident");
  panel.hidden = false;
  panel.innerHTML = `
    <div class="strand-selection-label">${node.type === "ioc" ? "IOC" : "Affected asset"}: <strong>${escapeHtml(node.label)}</strong></div>
    <div class="strand-selection-incidents">
      ${connected
        .map(
          (inc) =>
            `<button class="strand-selection-link" data-thread-id="${escapeHtml(inc.thread_id)}">${escapeHtml(inc.label)}</button>`
        )
        .join("") || "<span>No incidents reference this.</span>"}
    </div>`;
  panel.querySelectorAll(".strand-selection-link").forEach((btn) => {
    btn.addEventListener("click", () => jumpToIncidentFromStrandMap(btn.dataset.threadId));
  });
}

function handleStrandClick(canvas, clientX, clientY) {
  const { x, y } = strandScreenToSim(canvas, clientX, clientY);
  const node = strandNodeAt(x, y);
  strandSelectedId = node ? node.id : null;
  drawStrandFrame(canvas);
  if (node && node.type === "incident") {
    jumpToIncidentFromStrandMap(node.thread_id);
    return;
  }
  showStrandSelection(node);
}

function initStrandMapCanvasInteractions(canvas) {
  let dragging = false;
  let dragMoved = false;
  let dragStart = { x: 0, y: 0 };
  let viewStart = { x: 0, y: 0 };

  canvas.addEventListener("mousedown", (evt) => {
    dragging = true;
    dragMoved = false;
    dragStart = { x: evt.clientX, y: evt.clientY };
    viewStart = { x: strandView.offsetX, y: strandView.offsetY };
  });

  window.addEventListener("mousemove", (evt) => {
    if (!dragging) return;
    const dx = evt.clientX - dragStart.x;
    const dy = evt.clientY - dragStart.y;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) dragMoved = true;
    if (dragMoved) {
      strandView.offsetX = viewStart.x + dx;
      strandView.offsetY = viewStart.y + dy;
      drawStrandFrame(canvas);
    }
  });

  window.addEventListener("mouseup", (evt) => {
    if (!dragging) return;
    dragging = false;
    if (!dragMoved) handleStrandClick(canvas, evt.clientX, evt.clientY);
  });

  canvas.addEventListener(
    "wheel",
    (evt) => {
      evt.preventDefault();
      const rect = canvas.getBoundingClientRect();
      const mouseX = evt.clientX - rect.left;
      const mouseY = evt.clientY - rect.top;
      const zoomFactor = evt.deltaY < 0 ? 1.1 : 1 / 1.1;
      const newScale = Math.max(0.2, Math.min(4, strandView.scale * zoomFactor));
      strandView.offsetX = mouseX - ((mouseX - strandView.offsetX) / strandView.scale) * newScale;
      strandView.offsetY = mouseY - ((mouseY - strandView.offsetY) / strandView.scale) * newScale;
      strandView.scale = newScale;
      drawStrandFrame(canvas);
    },
    { passive: false }
  );
}

async function loadStrandMap() {
  const canvas = document.getElementById("strand-map-canvas");
  const emptyState = document.getElementById("strand-map-empty");
  const countLabel = document.getElementById("strand-map-count");

  let graph;
  try {
    graph = await apiGet(`${tenantPrefix()}/incidents/graph`);
  } catch (err) {
    countLabel.textContent = `Error: ${err.message}`;
    return;
  }

  emptyState.hidden = graph.nodes.length > 0;
  countLabel.textContent = graph.nodes.length
    ? `${graph.incidents_included} of ${graph.incidents_total} incidents shown, ${graph.nodes.length} nodes, ${graph.edges.length} links`
    : "";
  showStrandSelection(null);
  if (!graph.nodes.length) {
    strandMapSim = null;
    const ctx = canvas.getContext("2d");
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    return;
  }

  const { width, height } = sizeStrandCanvas(canvas);
  const previous = strandMapSim ? strandMapSim.byId : new Map();
  const byId = new Map();
  const nodes = graph.nodes.map((n) => {
    const prior = previous.get(n.id);
    let x, y;
    if (prior) {
      x = prior.x;
      y = prior.y;
    } else {
      const angle = Math.random() * Math.PI * 2;
      const radius = Math.random() * Math.min(width, height) * 0.3;
      x = width / 2 + Math.cos(angle) * radius;
      y = height / 2 + Math.sin(angle) * radius;
    }
    const node = { ...n, x, y, vx: prior ? prior.vx : 0, vy: prior ? prior.vy : 0 };
    byId.set(n.id, node);
    return node;
  });
  const edges = graph.edges
    .map((e) => ({ source: byId.get(e.source), target: byId.get(e.target) }))
    .filter((e) => e.source && e.target);

  strandMapSim = { nodes, edges, byId };
  runStrandSimulation(canvas, width, height);
}

function initStrandMap() {
  const canvas = document.getElementById("strand-map-canvas");
  document.getElementById("strand-map-refresh-btn").addEventListener("click", () => {
    strandView.offsetX = 0;
    strandView.offsetY = 0;
    strandView.scale = 1;
    loadStrandMap();
  });
  initStrandMapCanvasInteractions(canvas);
  window.addEventListener("resize", () => {
    const panel = document.getElementById("tab-strand-map");
    if (panel.classList.contains("active") && strandMapSim) {
      const { width, height } = sizeStrandCanvas(canvas);
      runStrandSimulation(canvas, width, height);
    }
  });
}

/* ---------- Wiring ---------- */

/* ---------- Real per-user login (optional; see utils/user_accounts.py) ---------- */

function renderLoginState() {
  const loggedIn = Boolean(settings.sessionToken);
  document.getElementById("login-form").hidden = loggedIn;
  document.getElementById("logged-in-state").hidden = !loggedIn;
  if (loggedIn) {
    document.getElementById("logged-in-label").textContent =
      `Signed in as ${settings.sessionUsername} (${settings.sessionRole})`;
  }
  const analystInput = document.getElementById("analyst-name-input");
  analystInput.readOnly = loggedIn;
  analystInput.title = loggedIn ? "Locked to your signed-in identity while logged in." : "";
}

async function doLogin() {
  const username = document.getElementById("login-username-input").value.trim();
  const password = document.getElementById("login-password-input").value;
  const errorEl = document.getElementById("login-error");
  errorEl.textContent = "";
  if (!username || !password) {
    errorEl.textContent = "Username and password are both required.";
    return;
  }
  try {
    const response = await fetch(`${tenantPrefix()}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      errorEl.textContent = body.detail || `Login failed (HTTP ${response.status}).`;
      return;
    }
    const data = await response.json();
    settings.sessionToken = data.token;
    settings.sessionUsername = data.username;
    settings.sessionRole = data.role;
    settings.analystName = data.username;
    saveSettings();
    document.getElementById("login-password-input").value = "";
    document.getElementById("analyst-name-input").value = settings.analystName;
    renderLoginState();
    loadIncidents();
    loadStats();
    checkConnection();
  } catch (exc) {
    errorEl.textContent = `Login failed: ${exc.message}`;
  }
}

async function doLogout() {
  try {
    await apiPost(`${tenantPrefix()}/auth/logout`, {});
  } catch (exc) {
    // Best-effort -- even if the network call fails, still forget the
    // token locally so the UI reflects "logged out" immediately.
  }
  clearSession();
  renderLoginState();
  checkConnection();
}

function initLoginForm() {
  renderLoginState();
  document.getElementById("login-submit-btn").addEventListener("click", doLogin);
  document.getElementById("login-password-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doLogin();
  });
  document.getElementById("logout-btn").addEventListener("click", doLogout);
}

function initSettingsForm() {
  document.getElementById("tenant-input").value = settings.tenant;
  document.getElementById("apikey-input").value = settings.apiKey;
  document.getElementById("analyst-name-input").value = settings.analystName;
  document.getElementById("apply-settings-btn").addEventListener("click", () => {
    const newTenant = document.getElementById("tenant-input").value.trim() || "default";
    // A session token is scoped to the tenant it was issued for (see
    // utils/user_accounts.py) -- switching tenants while one is active
    // would otherwise silently carry a token that can never validate
    // against the new tenant, which reads as a confusing auth failure
    // rather than the tenant switch the analyst actually asked for.
    if (newTenant !== settings.tenant && settings.sessionToken) {
      clearSession();
    }
    settings.tenant = newTenant;
    settings.apiKey = document.getElementById("apikey-input").value.trim();
    if (!settings.sessionToken) {
      settings.analystName = document.getElementById("analyst-name-input").value.trim();
    }
    saveSettings();
    renderLoginState();
    selectedThreadId = null;
    keyboardFocusIndex = -1;
    document.getElementById("detail-pane").innerHTML = '<div class="empty-state">Select an incident to view details.</div>';
    loadIncidents();
    loadStats();
    checkConnection();
    connectIncidentEvents();
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
  initLoginForm();
  initAutoRefresh();
  initFilters();
  initKeyboardShortcuts();
  initBulkActions();
  initOnboardingBanner();
  initStrandMap();
  document.getElementById("new-incident-form").addEventListener("submit", submitNewIncident);
  document.getElementById("hunt-form").addEventListener("submit", submitHunt);
  document.getElementById("ioc-lookup-form").addEventListener("submit", submitIocLookup);
  checkConnection();
  loadIncidents();
  loadStats();
  connectIncidentEvents();
});
