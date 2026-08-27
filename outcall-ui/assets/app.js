const REFRESH_INTERVAL_MS = 5000;
let token = "";
let refreshPromise = null;
let refreshIntervalId = null;

const endpoints = {
  bridge: "/api/v1/bridge",
  dns: "/api/v1/dns",
  proxy: "/api/v1/proxy",
  networks: "/api/v1/networks",
  containers: "/api/v1/containers",
  grants: "/api/v1/rules/active",
  rules: "/api/v1/rules",
  requests: "/api/v1/requests/rules",
  cache: "/api/v1/dns/cache?entries=true",
};

function byId(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const element = byId(id);
  if (element) element.textContent = value == null ? "--" : String(value);
}

function plural(count, singular, pluralForm = `${singular}s`) {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

function status(text, tone = "neutral") {
  const element = document.createElement("span");
  element.className = `status status-${tone}`;
  element.textContent = text;
  return element;
}

function textCell(value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value == null || value === "" ? "--" : String(value);
  if (className) cell.className = className;
  return cell;
}

function codeCell(value, title = "") {
  const cell = document.createElement("td");
  const code = document.createElement("code");
  code.className = "truncate";
  code.textContent = value == null || value === "" ? "--" : String(value);
  code.title = title || code.textContent;
  cell.appendChild(code);
  return cell;
}

function statusCell(value, tone) {
  const cell = document.createElement("td");
  cell.appendChild(status(value, tone));
  return cell;
}

function setTableMessage(bodyId, columns, message, isError = false) {
  const body = byId(bodyId);
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = columns;
  cell.className = `table-message${isError ? " error" : ""}`;
  cell.textContent = message;
  row.appendChild(cell);
  body.replaceChildren(row);
}

function replaceRows(bodyId, rows, columns, emptyMessage) {
  const body = byId(bodyId);
  if (!rows.length) {
    setTableMessage(bodyId, columns, emptyMessage);
    return;
  }
  body.replaceChildren(...rows);
}

function formatTime(value) {
  if (!value) return "--";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json" };
  if (token) headers["X-Outcall-Token"] = token;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    cache: "no-store",
    method: options.method || "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok || !payload || !payload.success) {
    throw new Error(payload?.error || `HTTP ${response.status}`);
  }
  return payload.data;
}

function renderBridge(bridge) {
  setText("bridge-value", bridge.up ? "Up" : "Down");
  setText("bridge-detail", `${bridge.name} / nftables ${bridge.nftables_active ? "active" : "inactive"}`);
}

function renderDns(dns) {
  setText("dns-value", dns.running ? "Active" : "Inactive");
  setText("dns-detail", dns.running ? `${dns.queries_total} queries / ${dns.queries_blocked} blocked` : "Resolver stopped");
}

function renderProxy(proxy) {
  setText("proxy-value", proxy.running ? "Active" : "Inactive");
  setText("proxy-detail", proxy.running ? `${proxy.active_connections} open / ${proxy.total_blocked} blocked` : "Proxy stopped");
}

function renderNetworks(networks) {
  setText("network-count", networks.length);
  setText("network-detail", plural(networks.reduce((total, network) => total + (network.containers?.length || 0), 0), "attachment"));
  setText("networks-meta", plural(networks.length, "network"));
  const rows = networks.map((network) => {
    const row = document.createElement("tr");
    row.append(
      codeCell(network.name),
      codeCell(network.subnet),
      codeCell(network.gateway),
      textCell(network.containers?.length || 0),
      codeCell(network.network_id),
    );
    return row;
  });
  replaceRows("networks-body", rows, 5, "No managed networks");
}

function renderContainers(containers, grants, networks) {
  const running = containers.filter((container) => container.state === "running").length;
  setText("container-count", containers.length);
  setText("container-detail", `${running} running`);
  setText("containers-meta", plural(containers.length, "container"));
  const rows = containers.map((container) => {
    const grantCount = grants.filter((grant) => grant.container === container.name).length;
    const network = networks.find((candidate) => candidate.name === container.network);
    const attachment = network?.containers?.find((candidate) => candidate.name === container.name);
    const row = document.createElement("tr");
    row.append(
      codeCell(container.name),
      statusCell(container.state, container.state === "running" ? "good" : "neutral"),
      codeCell(container.image),
      codeCell(container.network),
      codeCell(attachment?.ipv4_address),
      textCell(grantCount),
      textCell(formatTime(container.created_at)),
    );
    return row;
  });
  replaceRows("containers-body", rows, 7, "No managed agent containers");
}

function renderGrants(grants) {
  setText("grant-count", grants.length);
  const expiring = grants.filter((grant) => grant.expires_in_secs != null).length;
  setText("grant-detail", expiring ? `${expiring} expiring` : "Persistent only");
  setText("grants-meta", plural(grants.length, "grant"));
  const rows = grants.map((grant) => {
    const protocol = [grant.protocol, grant.port].filter((value) => value != null).join("/") || "any";
    const expiry = grant.expires_in_secs == null ? "Persistent" : `${grant.expires_in_secs}s`;
    const row = document.createElement("tr");
    row.append(
      codeCell(grant.container),
      codeCell(grant.src_ip),
      codeCell(grant.destination),
      codeCell(protocol),
      textCell(formatTime(grant.inserted_at)),
      textCell(expiry),
      codeCell(grant.nft_handle),
    );
    return row;
  });
  replaceRows("grants-body", rows, 7, "No active dynamic grants");
}

function renderRules(rules) {
  setText("rules-meta", plural(rules.length, "rule"));
  const rows = rules.map((rule) => {
    const row = document.createElement("tr");
    row.append(codeCell(rule.id));
    row.appendChild(statusCell(rule.action, rule.action === "allow" ? "good" : rule.action === "block" ? "bad" : "warning"));
    row.append(codeCell(rule.file), codeCell(rule.description || rule.condition_preview));
    return row;
  });
  replaceRows("rules-body", rows, 4, "No static rules loaded; default deny is active");
}

function requestRuleCell(ruleFile) {
  const cell = document.createElement("td");
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  const contents = document.createElement("pre");
  summary.textContent = "Review YAML";
  contents.textContent = ruleFile;
  details.append(summary, contents);
  cell.appendChild(details);
  return cell;
}

function requestActions(request) {
  const cell = document.createElement("td");
  const actions = document.createElement("div");
  actions.className = "actions";
  const approve = document.createElement("button");
  approve.type = "button";
  approve.className = "button button-approve";
  approve.dataset.requestId = request.id;
  approve.dataset.requestAction = "approve";
  approve.textContent = "Approve";
  const reject = document.createElement("button");
  reject.type = "button";
  reject.className = "button button-reject";
  reject.dataset.requestId = request.id;
  reject.dataset.requestAction = "reject";
  reject.textContent = "Reject";
  actions.append(approve, reject);
  cell.appendChild(actions);
  return cell;
}

function renderRequests(requests) {
  setText("requests-meta", plural(requests.length, "pending request"));
  const rows = requests.map((request) => {
    const row = document.createElement("tr");
    row.append(codeCell(request.id), codeCell(request.container_id), requestRuleCell(request.rule_file), requestActions(request));
    return row;
  });
  replaceRows("requests-body", rows, 4, "No pending rule requests");
}

function renderCache(cache) {
  const entries = cache.entries || [];
  const stats = cache.stats || {};
  setText("cache-meta", `${stats.entries || 0} / ${stats.max_entries || 0} entries`);
  const rows = entries.map((entry) => {
    const row = document.createElement("tr");
    row.append(codeCell(entry.hostname), codeCell(entry.record_type), textCell(`${entry.ttl_remaining_secs}s`));
    return row;
  });
  replaceRows("cache-body", rows, 3, "DNS cache is empty");
}

function renderError(key, error) {
  const tables = {
    networks: ["networks-body", 5],
    containers: ["containers-body", 7],
    grants: ["grants-body", 7],
    rules: ["rules-body", 4],
    requests: ["requests-body", 4],
    cache: ["cache-body", 3],
  };
  if (tables[key]) setTableMessage(tables[key][0], tables[key][1], `Unavailable: ${error.message}`, true);
  if (key === "bridge") setText("bridge-detail", `Unavailable: ${error.message}`);
  if (key === "dns") setText("dns-detail", `Unavailable: ${error.message}`);
  if (key === "proxy") setText("proxy-detail", `Unavailable: ${error.message}`);
}

async function loadDashboard() {
  const keys = Object.keys(endpoints);
  const results = await Promise.allSettled(keys.map((key) => api(endpoints[key])));
  const data = {};
  const errors = [];

  results.forEach((result, index) => {
    const key = keys[index];
    if (result.status === "fulfilled") data[key] = result.value;
    else {
      errors.push(key);
      renderError(key, result.reason);
    }
  });

  if (data.bridge) renderBridge(data.bridge);
  if (data.dns) renderDns(data.dns);
  if (data.proxy) renderProxy(data.proxy);
  if (data.networks) renderNetworks(data.networks);
  if (data.grants) renderGrants(data.grants);
  if (data.containers) renderContainers(data.containers, data.grants || [], data.networks || []);
  if (data.rules) renderRules(data.rules);
  if (data.requests) renderRequests(data.requests);
  if (data.cache) renderCache(data.cache);

  const alert = byId("page-alert");
  alert.hidden = errors.length === 0;
  alert.textContent = errors.length ? `Some daemon data is unavailable: ${errors.join(", ")}.` : "";
  const overall = byId("overall-status");
  const nextOverall = status(errors.length ? "Degraded" : "Connected", errors.length ? "warning" : "good");
  nextOverall.id = "overall-status";
  overall.replaceWith(nextOverall);
  setText("last-refresh", `Updated ${new Date().toLocaleTimeString()}`);
}

function refresh() {
  if (!refreshPromise) {
    refreshPromise = loadDashboard().finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
}

async function refreshAfterMutation() {
  if (refreshPromise) await refreshPromise;
  await refresh();
}

async function reviewRequest(button) {
  const id = button.dataset.requestId;
  const action = button.dataset.requestAction;
  let body;
  if (action === "approve") {
    if (!window.confirm(`Approve rule request ${id}? This changes active egress policy.`)) return;
  } else {
    const reason = window.prompt("Optional rejection reason", "");
    if (reason === null) return;
    body = reason.trim() ? { reason: reason.trim() } : {};
  }

  document.querySelectorAll("[data-request-action]").forEach((element) => { element.disabled = true; });
  try {
    await api(`/api/v1/requests/rules/${encodeURIComponent(id)}/${action}`, {
      method: "POST",
      ...(body === undefined ? {} : { body }),
    });
    await refreshAfterMutation();
  } catch (error) {
    const alert = byId("page-alert");
    alert.hidden = false;
    alert.textContent = `Could not ${action} ${id}: ${error.message}`;
  } finally {
    document.querySelectorAll("[data-request-action]").forEach((element) => { element.disabled = false; });
  }
}

document.addEventListener("click", (event) => {
  if (!(event.target instanceof Element)) return;
  const button = event.target.closest("[data-request-action]");
  if (button) reviewRequest(button);
});

function showMissingToken() {
  const alert = byId("page-alert");
  alert.hidden = false;
  alert.textContent = "Dashboard session token is missing. Start a new session with outcall ui.";
  const overall = byId("overall-status");
  const missingToken = status("Session required", "bad");
  missingToken.id = "overall-status";
  overall.replaceWith(missingToken);
  setText("last-refresh", "Start with outcall ui");
}

function showConnecting() {
  const alert = byId("page-alert");
  alert.hidden = true;
  alert.textContent = "";
  const overall = byId("overall-status");
  const connecting = status("Connecting");
  connecting.id = "overall-status";
  overall.replaceWith(connecting);
  setText("last-refresh", "Waiting for daemon");
}

function activateTokenFromHash() {
  const nextToken = new URLSearchParams(window.location.hash.slice(1)).get("token") || "";
  if (window.location.hash) {
    history.replaceState(null, "", window.location.pathname + window.location.search);
  }

  if (!nextToken) {
    if (!token) showMissingToken();
    return;
  }

  token = nextToken;
  showConnecting();
  if (refreshIntervalId === null) {
    refreshIntervalId = window.setInterval(refresh, REFRESH_INTERVAL_MS);
  }
  void refreshAfterMutation();
}

window.addEventListener("hashchange", activateTokenFromHash);
activateTokenFromHash();
