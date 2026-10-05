const state = { rows: [], result: null, selected: null, timer: null, pollTimer: null, live: false, page: "overview", flowPage: 0 };
const $ = (id) => document.getElementById(id);
const fmt = (value) => Number(value || 0).toLocaleString();
const pageTitles = { overview: "Overview", traffic: "Traffic analysis", alerts: "Anomaly center" };

function navigateToPage() {
  const requested = window.location.hash.slice(1);
  const page = Object.hasOwn(pageTitles, requested) ? requested : "overview";
  state.page = page;
  for (const view of document.querySelectorAll("[data-page]")) {
    const active = view.dataset.page === page;
    view.hidden = !active;
    view.classList.toggle("active", active);
  }
  for (const link of document.querySelectorAll(".nav-item[data-route]")) {
    const active = link.dataset.route === page;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  $("breadcrumb-title").textContent = pageTitles[page];
  if (state.result) drawChart(state.result.results, state.result.summary.threshold);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function toast(message, isError = false) {
  const node = $("toast");
  node.textContent = message;
  node.classList.toggle("error", isError);
  node.classList.add("show");
  clearTimeout(state.timer);
  state.timer = setTimeout(() => node.classList.remove("show"), 3400);
}

async function loadDemo() {
  if (state.live) {
    toast("Stop live monitoring before switching to sample traffic.", true);
    return;
  }
  try {
    $("refresh-btn").disabled = true;
    state.flowPage = 0;
    const response = await fetch("/api/demo");
    if (!response.ok) throw new Error("Could not load sample traffic.");
    const payload = await response.json();
    state.rows = payload.rows;
    state.selected = null;
    await analyze();
    toast("Sample network traffic loaded.");
  } catch (error) {
    toast(error.message || "Unable to load sample traffic.", true);
  } finally {
    $("refresh-btn").disabled = false;
  }
}

async function analyze() {
  if (!state.rows.length) return;
  if (state.live) return pollLive();
  const payload = {
    rows: state.rows,
    threshold: Number($("threshold").value),
    ...(state.selected ? { features: state.selected } : {}),
  };
  const response = await fetch("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Traffic analysis failed.");
  state.result = data;
  render();
}

function render() {
  const { summary, features, protocols, results } = state.result;
  $("total-flows").textContent = fmt(summary.total_flows);
  $("anomaly-count").textContent = fmt(summary.anomalies);
  $("normal-count").textContent = fmt(summary.normal);
  $("source-count").textContent = fmt(summary.unique_sources);
  $("anomaly-rate").textContent = `${summary.anomaly_rate}%`;
  $("nav-alert-count").textContent = fmt(summary.anomalies);
  $("updated-label").textContent = `Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  $("table-count").textContent = `${fmt(summary.anomalies)} anomal${summary.anomalies === 1 ? "y" : "ies"} · ${fmt(summary.total_flows)} flows analyzed`;
  $("traffic-record-count").textContent = `${fmt(summary.total_flows)} flows · ${fmt(summary.anomalies)} flagged`;
  $("chart-start").textContent = `${fmt(summary.total_flows)} flows`;
  $("chart-end").textContent = `${summary.anomalies} flagged`;
  $("export-btn").disabled = summary.anomalies === 0;
  $("reanalyze-btn").disabled = false;
  renderFeatures(features);
  renderAlerts(results);
  renderOverview(state.result);
  renderFlowExplorer(results);
  renderAlertSummary(results, summary);
  drawChart(results, summary.threshold);
}

function updateCapture(status) {
  state.live = status.state === "running";
  $("capture-indicator").classList.toggle("running", state.live);
  $("capture-indicator").classList.toggle("error", status.state === "error");
  $("capture-title").textContent = state.live
    ? `Monitoring ${status.interface}`
    : status.state === "error" ? "Live capture failed" : "Live capture is off";
  $("capture-detail").textContent = status.state === "error"
    ? status.error
    : state.live
      ? `${fmt(status.packets_seen)} packets · ${fmt(status.active_flows)} active flows · payloads never stored`
      : "Monitor traffic visible to this device. Payload contents are not collected.";
  $("live-start-btn").hidden = state.live;
  $("live-stop-btn").hidden = !state.live;
  $("interface-select").disabled = state.live;
  if (state.live) scheduleLivePoll(100);
  else clearTimeout(state.pollTimer);
}

async function initializeLive() {
  const select = $("interface-select");
  try {
    const interfaceResponse = await fetch("/api/live/interfaces", {
      signal: AbortSignal.timeout(8000),
    });
    if (!interfaceResponse.ok) {
      if (interfaceResponse.status === 404) {
        throw new Error(
          "The running Strata server is outdated and does not provide interface discovery. Restart it from the current Strata project, then reload this page."
        );
      }
      throw new Error(`Interface discovery failed (HTTP ${interfaceResponse.status}).`);
    }
    const { interfaces } = await interfaceResponse.json();
    select.replaceChildren();
    for (const item of interfaces) {
      const option = document.createElement("option");
      option.value = item.name;
      option.textContent = item.label;
      select.append(option);
    }
    if (!interfaces.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No active interfaces";
      select.append(option);
    }
    $("live-start-btn").disabled = !interfaces.length;
  } catch (error) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Interface discovery failed";
    select.replaceChildren(option);
    select.disabled = true;
    $("live-start-btn").disabled = true;
    $("capture-title").textContent = "Interface discovery unavailable";
    $("capture-detail").textContent = error.name === "TimeoutError"
      ? "Interface discovery timed out. Confirm the Strata server is responding, then reload."
      : error.message || "Could not discover interfaces.";
    return;
  }

  try {
    const statusResponse = await fetch("/api/live/status", {
      signal: AbortSignal.timeout(8000),
    });
    if (!statusResponse.ok) {
      throw new Error(`Capture status failed (HTTP ${statusResponse.status}).`);
    }
    updateCapture(await statusResponse.json());
  } catch (error) {
    $("capture-title").textContent = "Capture status unavailable";
    $("capture-detail").textContent = error.name === "TimeoutError"
      ? "Capture status request timed out. Reload the dashboard after checking the Strata server."
      : error.message || "Could not retrieve capture status.";
  }
}

function scheduleLivePoll(delay = 2000) {
  clearTimeout(state.pollTimer);
  if (state.live) state.pollTimer = setTimeout(pollLive, delay);
}

async function pollLive() {
  try {
    const response = await fetch("/api/live/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        threshold: Number($("threshold").value),
        ...(state.selected ? { features: state.selected } : {}),
      }),
    });
    const result = await response.json();
    if (!response.ok) {
      if (result.error && result.error.includes("Selected features")) state.selected = null;
      else throw new Error(result.error || "Live analysis failed.");
    } else {
      state.result = result;
      state.rows = result.results.map((item) => item.record);
      updateCapture(result.capture);
      render();
    }
  } catch (error) {
    toast(error.message || "Live traffic update failed.", true);
    scheduleLivePoll(5000);
  }
}

async function toggleCapture(start) {
  const button = start ? $("live-start-btn") : $("live-stop-btn");
  button.disabled = true;
  try {
    const response = await fetch(start ? "/api/live/start" : "/api/live/stop", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(start ? { interface: $("interface-select").value } : {}),
    });
    const status = await response.json();
    if (!response.ok) throw new Error(status.error || "Could not change capture state.");
    updateCapture(status);
    if (start) {
      state.rows = [];
      state.result = null;
      state.selected = null;
      state.flowPage = 0;
      toast(`Live capture started on ${status.interface}.`);
    } else {
      toast("Live capture stopped.");
    }
  } catch (error) {
    toast(error.message || "Could not change capture state.", true);
  } finally {
    button.disabled = false;
  }
}

function renderFeatures(features) {
  const wrap = $("feature-list");
  wrap.replaceChildren();
  if (!features.length) {
    const empty = document.createElement("span");
    empty.className = "empty-features";
    empty.textContent = "No numeric fields available for outlier detection.";
    wrap.append(empty);
    return;
  }
  if (!state.selected) state.selected = [...features];
  for (const feature of features) {
    const label = document.createElement("label");
    label.className = "feature-chip";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = state.selected.includes(feature);
    checkbox.value = feature;
    checkbox.addEventListener("change", () => {
      state.selected = [...wrap.querySelectorAll("input:checked")].map((input) => input.value);
    });
    label.append(checkbox, document.createTextNode(feature));
    wrap.append(label);
  }
}

function fieldValue(record, keys) {
  const normalized = new Map(Object.entries(record).map(([key, value]) => [
    key.toLowerCase().replaceAll(/[^a-z0-9]/g, ""),
    value,
  ]));
  for (const key of keys) {
    const value = normalized.get(key.toLowerCase().replaceAll(/[^a-z0-9]/g, ""));
    if (value !== undefined && value !== "") return value;
  }
  return "—";
}

function renderOverview(result) {
  const protocolWrap = $("protocol-breakdown");
  const riskWrap = $("risk-highlight");
  protocolWrap.replaceChildren();
  riskWrap.replaceChildren();

  if (!result || !result.summary.total_flows) {
    const emptyProtocols = document.createElement("span");
    emptyProtocols.className = "overview-empty";
    emptyProtocols.textContent = "Load or capture traffic to see protocol composition.";
    protocolWrap.append(emptyProtocols);
    const emptyRisk = document.createElement("span");
    emptyRisk.className = "overview-empty";
    emptyRisk.textContent = "No scored flows yet.";
    riskWrap.append(emptyRisk);
    return;
  }

  const protocols = Object.entries(result.protocols)
    .sort((left, right) => right[1] - left[1]);
  if (!protocols.length) protocols.push(["Unspecified", result.summary.total_flows]);
  const maxProtocolCount = Math.max(...protocols.map(([, count]) => count));
  for (const [name, count] of protocols.slice(0, 5)) {
    const row = document.createElement("div");
    row.className = "protocol-row";
    const label = document.createElement("div");
    label.className = "protocol-row-label";
    const protocolName = document.createElement("strong");
    protocolName.textContent = name.toUpperCase();
    const protocolCount = document.createElement("span");
    protocolCount.textContent = `${fmt(count)} · ${Math.round(count / result.summary.total_flows * 100)}%`;
    label.append(protocolName, protocolCount);
    const track = document.createElement("div");
    track.className = "protocol-track";
    const fill = document.createElement("i");
    fill.style.width = `${count / maxProtocolCount * 100}%`;
    track.append(fill);
    row.append(label, track);
    protocolWrap.append(row);
  }

  const highest = [...result.results].sort((left, right) => right.score - left.score)[0];
  if (!highest) return;
  const [source, destination] = endpoint(highest.record);
  const score = document.createElement("div");
  score.className = "risk-score";
  score.textContent = String(highest.score);
  const details = document.createElement("div");
  details.className = "risk-details";
  const severity = document.createElement("span");
  severity.className = `severity ${highest.severity}`;
  severity.textContent = highest.severity;
  const route = document.createElement("strong");
  route.textContent = `${source} → ${destination}`;
  const explanation = document.createElement("span");
  explanation.textContent = highest.reasons.join(" · ") || "No anomaly indicators for this flow.";
  details.append(severity, route, explanation);
  riskWrap.append(score, details);
}

function renderFlowExplorer(results) {
  const tbody = $("flows-body");
  tbody.replaceChildren();
  $("flow-explorer-count").textContent = `${fmt(results.length)} flows`;
  const pageSize = 50;
  const pageCount = Math.ceil(results.length / pageSize);
  state.flowPage = Math.min(state.flowPage, Math.max(pageCount - 1, 0));
  const start = state.flowPage * pageSize;
  const visible = [...results]
    .sort((left, right) => right.score - left.score)
    .slice(start, start + pageSize);
  $("flow-table-count").textContent = results.length
    ? `Showing ${fmt(start + 1)}–${fmt(Math.min(start + pageSize, results.length))} of ${fmt(results.length)} flows`
    : "No analyzed records";
  $("flow-page-label").textContent = `Page ${pageCount ? state.flowPage + 1 : 0} of ${pageCount}`;
  $("flow-prev").disabled = state.flowPage === 0;
  $("flow-next").disabled = !pageCount || state.flowPage >= pageCount - 1;
  if (!results.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = document.createElement("td");
    cell.colSpan = 7;
    const heading = document.createElement("strong");
    heading.textContent = "No flows to inspect";
    const message = document.createElement("span");
    message.textContent = "Load sample traffic, import a CSV, or start live monitoring.";
    cell.append(heading, message);
    row.append(cell);
    tbody.append(row);
    return;
  }

  for (const item of visible) {
    const row = document.createElement("tr");
    const [source, destination] = endpoint(item.record);
    const protocol = fieldValue(item.record, ["protocol", "proto"]);
    const packets = fieldValue(item.record, ["total_packets", "packets", "packet_count", "total_fwd_packets"]);
    const bytes = fieldValue(item.record, ["total_bytes", "bytes", "byte_count"]);
    const values = [
      item.record.flow_id || `FL-${String(item.id).padStart(4, "0")}`,
      `${source} → ${destination}`,
      String(protocol).toUpperCase(),
      packets,
      bytes,
      String(item.score),
    ];
    for (const [index, value] of values.entries()) {
      const cell = document.createElement("td");
      cell.textContent = String(value);
      if (index === 0) cell.className = "flow-id";
      if (index === 1) cell.className = "endpoint";
      if (index === 2) {
        const badge = document.createElement("span");
        badge.className = "protocol-badge";
        badge.textContent = String(value);
        cell.replaceChildren(badge);
      }
      if (index === 5) {
        cell.className = "score-cell";
        const meter = document.createElement("span");
        meter.className = "score-track";
        const fill = document.createElement("i");
        fill.style.width = `${item.score}%`;
        meter.append(fill);
        cell.append(meter);
      }
      row.append(cell);
    }
    const statusCell = document.createElement("td");
    const status = document.createElement("span");
    status.className = item.status === "anomaly" ? `severity ${item.severity}` : "flow-status normal";
    status.textContent = item.status === "anomaly" ? item.severity : "baseline";
    statusCell.append(status);
    row.append(statusCell);
    tbody.append(row);
  }
}

function renderAlertSummary(results, summary) {
  const severities = { critical: 0, high: 0, medium: 0 };
  for (const item of results) {
    if (item.status === "anomaly" && Object.hasOwn(severities, item.severity)) {
      severities[item.severity]++;
    }
  }
  $("critical-count").textContent = fmt(severities.critical);
  $("high-count").textContent = fmt(severities.high);
  $("medium-count").textContent = fmt(severities.medium);
  $("baseline-count").textContent = fmt(summary.normal);
  $("alert-summary").textContent = `${fmt(summary.anomalies)} findings · ${fmt(summary.total_flows)} flows reviewed`;
  $("alerts-export-btn").disabled = summary.anomalies === 0;
}

function endpoint(record, fields) {
  const src = record.src_ip || record.source_ip || record.srcip || record.src || "—";
  const dst = record.dst_ip || record.destination_ip || record.dstip || record.dst || "—";
  const srcPort = record.src_port || record.source_port || "";
  const dstPort = record.dst_port || record.destination_port || record.dest_port || "";
  const source = srcPort ? `${src}:${srcPort}` : src;
  const destination = dstPort ? `${dst}:${dstPort}` : dst;
  return [source, destination];
}

function renderAlerts(results) {
  const tbody = $("alerts-body");
  tbody.replaceChildren();
  const search = $("search-input").value.trim().toLowerCase();
  const severity = $("severity-filter").value;
  const filtered = results.filter((item) => {
    if (item.status !== "anomaly" || (severity !== "all" && item.severity !== severity)) return false;
    const text = JSON.stringify(item.record).toLowerCase();
    return !search || text.includes(search) || item.reasons.join(" ").toLowerCase().includes(search);
  });
  if (!filtered.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = document.createElement("td");
    cell.colSpan = 6;
    const heading = document.createElement("strong");
    heading.textContent = results.some((item) => item.status === "anomaly") ? "No matching anomalies" : "No anomalies detected";
    const copy = document.createElement("span");
    copy.textContent = results.some((item) => item.status === "anomaly") ? "Try changing your search or severity filter." : "All analyzed flows are within the selected threshold.";
    cell.append(heading, copy);
    row.append(cell);
    tbody.append(row);
    return;
  }
  for (const item of filtered.slice(0, 100)) {
    const row = document.createElement("tr");
    const [source, destination] = endpoint(item.record);
    const protocol = item.record.protocol || item.record.proto || "—";
    const reason = item.reasons.join(" · ") || "Statistical deviation";
    const cells = [
      ["flow-id", item.record.flow_id || `FL-${String(item.id).padStart(4, "0")}`],
      ["endpoint", ""],
      ["protocol", String(protocol).toUpperCase()],
      ["reason-cell", reason],
      ["score-cell", `${item.score}`],
      ["severity-cell", item.severity],
    ];
    for (let index = 0; index < cells.length; index++) {
      const [className, text] = cells[index];
      const cell = document.createElement("td");
      if (index === 1) {
        cell.className = className;
        const left = document.createTextNode(source);
        const arrow = document.createElement("span");
        arrow.textContent = "→";
        const right = document.createTextNode(destination);
        cell.append(left, arrow, right);
      } else if (index === 2) {
        const badge = document.createElement("span");
        badge.className = "protocol-badge";
        badge.textContent = text;
        cell.append(badge);
      } else if (index === 4) {
        const score = document.createElement("span");
        score.className = "score-value";
        score.textContent = text;
        const track = document.createElement("span");
        track.className = "score-track";
        const fill = document.createElement("i");
        fill.className = `score-fill score-${Math.ceil(item.score / 10) * 10}`;
        track.append(fill);
        cell.append(score, track);
      } else if (index === 5) {
        const badge = document.createElement("span");
        badge.className = `severity ${item.severity}`;
        badge.textContent = text;
        cell.append(badge);
      } else {
        cell.className = className;
        cell.textContent = text;
      }
      row.append(cell);
    }
    tbody.append(row);
  }
}

function drawChart(results, threshold) {
  const canvas = $("traffic-chart");
  const bounds = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.round(bounds.width * ratio));
  canvas.height = Math.max(1, Math.round(bounds.height * ratio));
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  const width = bounds.width;
  const height = bounds.height;
  const left = 2;
  const right = width - 4;
  const top = 4;
  const bottom = height - 5;
  for (let line = 0; line <= 4; line++) {
    const y = top + (bottom - top) * line / 4;
    ctx.beginPath();
    ctx.strokeStyle = "#dcebdd";
    ctx.lineWidth = 1;
    ctx.setLineDash([]);
    ctx.moveTo(left, y);
    ctx.lineTo(right, y);
    ctx.stroke();
  }
  const thresholdY = bottom - (bottom - top) * threshold / 100;
  ctx.beginPath();
  ctx.strokeStyle = "#8da957";
  ctx.setLineDash([4, 4]);
  ctx.moveTo(left, thresholdY);
  ctx.lineTo(right, thresholdY);
  ctx.stroke();
  ctx.setLineDash([]);
  if (!results.length) return;
  const step = (right - left) / Math.max(results.length - 1, 1);
  const points = results.map((item, index) => ({
    x: left + step * index,
    y: bottom - (bottom - top) * item.score / 100,
    flagged: item.status === "anomaly",
  }));
  ctx.beginPath();
  points.forEach((point, index) => index ? ctx.lineTo(point.x, point.y) : ctx.moveTo(point.x, point.y));
  ctx.lineTo(right, bottom);
  ctx.lineTo(left, bottom);
  ctx.closePath();
  const gradient = ctx.createLinearGradient(0, top, 0, bottom);
  gradient.addColorStop(0, "rgba(22, 131, 72, .24)");
  gradient.addColorStop(1, "rgba(22, 131, 72, 0)");
  ctx.fillStyle = gradient;
  ctx.fill();
  ctx.beginPath();
  points.forEach((point, index) => index ? ctx.lineTo(point.x, point.y) : ctx.moveTo(point.x, point.y));
  ctx.strokeStyle = "#168348";
  ctx.lineWidth = 2.25;
  ctx.stroke();
  for (const point of points) {
    if (!point.flagged) continue;
    ctx.beginPath();
    ctx.arc(point.x, point.y, 3, 0, Math.PI * 2);
    ctx.fillStyle = "#b9584c";
    ctx.fill();
    ctx.strokeStyle = "#ffffff";
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }
}

async function importCsv(file) {
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) {
    toast("CSV must be smaller than 5 MB.", true);
    return;
  }
  try {
    const csv = await file.text();
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ csv, threshold: Number($("threshold").value) }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Could not analyze this CSV.");
    state.rows = result.results.map((item) => item.record);
    state.selected = result.features;
    state.result = result;
    state.flowPage = 0;
    render();
    toast(`Analyzed ${fmt(result.summary.total_flows)} traffic records.`);
  } catch (error) {
    toast(error.message || "Could not read this CSV file.", true);
  }
}

function exportAlerts() {
  if (!state.result) return;
  const rows = state.result.results.filter((item) => item.status === "anomaly");
  if (!rows.length) return;
  const headers = ["flow_id", "score", "severity", "reasons", ...Object.keys(rows[0].record)];
  const quote = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const csv = [headers.map(quote).join(","), ...rows.map((item) => [
    `FL-${String(item.id).padStart(4, "0")}`, item.score, item.severity, item.reasons.join("; "),
    ...headers.slice(4).map((key) => item.record[key] ?? ""),
  ].map(quote).join(","))].join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "strata-anomalies.csv";
  link.click();
  URL.revokeObjectURL(url);
}

$("upload-trigger").addEventListener("click", () => $("file-input").click());
$("traffic-upload-trigger").addEventListener("click", () => $("file-input").click());
$("file-input").addEventListener("change", (event) => importCsv(event.target.files[0]));
$("refresh-btn").addEventListener("click", loadDemo);
$("empty-demo-btn").addEventListener("click", loadDemo);
$("live-start-btn").addEventListener("click", () => toggleCapture(true));
$("live-stop-btn").addEventListener("click", () => toggleCapture(false));
$("threshold").addEventListener("input", (event) => {
  $("threshold-value").textContent = event.target.value;
});
$("threshold").addEventListener("change", () => {
  if (state.rows.length) analyze().catch((error) => toast(error.message, true));
});
$("reanalyze-btn").addEventListener("click", () => analyze().catch((error) => toast(error.message, true)));
$("feature-reset").addEventListener("click", () => {
  if (state.result) {
    state.selected = [...state.result.features];
    renderFeatures(state.result.features);
  }
});
$("search-input").addEventListener("input", () => state.result && renderAlerts(state.result.results));
$("severity-filter").addEventListener("change", () => state.result && renderAlerts(state.result.results));
$("export-btn").addEventListener("click", exportAlerts);
$("alerts-export-btn").addEventListener("click", exportAlerts);
$("flow-prev").addEventListener("click", () => {
  if (state.flowPage > 0 && state.result) {
    state.flowPage--;
    renderFlowExplorer(state.result.results);
  }
});
$("flow-next").addEventListener("click", () => {
  if (state.result && state.flowPage < Math.ceil(state.result.results.length / 50) - 1) {
    state.flowPage++;
    renderFlowExplorer(state.result.results);
  }
});
for (const link of document.querySelectorAll(".nav-item[data-route]")) {
  link.addEventListener("click", () => {
    if (link.dataset.route === state.page) navigateToPage();
  });
}
window.addEventListener("hashchange", navigateToPage);
window.addEventListener("resize", () => state.result && drawChart(state.result.results, state.result.summary.threshold));

if (!window.location.hash) window.history.replaceState(null, "", "#overview");
navigateToPage();
initializeLive();
