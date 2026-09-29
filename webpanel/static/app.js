"use strict";

const TEAM_LABEL = { red: "Red", blue: "Blue", recon: "Recon" };
const grid = document.getElementById("grid");
let CATALOG = [];

function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html != null) e.innerHTML = html;
  return e;
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

// Build one field for a param spec.
function fieldFor(tool, p) {
  const id = `${tool.id}__${p.name}`;
  if (p.type === "flag") {
    const f = el("div", "field check full");
    const cb = el("input");
    cb.type = "checkbox"; cb.id = id; cb.dataset.name = p.name;
    if (p.default) cb.checked = true;
    const lab = el("label", null, esc(p.label || p.name));
    lab.htmlFor = id;
    f.append(cb, lab);
    return f;
  }
  const f = el("div", p.type === "str" ? "field full" : "field");
  const lab = el("label", null, esc(p.label || p.name) + (p.required ? " *" : ""));
  lab.htmlFor = id;
  let input;
  if (p.type === "choice") {
    input = el("select");
    for (const c of p.choices) {
      const o = el("option", null, c);
      o.value = c;
      if (c === p.default) o.selected = true;
      input.append(o);
    }
  } else {
    input = el("input");
    input.type = "text";
    input.value = p.default != null ? p.default : "";
    input.placeholder = p.label || p.name;
  }
  input.id = id; input.dataset.name = p.name;
  f.append(lab, input);
  return f;
}

function colorize(line) {
  const t = line;
  let cls = "";
  if (/\[(ALERT|FOUND|BLOCK|HIGH|CRITICAL|REFUSED|ERROR|DENY)\]|\bSUSPICIOUS\b|Traceback/i.test(t)) cls = "hi-alert";
  else if (/\[(OPEN|SUCCESS|ALLOW|OK|✓|REPORT)\]|\bFOUND\b|Password found|AUTH_OK/i.test(t)) cls = "hi-good";
  else if (/\[(WARN|MEDIUM|STATS|SIM|KIT|SCAN|TEST)\]/i.test(t)) cls = "hi-warn";
  else if (/\[(INFO|PACKET|CRAWL|IDS|PANEL|SNIFF|MONITOR)\]|Severity|Score:/i.test(t)) cls = "hi-info";
  else if (/^\s*(-|=|#|\[)/.test(t)) cls = "hi-dim";
  return `<span class="${cls}">${esc(t)}</span>`;
}

function card(tool) {
  const c = el("div", `card ${tool.team}${tool.disabled ? " disabled" : ""}`);
  c.dataset.team = tool.team;

  const head = el("div", "card-head");
  head.append(el("h3", null, esc(tool.name)),
              el("span", `badge ${tool.team}`, TEAM_LABEL[tool.team] || tool.team));
  c.append(head);
  c.append(el("p", "desc", esc(tool.desc)));
  if (tool.warn) c.append(el("div", "warn", "&#9888; " + esc(tool.warn)));

  if (tool.disabled) return c;

  const form = el("form", "form");
  for (const p of tool.params) form.append(fieldFor(tool, p));
  c.append(form);

  const actions = el("div", "actions");
  const run = el("button", "btn run", "&#9654; Run");
  const stop = el("button", "btn stop", "&#9632; Stop");
  const status = el("span", "status", "");
  run.type = "button"; stop.type = "button";
  actions.append(run, stop, status);
  c.append(actions);

  const term = el("pre", "term");
  c.append(term);

  let es = null, runId = null;

  function setRunning(on) {
    run.disabled = on;
    stop.style.display = on ? "inline-block" : "none";
    status.innerHTML = on ? '<span class="spinner"></span> ruleaza…' : status.innerHTML;
  }

  run.addEventListener("click", async () => {
    const params = {};
    form.querySelectorAll("[data-name]").forEach(inp => {
      params[inp.dataset.name] = inp.type === "checkbox" ? inp.checked : inp.value;
    });
    term.classList.add("show");
    term.innerHTML = "";
    setRunning(true);
    let res;
    try {
      res = await fetch("/api/run", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: tool.id, params }),
      }).then(r => r.json());
    } catch (e) { res = { error: "Nu pot contacta serverul." }; }

    if (res.error) {
      term.innerHTML = `<span class="hi-alert">[EROARE] ${esc(res.error)}</span>`;
      setRunning(false); status.textContent = "";
      return;
    }
    runId = res.run_id;
    // Batched + capped rendering: avoids O(n^2) innerHTML growth and DOM bloat
    // when a tool floods thousands of lines (e.g. a full-range UDP scan).
    let lines = [`<span class="cmd">$ ${esc(res.command)}</span>`];
    const MAX_LINES = 2000;
    let pending = false;
    const flush = () => {
      pending = false;
      if (lines.length > MAX_LINES) lines = lines.slice(-MAX_LINES);
      term.innerHTML = lines.join("\n");
      term.scrollTop = term.scrollHeight;
    };
    flush();

    es = new EventSource(`/api/stream/${runId}`);
    es.onmessage = (ev) => {
      lines.push(colorize(JSON.parse(ev.data)));
      if (!pending) { pending = true; requestAnimationFrame(flush); }
    };
    es.addEventListener("end", (ev) => {
      const rc = JSON.parse(ev.data).returncode;
      const ok = rc === 0;
      lines.push(`<span class="${ok ? "hi-good" : "hi-alert"}">— gata (exit ${rc}) —</span>`);
      flush();
      es.close(); setRunning(false);
      status.innerHTML = `<span class="${ok ? "hi-good" : "hi-alert"}">exit ${rc}</span>`;
    });
    es.onerror = () => { if (es) es.close(); setRunning(false); status.textContent = ""; };
  });

  stop.addEventListener("click", () => {
    if (runId) fetch(`/api/stop/${runId}`, { method: "POST" });
    status.textContent = "oprit…";
  });

  return c;
}

function render(team) {
  grid.innerHTML = "";
  const list = team === "all" ? CATALOG : CATALOG.filter(t => t.team === team);
  for (const t of list) grid.append(card(t));
  document.getElementById("count").textContent =
    `${CATALOG.length} tool-uri · ${CATALOG.filter(t=>t.team==="red").length} red / ${CATALOG.filter(t=>t.team==="blue").length} blue / ${CATALOG.filter(t=>t.team==="recon").length} recon`;
}

document.getElementById("filters").addEventListener("click", (e) => {
  const b = e.target.closest(".f");
  if (!b) return;
  document.querySelectorAll(".f").forEach(x => x.classList.remove("active"));
  b.classList.add("active");
  render(b.dataset.team);
});

fetch("/api/catalog").then(r => r.json()).then(data => {
  CATALOG = data;
  render("all");
});
