"use strict";

/* CerberusAuth dashboard: a thin shell over the admin API. No framework,
   no build step, no external requests. State lives in the API; this file
   only renders it. */

const $view = document.getElementById("view");
const $sidebar = document.getElementById("sidebar");
const $toast = document.getElementById("toast");

/* ---------- session ---------- */

function token() { return sessionStorage.getItem("token") || ""; }
function setToken(t, expiresAt) {
  sessionStorage.setItem("token", t);
  sessionStorage.setItem("token_expires", expiresAt);
}
function clearToken() {
  sessionStorage.removeItem("token");
  sessionStorage.removeItem("token_expires");
}

document.getElementById("logout").addEventListener("click", async () => {
  try { await api("DELETE", "/v1/admin/token"); } catch { /* revoked or already gone, either is fine */ }
  clearToken();
  location.hash = "#/login";
});

/* ---------- api ---------- */

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (token()) opts.headers["Authorization"] = "Bearer " + token();
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401) {
    clearToken();
    location.hash = "#/login";
    throw new Error("session expired, log in again");
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

/* ---------- tiny dom helpers ---------- */

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) n.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined) continue;
    n.append(c.nodeType ? c : document.createTextNode(c));
  }
  return n;
}

function show(node) { $view.replaceChildren(node); }

function toast(msg) {
  $toast.textContent = msg;
  $toast.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { $toast.hidden = true; }, 2600);
}

async function copy(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast((label || "Copied") + " to clipboard");
  } catch {
    toast("Clipboard unavailable; copy manually");
  }
}

/* Icon markup is static and local; innerHTML never sees user data. */
const ICONS = {
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>',
  shield: '<svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><path d="M12 2.5l8 3.6v5.6c0 4.8-3.3 8.1-8 9.8-4.7-1.7-8-5-8-9.8V6.1z"/><circle cx="8.3" cy="10.4" r="1.15" fill="currentColor" stroke="none"/><circle cx="12" cy="10.4" r="1.15" fill="currentColor" stroke="none"/><circle cx="15.7" cy="10.4" r="1.15" fill="currentColor" stroke="none"/><path d="M9 14.6c.9.7 1.9 1 3 1s2.1-.3 3-1" stroke-linecap="round"/></svg>',
};

function iconBtn(name, title, fn) {
  const b = el("button", { class: "btn icon", title, onclick: fn });
  b.innerHTML = ICONS[name];
  return b;
}

function fmtDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

function fmtExpiry(lic) {
  if (lic.status === "issued" && lic.duration_seconds) {
    return Math.round(lic.duration_seconds / 86400) + "d after redeem";
  }
  if (!lic.expires_at) return "perpetual";
  const d = new Date(lic.expires_at);
  return (d < new Date() ? "expired " : "") + fmtDate(lic.expires_at);
}

function statusPill(lic) {
  let cls = lic.status;
  if (lic.status === "active" && lic.expires_at && new Date(lic.expires_at) < new Date()) cls = "expired";
  return el("span", { class: "pill " + cls }, cls);
}

function pageHead(title, sub, ...actions) {
  return el("div", { class: "page-head" },
    el("div", {}, el("h1", {}, title), sub ? el("p", { class: "sub" }, sub) : null),
    actions.length ? el("div", { class: "row" }, actions) : null,
  );
}

function panel(title, body, headExtra) {
  return el("div", { class: "panel" },
    el("div", { class: "panel-head" }, el("h2", {}, title), headExtra || null),
    body,
  );
}

/* ---------- router ---------- */

const routes = [
  { re: /^#\/login$/, fn: viewLogin, pub: true },
  { re: /^#\/overview$/, fn: viewOverview, nav: "overview" },
  { re: /^#\/apps$/, fn: viewApps, nav: "apps" },
  { re: /^#\/apps\/([0-9a-f-]{36})$/, fn: (m) => viewApp(m[1]), nav: "apps" },
  { re: /^#\/audit$/, fn: viewAudit, nav: "audit" },
];

async function route() {
  const hash = location.hash || "#/overview";
  const r = routes.find((r) => r.re.test(hash));
  if (!r) { location.hash = "#/overview"; return; }
  if (!r.pub && !token()) { location.hash = "#/login"; return; }
  if (r.pub && token()) { location.hash = "#/overview"; return; }

  $sidebar.hidden = !token();
  for (const a of document.querySelectorAll("[data-nav]")) {
    a.classList.toggle("active", a.dataset.nav === r.nav);
  }
  try {
    await r.fn(hash.match(r.re));
  } catch (e) {
    show(el("div", { class: "panel" }, el("div", { class: "panel-body" }, el("p", { class: "error" }, e.message))));
  }
}

window.addEventListener("hashchange", route);
route();

/* ---------- login ---------- */

function viewLogin() {
  const err = el("div", { class: "error" });
  const email = el("input", { type: "email", autocomplete: "username", required: "" });
  const pass = el("input", { type: "password", autocomplete: "current-password", required: "" });

  const form = el("form", {
    onsubmit: async (ev) => {
      ev.preventDefault();
      err.textContent = "";
      try {
        const r = await api("POST", "/v1/admin/login", { email: email.value, password: pass.value });
        setToken(r.token, r.expires_at);
        location.hash = "#/overview";
      } catch (e) {
        err.textContent = e.message;
      }
    },
  },
    el("div", { class: "field" }, el("label", {}, "Email"), email),
    el("div", { class: "field" }, el("label", {}, "Password"), pass),
    el("button", { class: "btn primary", type: "submit" }, "Log in"),
    err,
  );

  const mark = el("div", { class: "login-brand" });
  mark.innerHTML = ICONS.shield;
  mark.append(el("span", { class: "brand-name" }, "Cerberus", el("b", {}, "Auth")));

  show(el("div", { class: "login-wrap" },
    el("div", { class: "login-card" },
      mark,
      el("p", { class: "login-sub" }, "Admin console"),
      form,
    ),
  ));
}

/* ---------- overview ---------- */

async function viewOverview() {
  const [stats, auditResp, appsResp] = await Promise.all([
    api("GET", "/v1/admin/stats"),
    api("GET", "/v1/admin/audit?limit=8"),
    api("GET", "/v1/admin/apps"),
  ]);
  const entries = auditResp.entries || [];
  const apps = (appsResp.applications || []).slice(0, 5);

  const stat = (label, n) => el("div", { class: "stat" },
    el("div", { class: "stat-num" }, String(n)),
    el("div", { class: "stat-label" }, label));

  const appRows = apps.map((a) => el("div", {
    class: "app-card",
    onclick: () => { location.hash = "#/apps/" + a.id; },
  },
    el("div", {},
      el("div", { class: "app-name" }, a.name),
      el("div", { class: "app-meta" },
        el("span", { class: "chip" }, "key " + a.key_id),
        el("span", {}, "created " + fmtDate(a.created_at)),
      ),
    ),
  ));

  const auditRows = entries.map((e) => el("tr", {},
    el("td", { class: "muted", style: "white-space:nowrap" }, fmtDate(e.at)),
    el("td", {}, auditAction(e.action)),
    el("td", { class: "mono muted" }, e.target_id ? e.target_id.slice(0, 8) : ""),
  ));

  show(el("div", {},
    pageHead("Overview", "State of this CerberusAuth instance."),
    el("div", { class: "stat-grid" },
      stat("Applications", stats.applications),
      stat("Licenses issued", stats.licenses),
      stat("Active licenses", stats.active_licenses),
      stat("Banned", stats.banned_licenses),
    ),
    el("div", { class: "cols" },
      panel("Applications",
        el("div", { class: "panel-body flush" },
          apps.length === 0
            ? el("div", { class: "empty" }, "No applications yet.")
            : el("div", {}, appRows)),
        el("a", { class: "btn small ghost", href: "#/apps" }, "View all"),
      ),
      panel("Recent activity",
        el("div", { class: "panel-body flush" },
          entries.length === 0
            ? el("div", { class: "empty" }, "Nothing yet.")
            : el("table", {},
                el("thead", {}, el("tr", {}, el("th", {}, "When"), el("th", {}, "Action"), el("th", {}, "Target"))),
                el("tbody", {}, auditRows))),
        el("a", { class: "btn small ghost", href: "#/audit" }, "Full log"),
      ),
    ),
  ));
}

function auditAction(action) {
  let cls = "act";
  if (action.endsWith(".ban") || action.endsWith(".login_failed")) cls += " bad";
  else if (action.startsWith("app.")) cls += " gold";
  else if (action.startsWith("admin.")) cls += " dim";
  return el("span", { class: cls }, action);
}

/* ---------- apps ---------- */

async function viewApps() {
  const data = await api("GET", "/v1/admin/apps");
  const apps = data.applications || [];

  const name = el("input", { placeholder: "My Game", maxlength: "200", required: "" });
  const err = el("div", { class: "error" });
  const createForm = el("form", {
    class: "row",
    onsubmit: async (ev) => {
      ev.preventDefault();
      err.textContent = "";
      try {
        const app = await api("POST", "/v1/admin/apps", { name: name.value });
        location.hash = "#/apps/" + app.id;
      } catch (e) { err.textContent = e.message; }
    },
  },
    el("div", { class: "field" }, el("label", {}, "Application name"), name),
    el("button", { class: "btn primary", type: "submit" }, "Create application"),
  );

  const cards = apps.map((a) => el("div", {
    class: "app-card",
    onclick: () => { location.hash = "#/apps/" + a.id; },
  },
    el("div", {},
      el("div", { class: "app-name" }, a.name),
      el("div", { class: "app-meta" },
        el("span", { class: "chip" }, a.id),
        el("span", { class: "chip" }, "key " + a.key_id),
        el("span", {}, "created " + fmtDate(a.created_at)),
      ),
    ),
    el("div", { class: "actions" },
      el("button", {
        class: "btn small",
        onclick: (ev) => { ev.stopPropagation(); copy(a.id, "App ID"); },
      }, "Copy ID"),
      el("button", { class: "btn small primary" }, "Manage"),
    ),
  ));

  show(el("div", {},
    pageHead("Applications", "Each application has its own signing keypair; clients pin the public half."),
    panel("New application", el("div", { class: "panel-body" }, createForm, err)),
    panel("My applications",
      el("div", { class: "panel-body flush" },
        apps.length === 0
          ? el("div", { class: "empty" }, "No applications yet. Create the first one above.")
          : el("div", {}, cards)),
      el("span", { class: "muted", style: "font-size:12px" }, apps.length + " total"),
    ),
  ));
}

/* ---------- single app ---------- */

const PAGE = 50;

async function viewApp(id, page = 0) {
  const [app, keysResp, licResp] = await Promise.all([
    api("GET", "/v1/admin/apps/" + id),
    api("GET", "/v1/admin/apps/" + id + "/keys"),
    api("GET", `/v1/admin/apps/${id}/licenses?limit=${PAGE}&offset=${page * PAGE}`),
  ]);
  const keys = keysResp.keys || [];
  const lics = licResp.licenses || [];

  const kv = (label, value) => el("div", { class: "kv" },
    el("div", { class: "kv-label" }, label),
    el("div", { class: "kv-row" },
      el("div", { class: "kv-value" }, value),
      iconBtn("copy", "Copy " + label.toLowerCase(), () => copy(value, label)),
    ),
  );

  const credsPanel = panel("Credentials",
    el("div", { class: "panel-body" },
      kv("Application ID", app.id),
      kv("Active public key", app.public_key),
      kv("Key ID", app.key_id),
      el("p", { class: "hint" }, "Pin the public key in your client at build time. The pubkey endpoint is a convenience, not the trust anchor."),
    ),
  );

  const keysPanel = panel("Signing keys",
    el("div", { class: "panel-body flush" },
      el("table", {},
        el("thead", {}, el("tr", {},
          el("th", {}, "Key ID"), el("th", {}, "Status"), el("th", {}, "Created"), el("th", {}, "Retired"))),
        el("tbody", {}, keys.map((k) => el("tr", {},
          el("td", { class: "mono" }, k.key_id),
          el("td", {}, el("span", { class: "pill " + (k.active ? "active" : "retired") }, k.active ? "active" : "retired")),
          el("td", { class: "muted" }, fmtDate(k.created_at)),
          el("td", { class: "muted" }, k.retired_at ? fmtDate(k.retired_at) : ""),
        ))),
      ),
      el("div", { style: "padding:12px 16px; border-top: 1px solid var(--border)" },
        el("button", {
          class: "btn small danger",
          onclick: async () => {
            if (!confirm("Rotate the signing key for \"" + app.name + "\"?\n\nClients that pin only the current key will fail closed until they ship the new one. Read docs/KEY-ROTATION.md first.")) return;
            try {
              await api("POST", "/v1/admin/apps/" + id + "/rotate-key");
              toast("Key rotated");
              viewApp(id, page);
            } catch (e) { toast(e.message); }
          },
        }, "Rotate key"),
        el("p", { class: "hint" }, "Rotating retires this key but keeps it listed, so clients pinning both stay valid during the switch."),
      ),
    ),
  );

  /* issue licenses */
  const count = el("input", { type: "number", min: "1", max: "1000", value: "1", style: "width:80px" });
  const tier = el("input", { placeholder: "default", maxlength: "64", style: "width:130px" });
  const days = el("input", { type: "number", min: "0", placeholder: "perpetual", style: "width:120px" });
  const issueErr = el("div", { class: "error" });
  const issueOut = el("div", {});

  const issueForm = el("form", {
    class: "row",
    onsubmit: async (ev) => {
      ev.preventDefault();
      issueErr.textContent = "";
      const body = { count: parseInt(count.value, 10) || 1, tier: tier.value };
      const d = parseInt(days.value, 10);
      if (d > 0) body.duration_seconds = d * 86400;
      try {
        const r = await api("POST", "/v1/admin/apps/" + id + "/licenses", body);
        const keysText = (r.licenses || []).map((l) => l.key).join("\n");
        issueOut.replaceChildren(
          el("p", { class: "notice" }, "Plaintext keys, shown once. Copy or download them now; the server keeps only hashes."),
          el("div", { class: "issued-keys" }, keysText),
          el("div", { class: "row" },
            el("button", { class: "btn small primary", onclick: () => copy(keysText, "Keys") }, "Copy all"),
            el("button", {
              class: "btn small",
              onclick: () => {
                const a = el("a", {
                  href: URL.createObjectURL(new Blob([keysText + "\n"], { type: "text/plain" })),
                  download: app.name.replace(/[^a-z0-9-_]+/gi, "_") + "-keys.txt",
                });
                a.click();
                URL.revokeObjectURL(a.href);
              },
            }, "Download .txt"),
          ),
        );
        viewAppLicenses(id, 0, licTable); // refresh table without wiping the shown keys
      } catch (e) { issueErr.textContent = e.message; }
    },
  },
    el("div", { class: "field" }, el("label", {}, "Count"), count),
    el("div", { class: "field" }, el("label", {}, "Tier"), tier),
    el("div", { class: "field" }, el("label", {}, "Days valid (from redeem)"), days),
    el("button", { class: "btn primary", type: "submit" }, "Issue"),
  );

  const issuePanel = panel("Issue licenses",
    el("div", { class: "panel-body" }, issueForm, issueErr, issueOut));

  /* licenses table */
  const licTable = el("div", {});
  renderLicenses(licTable, id, lics, page);
  const licPanel = panel("Licenses", el("div", { class: "panel-body flush" }, licTable));

  show(el("div", {},
    el("div", { class: "crumbs" }, el("a", { href: "#/apps" }, "Applications"), el("span", {}, app.name)),
    pageHead(app.name, "Created " + fmtDate(app.created_at)),
    el("div", { class: "detail-grid" },
      el("div", {}, credsPanel, keysPanel),
      el("div", {}, issuePanel, licPanel),
    ),
  ));
}

async function viewAppLicenses(id, page, container) {
  const r = await api("GET", `/v1/admin/apps/${id}/licenses?limit=${PAGE}&offset=${page * PAGE}`);
  renderLicenses(container, id, r.licenses || [], page);
}

function renderLicenses(container, appID, lics, page) {
  const act = (label, cls, fn) => el("button", { class: "btn small " + cls, onclick: fn }, label);

  const refresh = () => viewAppLicenses(appID, page, container);

  const rows = lics.map((l) => el("tr", {},
    el("td", { class: "mono" }, "...-" + l.key_hint),
    el("td", {}, l.tier),
    el("td", {}, statusPill(l)),
    el("td", {}, l.hwid_bound ? "bound" : el("span", { class: "muted" }, "unbound")),
    el("td", { class: "muted" }, fmtExpiry(l)),
    el("td", { class: "right" },
      l.status === "banned"
        ? act("Unban", "", async () => {
            try { await api("POST", `/v1/admin/licenses/${l.id}/unban`); toast("Unbanned"); refresh(); }
            catch (e) { toast(e.message); }
          })
        : act("Ban", "danger", async () => {
            const reason = prompt("Ban reason (optional):");
            if (reason === null) return;
            try { await api("POST", `/v1/admin/licenses/${l.id}/ban`, { reason }); toast("Banned"); refresh(); }
            catch (e) { toast(e.message); }
          }),
      " ",
      l.hwid_bound
        ? act("Reset HWID", "", async () => {
            if (!confirm("Unbind the device? The next device to validate will claim it.")) return;
            try { await api("POST", `/v1/admin/licenses/${l.id}/reset-hwid`); toast("HWID reset"); refresh(); }
            catch (e) { toast(e.message); }
          })
        : null,
    ),
  ));

  const pager = el("div", { class: "pager" },
    el("button", {
      class: "btn small", disabled: page === 0 ? "" : undefined,
      onclick: () => viewAppLicenses(appID, page - 1, container),
    }, "Newer"),
    el("button", {
      class: "btn small", disabled: lics.length < PAGE ? "" : undefined,
      onclick: () => viewAppLicenses(appID, page + 1, container),
    }, "Older"),
  );

  container.replaceChildren(
    lics.length === 0 && page === 0
      ? el("div", { class: "empty" }, "No licenses issued yet.")
      : el("div", {},
          el("table", {},
            el("thead", {}, el("tr", {},
              el("th", {}, "Key"), el("th", {}, "Tier"), el("th", {}, "Status"),
              el("th", {}, "Device"), el("th", {}, "Expiry"), el("th", { class: "right" }, "Actions"))),
            el("tbody", {}, rows)),
          pager),
  );
}

/* ---------- audit ---------- */

async function viewAudit(_, page = 0) {
  const r = await api("GET", `/v1/admin/audit?limit=${PAGE}&offset=${page * PAGE}`);
  const entries = r.entries || [];

  const rows = entries.map((e) => el("tr", {},
    el("td", { class: "muted", style: "white-space:nowrap" }, fmtDate(e.at)),
    el("td", {}, auditAction(e.action)),
    el("td", { class: "mono muted" }, e.target_id || ""),
    el("td", {}, e.detail || ""),
    el("td", { class: "mono muted" }, e.admin_id ? e.admin_id.slice(0, 8) : "-"),
  ));

  const pager = el("div", { class: "pager" },
    el("button", { class: "btn small", disabled: page === 0 ? "" : undefined, onclick: () => viewAudit(null, page - 1) }, "Newer"),
    el("button", { class: "btn small", disabled: entries.length < PAGE ? "" : undefined, onclick: () => viewAudit(null, page + 1) }, "Older"),
  );

  show(el("div", {},
    pageHead("Audit log", "Every admin action and login event, append-only, newest first."),
    panel("Events",
      el("div", { class: "panel-body flush" },
        entries.length === 0 && page === 0
          ? el("div", { class: "empty" }, "Nothing yet.")
          : el("div", {},
              el("table", {},
                el("thead", {}, el("tr", {},
                  el("th", {}, "When"), el("th", {}, "Action"), el("th", {}, "Target"),
                  el("th", {}, "Detail"), el("th", {}, "Admin"))),
                el("tbody", {}, rows)),
              pager)),
    ),
  ));
}
