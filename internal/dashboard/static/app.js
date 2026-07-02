"use strict";

/* CerberusAuth dashboard: a thin shell over the admin API. No framework,
   no build step, no external requests. State lives in the API; this file
   only renders it. */

const $view = document.getElementById("view");
const $topbar = document.getElementById("topbar");
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

function statusBadge(lic) {
  let cls = lic.status;
  if (lic.status === "active" && lic.expires_at && new Date(lic.expires_at) < new Date()) cls = "expired";
  return el("span", { class: "badge " + cls }, cls);
}

/* ---------- router ---------- */

const routes = [
  { re: /^#\/login$/, fn: viewLogin, pub: true },
  { re: /^#\/apps$/, fn: viewApps, nav: "apps" },
  { re: /^#\/apps\/([0-9a-f-]{36})$/, fn: (m) => viewApp(m[1]), nav: "apps" },
  { re: /^#\/audit$/, fn: viewAudit, nav: "audit" },
];

async function route() {
  const hash = location.hash || "#/apps";
  const r = routes.find((r) => r.re.test(hash));
  if (!r) { location.hash = "#/apps"; return; }
  if (!r.pub && !token()) { location.hash = "#/login"; return; }
  if (r.pub && token()) { location.hash = "#/apps"; return; }

  $topbar.hidden = !token();
  for (const a of document.querySelectorAll("[data-nav]")) {
    a.classList.toggle("active", a.dataset.nav === r.nav);
  }
  try {
    await r.fn(hash.match(r.re));
  } catch (e) {
    show(el("div", { class: "panel" }, el("p", { class: "error" }, e.message)));
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
        location.hash = "#/apps";
      } catch (e) {
        err.textContent = e.message;
      }
    },
  },
    el("div", { class: "field" }, el("label", {}, "Email"), email),
    el("div", { class: "field" }, el("label", {}, "Password"), pass),
    el("button", { type: "submit" }, "Log in"),
    err,
  );

  show(el("div", { class: "login-wrap" },
    el("div", { class: "panel login-box" },
      el("div", { class: "brand" }, "Cerberus", el("span", {}, "Auth")),
      form,
    ),
  ));
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
    el("button", { type: "submit" }, "Create"),
  );

  const rows = apps.map((a) => el("tr", {
    class: "click",
    onclick: () => { location.hash = "#/apps/" + a.id; },
  },
    el("td", {}, a.name),
    el("td", { class: "mono muted" }, a.id),
    el("td", { class: "mono" }, a.key_id),
    el("td", { class: "muted" }, fmtDate(a.created_at)),
  ));

  show(el("div", {},
    el("h1", {}, "Applications"),
    el("p", { class: "sub" }, "Each application has its own signing keypair; clients pin the public half."),
    el("div", { class: "panel" }, el("h2", {}, "New application"), createForm, err),
    el("div", { class: "panel" },
      apps.length === 0
        ? el("div", { class: "empty" }, "No applications yet. Create the first one above.")
        : el("table", {},
            el("thead", {}, el("tr", {},
              el("th", {}, "Name"), el("th", {}, "ID"), el("th", {}, "Active key"), el("th", {}, "Created"))),
            el("tbody", {}, rows)),
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

  /* pinned key */
  const keyPanel = el("div", { class: "panel" },
    el("h2", {}, "Signing keys"),
    el("div", { class: "keyblock" },
      el("code", {}, app.public_key),
      el("button", { class: "small ghost", onclick: () => copy(app.public_key, "Public key") }, "Copy"),
    ),
    el("p", { class: "sub", style: "margin:8px 0 12px" },
      "Pin this key in your client. Rotating retires it but keeps it listed, so clients pinning both stay valid during the switch."),
    el("table", {},
      el("thead", {}, el("tr", {},
        el("th", {}, "Key ID"), el("th", {}, "Status"), el("th", {}, "Created"), el("th", {}, "Retired"))),
      el("tbody", {}, keys.map((k) => el("tr", {},
        el("td", { class: "mono" }, k.key_id),
        el("td", {}, el("span", { class: "badge " + (k.active ? "active" : "retired") }, k.active ? "active" : "retired")),
        el("td", { class: "muted" }, fmtDate(k.created_at)),
        el("td", { class: "muted" }, k.retired_at ? fmtDate(k.retired_at) : ""),
      ))),
    ),
    el("div", { style: "margin-top:12px" },
      el("button", {
        class: "danger",
        onclick: async () => {
          if (!confirm("Rotate the signing key for \"" + app.name + "\"?\n\nClients that pin only the current key will fail closed until they ship the new one. Read docs/KEY-ROTATION.md first.")) return;
          try {
            await api("POST", "/v1/admin/apps/" + id + "/rotate-key");
            toast("Key rotated");
            viewApp(id, page);
          } catch (e) { toast(e.message); }
        },
      }, "Rotate key"),
    ),
  );

  /* issue licenses */
  const count = el("input", { type: "number", min: "1", max: "1000", value: "1", style: "width:80px" });
  const tier = el("input", { placeholder: "default", maxlength: "64", style: "width:120px" });
  const days = el("input", { type: "number", min: "0", placeholder: "perpetual", style: "width:110px" });
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
            el("button", { class: "small", onclick: () => copy(keysText, "Keys") }, "Copy all"),
            el("button", {
              class: "small ghost",
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
    el("button", { type: "submit" }, "Issue"),
  );

  const issuePanel = el("div", { class: "panel" },
    el("h2", {}, "Issue licenses"), issueForm, issueErr, issueOut);

  /* licenses table */
  const licTable = el("div", {});
  renderLicenses(licTable, id, lics, page);

  const licPanel = el("div", { class: "panel" }, el("h2", {}, "Licenses"), licTable);

  show(el("div", {},
    el("a", { class: "crumb", href: "#/apps" }, "< applications"),
    el("div", { class: "head-row" },
      el("h1", {}, app.name),
      el("span", { class: "mono muted", onclick: () => copy(app.id, "App ID"), style: "cursor:pointer" }, app.id),
    ),
    el("p", { class: "sub" }, "Created " + fmtDate(app.created_at)),
    keyPanel, issuePanel, licPanel,
  ));
}

async function viewAppLicenses(id, page, container) {
  const r = await api("GET", `/v1/admin/apps/${id}/licenses?limit=${PAGE}&offset=${page * PAGE}`);
  renderLicenses(container, id, r.licenses || [], page);
}

function renderLicenses(container, appID, lics, page) {
  const act = (label, cls, fn) => el("button", { class: "small " + cls, onclick: fn }, label);

  const refresh = () => viewAppLicenses(appID, page, container);

  const rows = lics.map((l) => el("tr", {},
    el("td", { class: "mono" }, "...-" + l.key_hint),
    el("td", {}, l.tier),
    el("td", {}, statusBadge(l)),
    el("td", {}, l.hwid_bound ? "bound" : el("span", { class: "muted" }, "unbound")),
    el("td", { class: "muted" }, fmtExpiry(l)),
    el("td", {},
      l.status === "banned"
        ? act("Unban", "ghost", async () => {
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
        ? act("Reset HWID", "ghost", async () => {
            if (!confirm("Unbind the device? The next device to validate will claim it.")) return;
            try { await api("POST", `/v1/admin/licenses/${l.id}/reset-hwid`); toast("HWID reset"); refresh(); }
            catch (e) { toast(e.message); }
          })
        : null,
    ),
  ));

  const pager = el("div", { class: "pager" },
    el("button", {
      class: "small ghost", disabled: page === 0 ? "" : undefined,
      onclick: () => viewAppLicenses(appID, page - 1, container),
    }, "Newer"),
    el("button", {
      class: "small ghost", disabled: lics.length < PAGE ? "" : undefined,
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
              el("th", {}, "Device"), el("th", {}, "Expiry"), el("th", {}, ""))),
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
    el("td", { class: "mono" }, e.action),
    el("td", { class: "mono muted" }, e.target_id || ""),
    el("td", {}, e.detail || ""),
    el("td", { class: "mono muted" }, e.admin_id ? e.admin_id.slice(0, 8) : "-"),
  ));

  const pager = el("div", { class: "pager" },
    el("button", { class: "small ghost", disabled: page === 0 ? "" : undefined, onclick: () => viewAudit(null, page - 1) }, "Newer"),
    el("button", { class: "small ghost", disabled: entries.length < PAGE ? "" : undefined, onclick: () => viewAudit(null, page + 1) }, "Older"),
  );

  show(el("div", {},
    el("h1", {}, "Audit log"),
    el("p", { class: "sub" }, "Every admin action and login event, append-only, newest first."),
    el("div", { class: "panel" },
      entries.length === 0 && page === 0
        ? el("div", { class: "empty" }, "Nothing yet.")
        : el("div", {},
            el("table", {},
              el("thead", {}, el("tr", {},
                el("th", {}, "When"), el("th", {}, "Action"), el("th", {}, "Target"),
                el("th", {}, "Detail"), el("th", {}, "Admin"))),
              el("tbody", {}, rows)),
            pager),
    ),
  ));
}
