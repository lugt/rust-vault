import init, { unlock, VaultHandle } from "./pkg/vault_wasm.js";

// ---- global state ----
let handle = null;        // VaultHandle from WASM
let snapCache = null;     // last fetched snapshot JSON
let currentVersion = 0;   // server's last known version
let dirty = false;        // unsaved local changes
let selectedName = null;  // currently selected entry name
let idleTimer = null;
const IDLE_MS = 60 * 60 * 1000;
const SAVED_API_KEY = "vault_api";
const SAVED_TOKEN_KEY = "vault_token";

// ---- API URL auto-detect ----
function autoDetectApi() {
  // If we're at /keychain/index.html or /keychain/, API is at /keychain/vault
  // Strip trailing index.html or trailing slash, append "vault".
  const path = location.pathname.replace(/index\.html$/, "").replace(/\/$/, "");
  return `${location.origin}${path}/vault`;
}

// ---- API helpers ----
async function apiGet(suffix = "") {
  const url = apiUrl() + suffix;
  const r = await fetch(url, { headers: authHeader() });
  return { res: r, url };
}
async function apiPost(suffix, body) {
  const url = apiUrl() + suffix;
  const r = await fetch(url, {
    method: "POST",
    headers: { ...authHeader(), "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { res: r, url };
}
async function apiPut(body, ifMatch) {
  const url = apiUrl();
  const r = await fetch(url, {
    method: "PUT",
    headers: { ...authHeader(), "content-type": "application/json", "if-match": String(ifMatch) },
    body: JSON.stringify(body),
  });
  return { res: r, url };
}
function apiUrl() {
  return document.getElementById("api-url").value.trim().replace(/\/$/, "");
}
function authHeader() {
  return { authorization: `Bearer ${document.getElementById("api-token").value.trim()}` };
}
function logErr(msg, url, status) {
  const err = document.getElementById("lock-error");
  err.textContent = `${msg} (url=${url}, status=${status})`;
  console.error(msg, { url, status });
}

// ---- Lock/unlock ----
function lock() {
  handle = null;
  snapCache = null;
  currentVersion = 0;
  selectedName = null;
  document.getElementById("app").hidden = true;
  document.getElementById("lock-screen").hidden = false;
  document.getElementById("lock-error").textContent = "";
}
function bumpIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => { alert("已自动锁定（60 分钟无活动）"); lock(); }, IDLE_MS);
}

document.getElementById("lock-btn").onclick = () => {
  if (dirty && !confirm("有未保存的修改，确认锁定？")) return;
  lock();
};

document.getElementById("unlock-btn").onclick = async () => {
  const pw = document.getElementById("master-pw").value;
  document.getElementById("lock-error").textContent = "解密中...";
  try {
    const { res, url } = await apiGet();
    if (!res.ok) { logErr(`GET vault failed`, url, res.status); return; }
    snapCache = await res.json();
    currentVersion = snapCache.version;
    await init();
    handle = unlock(pw, JSON.stringify(snapCache));
    document.getElementById("lock-screen").hidden = true;
    document.getElementById("app").hidden = false;
    document.getElementById("entry-count").textContent = handle.count();
    document.getElementById("version-info").textContent = `v${currentVersion}`;
    localStorage.setItem(SAVED_API_KEY, apiUrl());
    localStorage.setItem(SAVED_TOKEN_KEY, document.getElementById("api-token").value.trim());
    renderGroups();
    document.getElementById("search-box").dispatchEvent(new Event("input"));
    bumpIdle();
    document.getElementById("lock-error").textContent = "";
  } catch (e) {
    logErr(String(e.message || e), "", "");
    handle = null;
  }
};

// ---- Search & results ----
let debounce = null;
document.getElementById("search-box").oninput = (e) => {
  clearTimeout(debounce);
  debounce = setTimeout(() => {
    if (!handle) return;
    const q = e.target.value;
    const hits = handle.search(q);
    document.getElementById("results").innerHTML = hits
      .map(
        (h) =>
          `<div class="hit ${h.name === selectedName ? "selected" : ""}" data-name="${escapeHtml(h.name)}">
            <b>${escapeHtml(h.name)}</b>
            <span class="muted">${escapeHtml(h.url || "")}</span>
            <span class="muted">${escapeHtml(h.username || "")}</span>
            <span class="score">${h.score.toFixed(2)}</span>
          </div>`
      )
      .join("");
    document.querySelectorAll(".hit").forEach((el) => {
      el.onclick = () => showDetail(el.dataset.name);
    });
  }, 200);
};

function showDetail(name) {
  if (!handle) return;
  selectedName = name;
  const hits = handle.search(`name:"${name}"`);
  const h = hits[0];
  if (!h) return;
  document.getElementById("d-name").textContent = h.name;
  document.getElementById("d-url").textContent = h.url || "(none)";
  document.getElementById("d-user").textContent = h.username || "";
  const pwSpan = document.getElementById("d-pw");
  pwSpan.textContent = "••••••••";
  document.getElementById("d-note").textContent = h.note || "";
  document.getElementById("detail").hidden = false;
  document.getElementById("d-reveal").onclick = () => { pwSpan.textContent = h.password; bumpIdle(); };
  document.querySelectorAll("[data-copy]").forEach((b) => {
    b.onclick = () => copy(b.dataset.copy === "pw" ? h.password : h.username);
  });
  // refresh selection highlight
  document.querySelectorAll(".hit").forEach((el) => el.classList.toggle("selected", el.dataset.name === name));
}

// ---- Clipboard ----
async function copy(text) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    setTimeout(async () => { try { await navigator.clipboard.writeText(""); } catch {} }, 30_000);
  } catch (e) { alert("复制失败: " + e.message); }
}

// ---- Groups sidebar ----
function renderGroups() {
  if (!handle) return;
  const groups = handle.group_by_domain();
  document.getElementById("groups").innerHTML =
    `<div class="grp"><b>全部</b></div>` +
    groups
      .map((g) => `<div class="grp" data-key="${escapeHtml(g.key)}"><b>${escapeHtml(g.key)}</b> (${g.count})</div>`)
      .join("");
  document.querySelectorAll(".grp[data-key]").forEach((el) => {
    el.onclick = () => {
      const key = el.dataset.key;
      document.getElementById("search-box").value = `domain:"${key}"`;
      document.getElementById("search-box").dispatchEvent(new Event("input"));
    };
  });
}

// ---- Add / Edit / Delete / Save (in-memory + persist) ----
function readAll() {
  if (!handle) return [];
  return JSON.parse(JSON.stringify(handle.all()));  // serialize JsValue → plain array
}

document.getElementById("add-btn").onclick = () => openEntryModal(null);
document.getElementById("edit-btn").onclick = () => {
  if (!selectedName) return alert("请先在结果中点选一个条目");
  const all = readAll();
  const entry = all.find((e) => e.name === selectedName);
  if (entry) openEntryModal(entry);
};
document.getElementById("delete-btn").onclick = () => {
  if (!selectedName) return alert("请先在结果中点选一个条目");
  if (!confirm(`删除 "${selectedName}"？`)) return;
  const all = readAll().filter((e) => e.name !== selectedName);
  handle.set_entries(all);
  dirty = true;
  flagDirty();
  selectedName = null;
  document.getElementById("detail").hidden = true;
  document.getElementById("search-box").dispatchEvent(new Event("input"));
};

document.getElementById("save-btn").onclick = async () => {
  if (!handle) return;
  if (!dirty) return alert("没有未保存的修改");
  const write = JSON.parse(handle.put_entries());
  const { res, url } = await apiPut(write, currentVersion);
  if (res.status === 409) {
    const body = await res.json();
    if (!confirm(`服务器有更新的版本 (v${body.current_version})。强制覆盖？(可能丢失别人/上次的修改)`)) return;
    // Refetch, re-decrypt (with current master pw), merge, save again
    const { res: r2 } = await apiGet();
    const newSnap = await r2.json();
    currentVersion = newSnap.version;
    handle = unlock(document.getElementById("master-pw").value, JSON.stringify(newSnap));
    // apply our in-memory edits (handle now has server's version, replace with our entries)
    handle.set_entries(readAll());
    const w2 = JSON.parse(handle.put_entries());
    const { res: r3 } = await apiPut(w2, currentVersion);
    if (!r3.ok) return alert("保存失败: " + r3.status);
  } else if (!res.ok) {
    return alert(`保存失败: ${res.status}`);
  }
  const body = await res.json();
  currentVersion = body.version || currentVersion + 1;
  document.getElementById("version-info").textContent = `v${currentVersion}`;
  dirty = false;
  flagDirty();
  alert("已保存");
};

document.getElementById("rekey-btn").onclick = () => openRekeyModal();
document.getElementById("history-btn").onclick = () => openHistoryModal();
document.getElementById("clear-btn").onclick = () => openClearModal();

function flagDirty() {
  document.getElementById("dirty-flag").textContent = dirty ? "是" : "否";
  document.getElementById("dirty-flag").style.color = dirty ? "#c00" : "#888";
}

// ---- Modal helpers ----
function openModal(title, bodyHTML, footerHTML) {
  document.getElementById("modal-title").textContent = title;
  document.getElementById("modal-body").innerHTML = bodyHTML;
  document.getElementById("modal-footer").innerHTML = footerHTML;
  document.getElementById("modal-bg").hidden = false;
  bumpIdle();
}
function closeModal() {
  document.getElementById("modal-bg").hidden = true;
}
document.getElementById("modal-close").onclick = closeModal;
document.getElementById("modal-bg").onclick = (e) => { if (e.target.id === "modal-bg") closeModal(); };

// ---- Entry modal (add/edit) ----
function openEntryModal(entry) {
  const e = entry || { name: "", url: "", username: "", password: "", note: "" };
  const isNew = !entry;
  openModal(isNew ? "新增条目" : "编辑条目",
    `<label>Name <input id="e-name" value="${escapeHtml(e.name)}" ${isNew ? "" : "readonly"}></label>
     <label>URL <input id="e-url" value="${escapeHtml(e.url)}"></label>
     <label>Username <input id="e-username" value="${escapeHtml(e.username)}"></label>
     <label>Password <input id="e-password" value="${escapeHtml(e.password)}"></label>
     <label>Note <textarea id="e-note" rows="3">${escapeHtml(e.note)}</textarea></label>`,
    `<button id="e-cancel">取消</button><button id="e-save">保存（到内存）</button>`
  );
  document.getElementById("e-cancel").onclick = closeModal;
  document.getElementById("e-save").onclick = () => {
    const newName = document.getElementById("e-name").value.trim();
    if (!newName) return alert("Name 不能为空");
    const newEntry = {
      name: newName,
      url: document.getElementById("e-url").value.trim(),
      username: document.getElementById("e-username").value.trim(),
      password: document.getElementById("e-password").value,
      note: document.getElementById("e-note").value,
    };
    const all = readAll();
    if (isNew) {
      if (all.some((x) => x.name === newName)) return alert("已存在同名条目");
      all.push(newEntry);
    } else {
      const i = all.findIndex((x) => x.name === selectedName);
      if (i >= 0) all[i] = newEntry;
    }
    handle.set_entries(all);
    selectedName = newName;
    dirty = true;
    flagDirty();
    closeModal();
    document.getElementById("search-box").dispatchEvent(new Event("input"));
  };
}

// ---- Rekey modal ----
function openRekeyModal() {
  openModal("更换主口令",
    `<p class="muted">重写 wrapped_cek，不重加密 CSV。会创建一个新版本。</p>
     <label>新主口令 <input id="r-new" type="password"></label>
     <label>确认新主口令 <input id="r-new2" type="password"></label>`,
    `<button id="r-cancel">取消</button><button id="r-go">确认换密码</button>`
  );
  document.getElementById("r-cancel").onclick = closeModal;
  document.getElementById("r-go").onclick = async () => {
    const n1 = document.getElementById("r-new").value;
    const n2 = document.getElementById("r-new2").value;
    if (!n1) return alert("新口令不能为空");
    if (n1 !== n2) return alert("两次输入不一致");
    const rekey = JSON.parse(handle.rekey(n1));
    const { res } = await apiPost("/rekey", rekey);
    if (!res.ok) return alert(`rekey 失败: ${res.status} ${await res.text()}`);
    const body = await res.json();
    currentVersion = body.version;
    document.getElementById("version-info").textContent = `v${currentVersion}`;
    closeModal();
    alert("已换密码，请用新口令重新解锁。");
    lock();
  };
}

// ---- History modal ----
async function openHistoryModal() {
  openModal("历史版本", `<div id="hist-list">加载中...</div>`,
    `<button id="h-close">关闭</button>`
  );
  document.getElementById("h-close").onclick = closeModal;
  const { res } = await apiGet("/history");
  if (!res.ok) {
    document.getElementById("hist-list").textContent = `加载失败: ${res.status}`;
    return;
  }
  const body = await res.json();
  const cur = body.current_version;
  const items = body.history || [];
  const list = items.map((h) =>
    `<div class="hist-row" data-v="${h.version}">
       <b>v${h.version}</b>
       <span class="muted">${escapeHtml(h.archived_at || "")}</span>
       <button class="recover-v" data-v="${h.version}">恢复</button>
     </div>`
  ).join("");
  document.getElementById("hist-list").innerHTML =
    `<p>当前版本: ${cur === null ? "(空)" : "v" + cur}</p>` +
    (items.length === 0 ? "<p class='muted'>(暂无历史)</p>" : list);
  document.querySelectorAll(".recover-v").forEach((btn) => {
    btn.onclick = async () => {
      const v = Number(btn.dataset.v);
      if (!confirm(`恢复 v${v}？当前版本会被归档。需要 v${v} 的老主口令解密。`)) return;
      const { res: r2 } = await apiPost("/recover", { from_version: v });
      if (!r2.ok) return alert(`恢复失败: ${r2.status} ${await r2.text()}`);
      const b = await r2.json();
      currentVersion = b.version;
      document.getElementById("version-info").textContent = `v${currentVersion}`;
      closeModal();
      alert(`已恢复为 v${currentVersion}。请用 v${v} 的主口令重新解锁。`);
      lock();
    };
  });
}

// ---- Clear modal ----
function openClearModal() {
  if (!confirm("⚠️ 高危操作：清空当前 vault？当前快照会归档到历史，但下次登录需要 init。")) return;
  const ok = prompt("输入 CLEAR 确认清空：");
  if (ok !== "CLEAR") return alert("已取消");
  (async () => {
    const { res } = await apiPost("/clear", {});
    if (res.status !== 204) return alert(`清空失败: ${res.status} ${await res.text()}`);
    alert("已清空。请用 vault-cli init 重新初始化。");
    lock();
  })();
}

// ---- utils ----
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

// ---- init: pre-fill API URL & token from localStorage ----
const savedApi = localStorage.getItem(SAVED_API_KEY);
const savedToken = localStorage.getItem(SAVED_TOKEN_KEY);
if (savedApi) document.getElementById("api-url").value = savedApi;
else document.getElementById("api-url").value = autoDetectApi();
if (savedToken) document.getElementById("api-token").value = savedToken;
