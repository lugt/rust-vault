import init, { unlock, VaultHandle } from "./pkg/vault_wasm.js";

let handle = null;
let snapCache = null;
let idleTimer = null;
const IDLE_MS = 60 * 60 * 1000; // 60 minutes

function lock() {
  handle = null;
  snapCache = null;
  document.getElementById("app").hidden = true;
  document.getElementById("lock-screen").hidden = false;
  document.getElementById("lock-error").textContent = "";
}

function bumpIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    alert("已自动锁定（60 分钟无活动）");
    lock();
  }, IDLE_MS);
}

document.addEventListener("mousemove", bumpIdle);
document.addEventListener("keydown", bumpIdle);

document.getElementById("lock-btn").onclick = () => {
  if (confirm("确认锁定？将清空浏览器中的明文。")) lock();
};

document.getElementById("unlock-btn").onclick = async () => {
  const url = document.getElementById("api-url").value.trim();
  const token = document.getElementById("api-token").value.trim();
  const pw = document.getElementById("master-pw").value;
  const errBox = document.getElementById("lock-error");
  errBox.textContent = "解密中...";
  try {
    const r = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
    if (!r.ok) throw new Error(`GET vault: ${r.status}`);
    snapCache = await r.json();
    await init();
    handle = unlock(pw, JSON.stringify(snapCache));
    document.getElementById("lock-screen").hidden = true;
    document.getElementById("app").hidden = false;
    document.getElementById("entry-count").textContent = handle.count();
    localStorage.setItem("vault_api", url);
    localStorage.setItem("vault_token", token);
    renderGroups();
    document.getElementById("search-box").dispatchEvent(new Event("input"));
    bumpIdle();
    errBox.textContent = "";
  } catch (e) {
    errBox.textContent = String(e.message || e);
    handle = null;
  }
};

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
          `<div class="hit" data-name="${escapeHtml(h.name)}">
            <b>${escapeHtml(h.name)}</b>
            <span class="muted">${escapeHtml(h.url || "")}</span>
            <span class="muted">${escapeHtml(h.username || "")}</span>
            <span class="score">${h.score.toFixed(2)}</span>
          </div>`
      )
      .join("");
    [...document.querySelectorAll(".hit")].forEach((el) => {
      el.onclick = () => showDetail(el.dataset.name);
    });
  }, 200);
};

function showDetail(name) {
  if (!handle) return;
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
  document.getElementById("d-reveal").onclick = () => {
    pwSpan.textContent = h.password;
    bumpIdle();
  };
  document.querySelectorAll("[data-copy]").forEach((b) => {
    b.onclick = () => copy(b.dataset.copy === "pw" ? h.password : h.username);
  });
}

async function copy(text) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    setTimeout(async () => {
      try {
        await navigator.clipboard.writeText("");
      } catch {}
    }, 30_000);
  } catch (e) {
    alert("复制失败: " + e.message);
  }
}

function renderGroups() {
  if (!handle) return;
  const groups = handle.group_by_domain();
  document.getElementById("groups").innerHTML =
    `<div class="grp"><b>全部</b></div>` +
    groups
      .map(
        (g) =>
          `<div class="grp" data-key="${escapeHtml(g.key)}"><b>${escapeHtml(g.key)}</b> (${g.count})</div>`
      )
      .join("");
  document.querySelectorAll(".grp[data-key]").forEach((el) => {
    el.onclick = () => {
      const key = el.dataset.key;
      document.getElementById("search-box").value = `domain:"${key}"`;
      document.getElementById("search-box").dispatchEvent(new Event("input"));
    };
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

// Pre-fill api/token from localStorage
const savedApi = localStorage.getItem("vault_api");
const savedToken = localStorage.getItem("vault_token");
if (savedApi) document.getElementById("api-url").value = savedApi;
if (savedToken) document.getElementById("api-token").value = savedToken;
