// Global reactive state. No Pinia — a single reactive object is enough.
//
// SECURITY INVARIANTS:
//   - masterPw is NEVER persisted. It lives only in memory and is cleared
//     on lock / idle-timeout / page unload.
//   - token and apiUrl MAY be cached in localStorage for convenience.
//   - The VaultHandle (WASM) holds the decrypted CEK/entries in WASM memory;
//     clearing `handleCleared` on lock drops that reference.

import { reactive } from "vue";
import { autoDetectApi } from "./api.js";
import { clearHandle } from "./wasm.js";

const LS_API = "vault_api";
const LS_TOKEN = "vault_token";

export const state = reactive({
  // connection
  apiUrl: localStorage.getItem(LS_API) || autoDetectApi(),
  token: localStorage.getItem(LS_TOKEN) || "",

  // session (memory only)
  unlocked: false,
  masterPw: "", // never persisted
  currentVersion: 0,
  dirty: false,
  selectedName: null,
  activeTab: "entries",

  // transient
  busy: false,
});

let idleTimer = null;
const IDLE_MS = 60 * 60 * 1000;

export function bumpIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    lock("已自动锁定（60 分钟无活动）");
  }, IDLE_MS);
}

/** Lock the vault: wipe in-memory secrets. */
export function lock(reason) {
  clearHandle();
  state.unlocked = false;
  state.masterPw = "";
  state.currentVersion = 0;
  state.dirty = false;
  state.selectedName = null;
  state.activeTab = "entries";
  if (reason) {
    // surfaced by caller via message
    state._lockReason = reason;
  }
}

/** Persist connection prefs (token + api url). Master pw never saved. */
export function persistConn() {
  if (state.apiUrl) localStorage.setItem(LS_API, state.apiUrl);
  if (state.token) localStorage.setItem(LS_TOKEN, state.token);
}

export function markDirty(v) {
  state.dirty = v;
}
