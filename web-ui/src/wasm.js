// WASM bridge: lazy-init the module once, then expose unlock/put/rekey.
// The VaultHandle lives in module scope; only one unlocked vault at a time.

import init, { unlock, VaultHandle } from "../public/pkg/vault_wasm.js";

let inited = false;
let handle = null;

async function ensureInit() {
  if (!inited) {
    await init();
    inited = true;
  }
}

/** Decrypt a snapshot. Returns the VaultHandle (also cached module-side). */
export async function doUnlock(password, snapshotJson) {
  await ensureInit();
  handle = unlock(password, snapshotJson);
  return handle;
}

export function getHandle() {
  return handle;
}

export function clearHandle() {
  handle = null;
}

/** Serialize current entries to a VaultWrite JSON object (encrypted). */
export function putEntries() {
  if (!handle) throw new Error("vault not unlocked");
  return JSON.parse(handle.put_entries());
}

/** Re-wrap CEK under a new master password → VaultRekey JSON. */
export function rekeyHandle(newPassword) {
  if (!handle) throw new Error("vault not unlocked");
  return JSON.parse(handle.rekey(newPassword));
}

/** Get all entries as a plain JS array (deep clone via JSON). */
export function allEntries() {
  if (!handle) return [];
  return JSON.parse(JSON.stringify(handle.all()));
}

/** Replace in-memory entries with the given array. */
export function setEntries(arr) {
  if (!handle) throw new Error("vault not unlocked");
  handle.set_entries(arr);
}

export function searchEntries(q) {
  if (!handle) return [];
  return handle.search(q);
}

export function entryCount() {
  return handle ? handle.count() : 0;
}
