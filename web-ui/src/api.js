// HTTP helpers for the vault server. All requests carry the bearer token from
// the global store. Master key never appears here — it stays in WASM memory.

import { state } from "./store.js";

/** Infer the API endpoint from the current page URL.
 *  /keychain/        → origin + /keychain/vault
 *  /keychain/index.html → origin + /keychain/vault
 *  /                 → origin + /vault
 */
export function autoDetectApi() {
  const path = location.pathname.replace(/index\.html$/, "").replace(/\/$/, "");
  return `${location.origin}${path}/vault`;
}

function apiUrl() {
  return (state.apiUrl || "").trim().replace(/\/$/, "");
}

function authHeader() {
  return { authorization: `Bearer ${(state.token || "").trim()}` };
}

export async function apiGet(suffix = "") {
  const url = apiUrl() + suffix;
  const res = await fetch(url, { headers: authHeader() });
  return { res, url };
}

export async function apiPost(suffix, body) {
  const url = apiUrl() + suffix;
  const res = await fetch(url, {
    method: "POST",
    headers: { ...authHeader(), "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  return { res, url };
}

export async function apiPut(body, ifMatch) {
  const url = apiUrl();
  const res = await fetch(url, {
    method: "PUT",
    headers: {
      ...authHeader(),
      "content-type": "application/json",
      "if-match": String(ifMatch),
    },
    body: JSON.stringify(body),
  });
  return { res, url };
}
