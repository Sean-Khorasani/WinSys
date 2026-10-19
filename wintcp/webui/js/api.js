// api.js - API client with token header, errors, abort/timeouts

import { normalizeConnections } from "./connections.js";

const TOKEN_META = document.querySelector('meta[name="wintcp-api-token"]');
const TOKEN = TOKEN_META ? TOKEN_META.content : "";
let configQueue = Promise.resolve();
const configListeners = new Set();
const configChannel = typeof BroadcastChannel === "function"
  ? new BroadcastChannel("wintcp-config-updates")
  : null;
configChannel?.addEventListener("message", (event) => {
  if (event.data?.type !== "updated") return;
  for (const listener of configListeners) {
    try { listener(); } catch (error) { console.warn("config update listener failed", error); }
  }
});

async function request(path, options = {}) {
  const { responseMeta = false, raw = false, timeout: timeoutMs = 10000,
    signal, ...fetchOptions } = options;
  const controller = new AbortController();
  let timedOut = false;
  const cancel = () => controller.abort(signal.reason);
  if (signal?.aborted) cancel();
  else signal?.addEventListener("abort", cancel, { once: true });
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    const res = await fetch(path, {
      ...fetchOptions,
      signal: controller.signal,
      headers: {
        "X-WinTCP-Token": TOKEN,
        ...(options.body && !(options.body instanceof URLSearchParams) && {
          "Content-Type": "application/json",
        }),
        ...options.headers,
      },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      let body;
      try { body = JSON.parse(text); } catch { body = text; }
      const error = new Error(`HTTP ${res.status}: ${body?.error || body?.message || text}`);
      error.status = res.status;
      error.body = body;
      error.headers = res.headers;
      if (res.status === 403 && body?.error === "mutation authorization failed") {
        window.dispatchEvent(new CustomEvent("wintcp:session-expired"));
      }
      throw error;
    }
    // JSON-parse unless the caller asked for raw text.
    if (raw) return await res.text();
    const data = await res.json();
    if (responseMeta) return { data, etag: res.headers.get("ETag") };
    return path.split("?")[0] === "/api/connections" ? normalizeConnections(data) : data;
  } catch (err) {
    if (timedOut) throw new Error("Request timed out");
    throw err;
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", cancel);
  }
}

export const api = {
  get: (path, options = {}) => request(path, options),
  post: (path, body, options = {}) => request(path, { ...options, method: "POST", body: JSON.stringify(body) }),
  subscribeConfigChanges: (listener) => {
    if (typeof listener !== "function") return () => {};
    configListeners.add(listener);
    return () => configListeners.delete(listener);
  },
  updateConfig: (update) => {
    const operation = configQueue.catch(() => {}).then(async () => {
      for (let attempt = 0; attempt < 3; attempt++) {
        const { data: current, etag } = await request("/api/config", { responseMeta: true });
        if (!etag) throw new Error("Configuration revisions are unavailable. Update or restart the dashboard before saving.");
        const next = update(current);
        try {
          const { etag: savedEtag } = await api.post("/api/config", next, {
            headers: { "If-Match": etag }, responseMeta: true,
          });
          configChannel?.postMessage({ type: "updated", etag: savedEtag });
          return next;
        } catch (error) {
          if (error.status !== 412) throw error;
        }
      }
      const error = new Error("Configuration kept changing in another session. Your changes are not saved; please retry.");
      error.status = 412;
      throw error;
    });
    configQueue = operation;
    return operation;
  },
  postForm: (path, body, options = {}) =>
    request(path, {
      ...options,
      method: "POST",
      body:
        body instanceof URLSearchParams
          ? body
          : new URLSearchParams(body).toString(),
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }),
  raw: (path, options = {}) => request(path, { ...options, raw: true }),
  upload: (path, blob, filename, options = {}) => request(path, {
      ...options,
      method: "POST",
      timeout: 60000,
      headers: {
        "X-Filename": filename,
        "Content-Type": "application/octet-stream",
      },
      body: blob,
    }),
};
