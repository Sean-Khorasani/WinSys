// api.js - API client with token header, errors, abort/timeouts

const TOKEN_META = document.querySelector('meta[name="wintcp-api-token"]');
const TOKEN = TOKEN_META ? TOKEN_META.content : "";

async function request(path, options = {}) {
  const url = path.startsWith("http") ? path : path;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeout || 10000);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "X-WinTCP-Token": TOKEN,
        ...(options.body && !(options.body instanceof URLSearchParams) && {
          "Content-Type": "application/json",
        }),
        ...options.headers,
      },
    });
    clearTimeout(timeout);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}: ${text}`);
    }
    // JSON-parse unless the caller asked for raw text.
    if (options.raw) return await res.text();
    return await res.json();
  } catch (err) {
    clearTimeout(timeout);
    if (err.name === "AbortError") throw new Error("Request timed out");
    throw err;
  }
}

export const api = {
  get: (path) => request(path),
  post: (path, body) => request(path, { method: "POST", body: JSON.stringify(body) }),
  postForm: (path, body) =>
    request(path, {
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
  upload: (path, blob, filename) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000);
    return fetch(path, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "X-WinTCP-Token": TOKEN,
        "X-Filename": filename,
        "Content-Type": "application/octet-stream",
      },
      body: blob,
    }).then((res) => {
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
      return res.json();
    }).finally(() => clearTimeout(timeout));
  },
};
