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
        ...(options.body && { "Content-Type": "application/json" }),
        ...options.headers,
      },
    });
    clearTimeout(timeout);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}: ${text}`);
    }
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
};
