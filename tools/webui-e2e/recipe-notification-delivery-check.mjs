import assert from "node:assert/strict";
import { chromium } from "@playwright/test";

const urlArg = process.argv.find((arg) => arg.startsWith("--url="))?.slice(6);
const urlIndex = process.argv.indexOf("--url");
const baseUrl = urlArg || (urlIndex >= 0 ? process.argv[urlIndex + 1] : "");
if (!baseUrl) throw new Error("Usage: node recipe-notification-delivery-check.mjs --url http://127.0.0.1:PORT/");

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  const result = await page.evaluate(async () => {
    const { api: liveApi } = await import("/js/api.js");
    const livePage = await liveApi.get("/api/engine/notifications?limit=1");
    const { createRecipeNotificationDelivery } = await import(
      "/js/recipe-notification-delivery.js");
    class MemoryStorage {
      values = new Map();
      getItem(key) { return this.values.get(key) ?? null; }
      setItem(key, value) { this.values.set(key, String(value)); }
      removeItem(key) { this.values.delete(key); }
    }
    const storage = new MemoryStorage();
    const delivered = [];
    let rows = [
      { id: "epoch:notification-1", message: "old notice" },
      { id: "epoch:notification-2", message: "older retained notice" },
    ];
    let streamCursor = "cursor-tail";
    const api = { async get(path) {
      const query = new URL(path, location.href).searchParams;
      const requested = query.get("cursor") || "";
      if (!requested) {
        return { items: rows.slice(0, 1), nextCursor: "cursor-1", hasMore: true };
      }
      if (requested === "cursor-1") {
        return { items: rows.slice(1), nextCursor: "cursor-tail", hasMore: false };
      }
      if (requested === streamCursor) {
        const next = `after:${rows.at(-1)?.id || "empty"}`;
        return { items: rows, nextCursor: next, hasMore: false };
      }
      if (requested.startsWith("after:"))
        return { items: [], nextCursor: requested, hasMore: false };
      return { items: [], nextCursor: requested, hasMore: false };
    } };
    const create = (notify, permitted = () => true) => createRecipeNotificationDelivery({
      api, storage, enabled: () => true, permitted, notify,
    });
    const pollUntil = async (delivery, predicate) => {
      for (let attempt = 0; attempt < 40; attempt++) {
        await delivery.poll();
        if (predicate()) return true;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      return false;
    };
    const first = create((item) => delivered.push(item.id), () => false);
    await pollUntil(first, () => storage.getItem("wintcp.recipe-notification-delivery.v1") !== null);
    // Initial history is a silent baseline.
    const saved = () => JSON.parse(storage.getItem("wintcp.recipe-notification-delivery.v1") || "null");
    const savedFirst = saved();
    const initialSuppressed = delivered.length === 0 && savedFirst.initialized &&
      savedFirst.cursor === "cursor-tail";

    streamCursor = "cursor-tail";
    rows = [{ id: "epoch:notification-3", message: "new notice" }];
    const send = create((item) => delivered.push(item.id));
    await pollUntil(send, () => saved()?.cursor === "after:epoch:notification-3");
    const exactlyOnce = delivered.length === 1 && delivered[0] === rows[0].id;

    // When permission is denied, advance the cursor but preserve the durable
    // inbox; granting permission later must not emit a stale backlog.
    streamCursor = "after:epoch:notification-3";
    rows = [{ id: "epoch:notification-4", message: "permission denied" }];
    const denied = create((item) => delivered.push(item.id), () => false);
    await pollUntil(denied, () => saved()?.cursor === "after:epoch:notification-4");
    const afterDenied = delivered.length;
    streamCursor = "after:epoch:notification-4";
    rows = [{ id: "epoch:notification-5", message: "current notice" }];
    await pollUntil(send, () => saved()?.cursor === "after:epoch:notification-5");
    const permissionIndependentInbox = afterDenied === 1 && delivered.length === 2 &&
      delivered[1] === rows[0].id;

    // Separate page instances serialize through the browser's shared lock so
    // the same newly persisted notice cannot produce two toasts.
    streamCursor = "after:epoch:notification-5";
    rows = [{ id: "epoch:notification-6", message: "cross-tab notice" }];
    await Promise.all([
      create((item) => delivered.push(item.id)).poll(),
      create((item) => delivered.push(item.id)).poll(),
    ]);
    await pollUntil(send, () => saved()?.cursor === "after:epoch:notification-6");
    const crossTabOnce = delivered.filter((id) => id === rows[0].id).length === 1;
    return { liveHasMoreField: typeof livePage.hasMore === "boolean",
      initialSuppressed, exactlyOnce, permissionIndependentInbox,
      crossTabOnce, finalDeliveryCount: delivered.length };
  });
  assert.equal(result.liveHasMoreField, true,
    "the live inbox API must expose its bounded-store continuation state");
  assert.equal(result.initialSuppressed, true, "existing inbox rows must seed silently");
  assert.equal(result.exactlyOnce, true, "new rows should deliver once and then deduplicate");
  assert.equal(result.permissionIndependentInbox, true,
    "permission denial must not change durable inbox behavior or replay old rows");
  assert.equal(result.crossTabOnce, true, "concurrent tabs must coordinate browser delivery");
  console.log(`recipe-notification-delivery-check=PASS ${JSON.stringify(result)}`);
} finally {
  await browser.close();
}
