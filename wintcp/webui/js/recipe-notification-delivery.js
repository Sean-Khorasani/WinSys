const STORAGE_KEY = "wintcp.recipe-notification-delivery.v1";
const LOCK_NAME = "wintcp-recipe-notification-delivery";
const PAGE_SIZE = 500;
const MAX_PAGES = 64;

function readCheckpoint(storage) {
  try {
    const value = JSON.parse(storage.getItem(STORAGE_KEY) || "null");
    if (!value || value.version !== 1 || typeof value.cursor !== "string" ||
        !Array.isArray(value.ids)) return null;
    return {
      cursor: value.cursor,
      initialized: value.initialized === true,
      ids: value.ids.filter((id) =>
        typeof id === "string" && id.length <= 256).slice(-5000),
    };
  } catch {
    return null;
  }
}

function writeCheckpoint(storage, cursor, initialized, ids) {
  try {
    storage.setItem(STORAGE_KEY, JSON.stringify({
      version: 1,
      cursor,
      initialized,
      ids: [...ids].slice(-5000),
    }));
  } catch {
    // Browser storage is only a duplicate-suppression aid. The engine inbox is
    // the durable source of truth and remains available if storage is blocked.
  }
}

async function withDeliveryLock(work, storage, owner) {
  if (globalThis.navigator?.locks?.request) {
    await navigator.locks.request(LOCK_NAME, { ifAvailable: true }, async (lock) => {
      if (lock) await work();
    });
    return;
  }

  // Fallback for browsers without Web Locks: short best-effort local lease.
  // The persisted ID checkpoint and Notification.tag remain a second guard.
  const leaseKey = `${STORAGE_KEY}.lease`;
  const now = Date.now();
  try {
    const lease = JSON.parse(storage.getItem(leaseKey) || "null");
    if (lease && lease.owner !== owner && lease.expires > now) return;
    storage.setItem(leaseKey, JSON.stringify({ owner, expires: now + 60000 }));
    const claimed = JSON.parse(storage.getItem(leaseKey) || "null");
    if (claimed?.owner !== owner) return;
  } catch {
    // Continue best-effort if storage itself is unavailable.
    await work();
    return;
  }
  try {
    await work();
  } finally {
    try {
      const lease = JSON.parse(storage.getItem(leaseKey) || "null");
      if (lease?.owner === owner) storage.removeItem(leaseKey);
    } catch { /* no durable lease to release */ }
  }
}

export function createRecipeNotificationDelivery({
  api,
  enabled,
  permitted,
  notify,
  storage = globalThis.localStorage,
  owner = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`,
}) {
  let inFlight = false;

  async function poll() {
    if (inFlight || !api?.get || !storage) return;
    inFlight = true;
    try {
      await withDeliveryLock(async () => {
        let checkpoint = readCheckpoint(storage);
        let cursor = checkpoint?.cursor || "";
        let initialized = checkpoint?.initialized === true;
        const seen = new Set(checkpoint?.ids || []);
        const newlyObserved = [];
        let recoveredRotation = false;
        let reachedTail = false;

        for (let pageNumber = 0; pageNumber < MAX_PAGES; pageNumber++) {
          let page;
          try {
            const query = `?limit=${PAGE_SIZE}` +
              (cursor ? `&cursor=${encodeURIComponent(cursor)}` : "");
            page = await api.get(`/api/engine/notifications${query}`);
          } catch (error) {
            if (error?.status === 410 && cursor) {
              // A rotated segment invalidates the cursor. Re-baseline retained
              // history instead of turning old rows into a notification storm.
              cursor = "";
              seen.clear();
              recoveredRotation = true;
              pageNumber = -1;
              continue;
            }
            return;
          }

          for (const notice of page.items || []) {
            if (typeof notice.id !== "string" || !notice.id) continue;
            if (initialized && !recoveredRotation && !seen.has(notice.id))
              newlyObserved.push(notice);
            seen.add(notice.id);
          }
          cursor = typeof page.nextCursor === "string" ? page.nextCursor : cursor;
          if (!page.hasMore) {
            reachedTail = true;
            break;
          }
        }

        const mayDeliver = initialized && reachedTail && !recoveredRotation;
        if (reachedTail) initialized = true;
        // Persist first, before invoking browser UI. Duplicate notifications
        // are less useful than a missed toast; the durable inbox is unchanged.
        writeCheckpoint(storage, cursor, initialized, seen);
        if (!mayDeliver || !enabled() || !permitted()) return;

        // The cursor stream is oldest-first. Cap burst delivery while retaining
        // all rows in the inbox and checkpoint so the page never storms.
        for (const notice of newlyObserved.slice(-3)) {
          try { notify(notice); } catch { /* inbox remains the fallback */ }
        }
      }, storage, owner);
    } finally {
      inFlight = false;
    }
  }

  return { poll };
}
