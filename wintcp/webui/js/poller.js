// poller.js - Visibility-aware poller with backoff

export function createPoller(callback, intervalMs = 2000) {
  let timer = null;
  let running = false;
  let currentInterval = intervalMs;
  let consecutiveErrors = 0;

  async function tick() {
    if (!running) return;
    try {
      await callback();
      consecutiveErrors = 0;
      currentInterval = intervalMs;
    } catch {
      consecutiveErrors++;
      // Exponential backoff: 2s, 4s, 8s, 16s, max 30s
      currentInterval = Math.min(intervalMs * Math.pow(2, consecutiveErrors), 30000);
    }
    if (running) {
      timer = setTimeout(tick, currentInterval);
    }
  }

  function start() {
    if (running) return;
    running = true;
    tick();
  }

  function stop() {
    running = false;
    if (timer) clearTimeout(timer);
    timer = null;
  }

  function setInterval_(ms) {
    intervalMs = ms;
    currentInterval = ms;
  }

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      // Pause when hidden
      if (timer) clearTimeout(timer);
    } else {
      // Resume when visible
      if (running) tick();
    }
  });

  return { start, stop, setInterval: setInterval_ };
}
