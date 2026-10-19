export function createPoller(callback, intervalMs = 2000) {
  let timer = null;
  let running = false;
  let inFlight = false;
  let generation = 0;
  let currentInterval = intervalMs;
  let consecutiveErrors = 0;

  function cancelTimer() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
  }

  function schedule(delay) {
    cancelTimer();
    if (!running || document.hidden || inFlight) return;
    timer = setTimeout(tick, delay);
  }

  async function tick() {
    timer = null;
    if (!running || document.hidden || inFlight) return;
    inFlight = true;
    const mine = generation;
    try {
      await callback();
      consecutiveErrors = 0;
      currentInterval = intervalMs;
    } catch (err) {
      consecutiveErrors++;
      currentInterval = Math.min(intervalMs * Math.pow(2, consecutiveErrors), 30000);
      // Say something. A bare catch here silently swallowed a ReferenceError
      // thrown by the refresh callback for an entire session: the UI reported
      // "Live" and simply stopped updating, with nothing in the console.
      if (consecutiveErrors === 1 || consecutiveErrors % 10 === 0) {
        console.warn(
          `poller: callback failed (${consecutiveErrors} in a row), retrying in ` +
          `${Math.round(currentInterval / 1000)}s: ${err && err.message ? err.message : err}`,
        );
      }
    } finally {
      inFlight = false;
      schedule(mine === generation ? currentInterval : 0);
    }
  }

  function start() {
    if (running) return;
    running = true;
    generation++;
    schedule(0);
  }

  function stop() {
    running = false;
    generation++;
    cancelTimer();
  }

  function setInterval_(ms) {
    if (!Number.isFinite(ms) || ms <= 0) return;
    intervalMs = ms;
    currentInterval = ms;
    schedule(currentInterval);
  }

  const onVisibility = () => {
    generation++;
    cancelTimer();
    if (!document.hidden) schedule(0);
  };
  document.addEventListener("visibilitychange", onVisibility);

  return {
    start,
    stop,
    setInterval: setInterval_,
    destroy() {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    },
  };
}
