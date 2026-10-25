import assert from "node:assert/strict";
import { chromium } from "@playwright/test";

const urlArg = process.argv.find((arg) => arg.startsWith("--url="))?.slice(6);
const urlIndex = process.argv.indexOf("--url");
const baseUrl = urlArg || (urlIndex >= 0 ? process.argv[urlIndex + 1] : "");
if (!baseUrl) throw new Error("Usage: node recipe-schedule-check.mjs --url http://127.0.0.1:PORT/");

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  const result = await page.evaluate(async () => {
    const { api } = await import("/js/api.js");
    const hex = (value) => Array.from(new TextEncoder().encode(value),
      (byte) => byte.toString(16).padStart(2, "0")).join("");
    const operation = async (fields) => {
      const submitted = await api.postForm("/api/engine/recipes", {
        requestId: crypto.randomUUID().replaceAll("-", ""), ...fields,
      });
      for (let attempt = 0; attempt < 40; attempt++) {
        const current = await api.get(`/api/engine/operations/${submitted.operationId}`);
        if (current.status === "succeeded") return current;
        if (current.status === "failed") throw new Error(current.error?.code || "recipe operation failed");
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      throw new Error("recipe operation timed out");
    };
    const empty = await api.get("/api/engine/recipes");
    if (empty.items.length !== 0)
      throw new Error("precondition failed: recipe store is not empty; refusing to mutate it");
    const invalidText = "WinTCP-Recipes:2\nschedule-check|1|0|outbound_activity|60|" +
      `${hex("Schedule check")}|${hex("C:\\Windows\\System32\\notepad.exe")}|` +
      `weekly_window|127|0|1439|${hex("Not a Windows time zone")}\n`;
    let invalidZoneRejected = false;
    let invalidSubmission = null;
    try {
      invalidSubmission = await api.postForm("/api/engine/recipes", {
        requestId: crypto.randomUUID().replaceAll("-", ""),
        expectedRevision: empty.revision, recipesText: invalidText,
      });
    } catch (error) {
      invalidZoneRejected = error.body?.code === "invalid_time_zone_id";
    }
    if (!invalidZoneRejected) {
      if (invalidSubmission?.operationId) {
        for (let attempt = 0; attempt < 40; attempt++) {
          const current = await api.get(`/api/engine/operations/${invalidSubmission.operationId}`);
          if (current.status === "succeeded" || current.status === "failed") break;
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
      const contaminated = await api.get("/api/engine/recipes");
      if (contaminated.items.length)
        await operation({ expectedRevision: contaminated.revision,
          recipesText: "WinTCP-Recipes:2\n" });
      throw new Error("unknown Windows time-zone ID was not rejected");
    }

    let created = false;
    let creationError = null;
    try {
      const currentMinute = Math.floor(Date.now() / 60000) % 1440;
      const windowStart = (currentMinute + 1439) % 1440;
      const windowEnd = (currentMinute + 1) % 1440;
      const current = await api.get("/api/engine/recipes");
      const text = "WinTCP-Recipes:2\nschedule-check|1|0|outbound_activity|60|" +
        `${hex("Schedule check")}|${hex("C:\\Windows\\System32\\notepad.exe")}|` +
        `weekly_window|127|${windowStart}|${windowEnd}|${hex("UTC")}\n`;
      await operation({ expectedRevision: current.revision, recipesText: text });
      created = true;
      const saved = await api.get("/api/engine/recipes");
      const row = saved.items.find((item) => item.id === "schedule-check");
      if (!row) throw new Error("scheduled recipe did not appear in the engine API");
      if (row.schedule?.type !== "weekly_window" || row.schedule.timeZoneId !== "UTC" ||
          row.schedule.daysMask !== 127 || row.schedule.startMinute !== windowStart ||
          row.schedule.endMinute !== windowEnd)
        throw new Error("schedule fields did not round-trip through the API");
      if (row.runtime?.scheduleTimeZoneAvailable !== true ||
          row.runtime?.scheduleActive !== true)
        throw new Error("valid UTC schedule was not available and active at the current UTC time");
      const transitionMs = Number(row.runtime?.nextScheduleTransitionUtcMs);
      if (!Number.isFinite(transitionMs) || transitionMs <= Date.now() ||
          typeof row.runtime?.scheduleActiveAfterTransition !== "boolean" ||
          row.runtime?.scheduleLeaseReleaseState !== "window_active")
        throw new Error("runtime did not expose the next UTC transition and lease state");
      const enabledText = "WinTCP-Recipes:2\nschedule-check|2|1|outbound_activity|60|" +
        `${hex("Schedule check")}|${hex("C:\\Windows\\System32\\notepad.exe")}|` +
        `weekly_window|127|${windowStart}|${windowEnd}|${hex("UTC")}\n`;
      const latest = await api.get("/api/engine/recipes");
      await operation({ expectedRevision: latest.revision, recipesText: enabledText });
      let windowExitState = "";
      for (let attempt = 0; attempt < 145; attempt++) {
        const currentState = await api.get("/api/engine/recipes");
        const live = currentState.items.find((item) => item.id === "schedule-check");
        if (live?.runtime?.scheduleActive === false &&
            ["released", "error"].includes(live.runtime.scheduleLeaseReleaseState)) {
          windowExitState = live.runtime.scheduleLeaseReleaseState;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      if (!windowExitState)
        throw new Error("leaving the weekly window did not complete/report recipe lease release");
    } catch (error) {
      creationError = error;
    } finally {
      const current = await api.get("/api/engine/recipes");
      if (current.items.some((item) => item.id === "schedule-check")) {
        await operation({ expectedRevision: current.revision,
          recipesText: "WinTCP-Recipes:2\n" });
      }
      const final = await api.get("/api/engine/recipes");
      if (final.items.length !== 0)
        throw new Error("cleanup failed: test recipe remains in the store");
    }
    if (creationError) throw creationError;
    return { invalidZoneRejected, validZoneAvailable: true,
      scheduleRoundTrip: true, scheduleActive: true,
      nextTransition: true, windowExitHandled: true,
      fixtureRemoved: true };
  });
  const automationsUrl = new URL(baseUrl);
  automationsUrl.hash = "/automations";
  await page.goto(automationsUrl.toString(), { waitUntil: "domcontentloaded" });
  await page.getByRole("tab", { name: "Monitors" }).click();
  await page.getByRole("button", { name: "Add disabled monitor" }).waitFor();
  const schedule = page.getByLabel("Schedule");
  await schedule.selectOption("weekly_window");
  const weekdayControl = page.locator('select[aria-label="Days when this monitor is active"]');
  assert.equal(await weekdayControl.isVisible(), true,
    "weekday controls should appear only for a scheduled window");
  assert.equal(await page.locator('input[placeholder="e.g. Pacific Standard Time"]').inputValue(), "UTC",
    "new schedule editor should start with the portable UTC zone");
  await schedule.selectOption("always");
  assert.equal(await weekdayControl.isVisible(), false,
    "weekday controls should hide for Always");
  assert.equal(result.fixtureRemoved, true);
  console.log(`recipe-schedule-check=PASS ${JSON.stringify({ ...result, editor: true })}`);
} finally {
  await browser.close();
}
