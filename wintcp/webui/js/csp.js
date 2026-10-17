// csp.js - Content-Security-Policy violation reporter.
//
// The server sends a CSP with no 'unsafe-inline' and no 'unsafe-eval'. Any
// violation means the UI tried to do something the policy forbids: an inline
// handler, an eval, a remote origin. In a shipped build that is a silent bug;
// during development and in the Playwright run it must be a LOUD failure, so
// every violation is recorded where a test can assert on it and also logged.
//
// This is additive and weakens nothing: adding a listener does not relax the
// policy the server already sent.

/** @type {Array<{effectiveDirective: string, blockedURI: string, violatedDirective: string, sourceFile: string, lineNumber: number, sample: string}>} */
const violations = [];

// Exposed on window so an end-to-end run can read it without touching the UI.
globalThis.__wintcpCspViolations = violations;

export function installCspReporter() {
  document.addEventListener("securitypolicyviolation", (event) => {
    const record = {
      effectiveDirective: event.effectiveDirective || "",
      violatedDirective: event.violatedDirective || "",
      blockedURI: event.blockedURI || "",
      sourceFile: event.sourceFile || "",
      lineNumber: event.lineNumber || 0,
      sample: (event.sample || "").slice(0, 200),
    };
    violations.push(record);
    // console.error, not warn: the e2e run treats any console error as a failure
    // and a CSP violation must never be something a reviewer can scroll past.
    console.error(
      `CSP violation: ${record.violatedDirective || record.effectiveDirective} blocked "${record.blockedURI}"`,
      `${record.sourceFile}:${record.lineNumber}`,
    );
  });
}

export function cspViolations() {
  return violations.slice();
}