// legacy/automations.js - Automation parser, runner, monitor rules
// Moved from app.js as-is during the strangler migration.
// The parser, grammar, limits, permit logic and templates are unchanged.

export function parseScript(source) {
  if (!source || source.length > 8192) return { error: "Script too large (max 8 KiB)" };
  const lines = source.split("\n");
  if (lines.length > 200) return { error: "Too many lines (max 200)" };

  const statements = [];
  const errors = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;

    if (line.startsWith("let ")) {
      const m = line.match(/^let\s+(\w+)\s*=\s*(.+)$/);
      if (!m) { errors.push(`Line ${i + 1}: invalid let`); continue; }
      statements.push({ type: "let", name: m[1], command: m[2], line: i + 1 });
    } else if (line.startsWith("run ")) {
      statements.push({ type: "run", command: line.slice(4).trim(), line: i + 1 });
    } else if (line.startsWith("set ")) {
      const m = line.match(/^set\s+(\w+)\s*=\s*(.+)$/);
      if (!m) { errors.push(`Line ${i + 1}: invalid set`); continue; }
      statements.push({ type: "set", name: m[1], value: m[2], line: i + 1 });
    } else if (line.startsWith("print ")) {
      statements.push({ type: "print", value: line.slice(6).trim(), line: i + 1 });
    } else if (line === "if") {
      statements.push({ type: "if", line: i + 1 });
    } else if (line === "else") {
      statements.push({ type: "else", line: i + 1 });
    } else if (line === "end") {
      statements.push({ type: "end", line: i + 1 });
    } else {
      statements.push({ type: "command", command: line, line: i + 1 });
    }
  }

  if (errors.length) return { error: errors.join("; ") };
  if (statements.length > 100) return { error: "Too many statements (max 100)" };
  return { statements };
}

export function isSensitiveCommand(verb, args) {
  const sensitive = ["kill", "close", "block", "unblock", "capture"];
  if (sensitive.includes(verb)) {
    if (!args.includes("--dry-run")) return true;
  }
  if (args.includes("--yes") || args.includes("-y") || args.includes("--force")) return true;
  if (verb === "export" || args.includes("--out")) return true;
  if (["bookmark", "preset"].includes(verb)) {
    const mutating = ["add", "remove", "delete", "note", "colour", "save", "import"];
    if (mutating.some(m => args.includes(m))) return true;
  }
  return false;
}
