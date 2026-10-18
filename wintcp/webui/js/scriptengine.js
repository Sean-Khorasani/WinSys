// scriptengine.js - WinTCP Script v1 parser and execution engine.
//
// Extracted from the legacy dashboard so the control room's Automations page
// can run scripts without depending on the legacy bundle. The language is a
// deliberately small DSL that shells out to the sibling wintcp.exe:
//
//   let $name = cmd args          # capture output
//   run  cmd args                 # capture output as $last
//   set  $name = "literal"        # string assignment
//   print "text"                  # emit to the script console
//   if $var.exitCode == 0         # branch on exitCode | stdout | stderr | durationMs
//     ...
//   else
//     ...
//   end
//
// Constraints: 8 KiB source, 200 lines, 100 statements, 8-level nesting.

const MAX_SOURCE_BYTES = 8192;
const MAX_LINES = 200;
const MAX_STATEMENTS = 100;
const MAX_NESTING = 8;
export const MAX_STEPS = 100;
const SENSITIVE_VERBS = ["kill", "close", "block", "unblock", "capture"];
const SENSITIVE_FLAGS = ["--yes", "-y", "--force"];

export const STARTER_SCRIPT =
  '# WinTCP Script v1\n' +
  '# One local CLI call, followed by an exit-code branch.\n' +
  'let snapshot = list --format json --filter "state:estab" --limit 25\n' +
  'if snapshot.exitCode == 0\n' +
  '  print "Snapshot captured. Inspect ${snapshot.stdout} in Variables or use it in later commands."\n' +
  'else\n' +
  '  print "CLI exit ${snapshot.exitCode}: ${snapshot.stderr}"\n' +
  'end\n';

function esc(text) {
  const div = typeof document !== "undefined" ? document.createElement("div") : null;
  if (div) {
    div.textContent = String(text);
    return div.innerHTML;
  }
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function scriptTokens(text) {
  const tokens = [];
  let token = "";
  let quote = "";
  let started = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote && c === "\\" && i + 1 < text.length) {
      const next = text[i + 1];
      if (next === quote || next === "\\") {
        token += next;
        i++;
      } else {
        token += c;
      }
      started = true;
    } else if (quote) {
      if (c === quote) quote = "";
      else token += c;
      started = true;
    } else if (c === '"' || c === "'") {
      quote = c;
      started = true;
    } else if (/\s/.test(c)) {
      if (started) {
        tokens.push(token);
        token = "";
        started = false;
      }
    } else {
      token += c;
      started = true;
    }
  }
  if (quote) throw new Error("Unclosed quoted argument.");
  if (started) tokens.push(token);
  return tokens;
}

function scriptLineWithoutComment(line) {
  let quote = "";
  let escaped = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote && c === "\\") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    if (c === "#") return line.slice(0, i);
  }
  return line;
}

function scriptCommand(commandText, line) {
  const words = scriptTokens(commandText);
  if (words[0]?.toLowerCase() === "wintcp.exe" || words[0]?.toLowerCase() === "wintcp")
    words.shift();
  if (!words.length || !/^[A-Za-z][A-Za-z0-9-]*$/.test(words[0]))
    throw new Error(`Line ${line}: expected a WinTCP CLI verb and arguments.`);
  const command = {
    type: "command",
    verb: words[0].toLowerCase(),
    args: words.slice(1),
    line,
    source: commandText.trim(),
  };
  if (isSensitiveCli([command.verb, ...command.args]) &&
      command.args.some((arg) => /\$\{/.test(arg)))
    throw new Error(
      `Line ${line}: sensitive command arguments cannot use variable substitution; write the reviewed target literally.`,
    );
  return command;
}

export function isSensitiveCli(argv) {
  const verb = String(argv[0] || "").toLowerCase();
  const args = argv.slice(1).map((v) => String(v).toLowerCase());
  const dryRun = args.includes("--dry-run");
  if (!dryRun && SENSITIVE_VERBS.includes(verb)) return true;
  if (args.some((v) => SENSITIVE_FLAGS.includes(v))) return true;
  if (verb === "export" || args.includes("--out")) return true;
  if (["bookmark", "preset"].includes(verb) &&
      ["add", "remove", "delete", "note", "colour", "save", "import"].includes(args[0]))
    return true;
  if (verb === "alert" && args.some((v) =>
      ["--enable", "--disable", "--on-listener", "--off-listener", "--on-connection",
        "--off-connection", "--on-rst", "--off-rst", "--on-closed", "--off-closed",
        "--rule-on-new", "--rule-off-new", "--rule-on-close", "--rule-off-close",
        "--rule-on-threshold", "--bps-warn", "--bps-critical", "--connections",
        "--rule-name", "--rule-address", "--rule-process"].includes(v)))
    return true;
  return false;
}

function parseScriptCondition(text, line) {
  let match = /^if\s+([A-Za-z_][A-Za-z0-9_]*)\.exitCode\s*(==|!=|>=|<=|>|<)\s*(\d+)$/i.exec(text);
  if (match)
    return {
      variable: match[1],
      property: "exitCode",
      operator: match[2],
      value: Number(match[3]),
    };
  match = /^if\s+([A-Za-z_][A-Za-z0-9_]*)\.(stdout|stderr)\s+contains\s+("(?:\\.|[^"\\])*")$/i.exec(text);
  if (match) {
    let value;
    try {
      value = JSON.parse(match[3]);
    } catch {
      throw new Error(`Line ${line}: the contains value must be a valid double-quoted string.`);
    }
    return {
      variable: match[1],
      property: match[2].toLowerCase(),
      operator: "contains",
      value,
    };
  }
  throw new Error(
    `Line ${line}: use if name.exitCode == 0 (or another numeric comparison), or if name.stdout contains "text".`,
  );
}

export function parseScript(text) {
  if (typeof text !== "string")
    throw new Error("Script source must be a string.");
  if (new TextEncoder().encode(text).length > MAX_SOURCE_BYTES)
    throw new Error("Script source must be no more than 8 KiB of UTF-8.");
  const lines = text.split(/\r?\n/);
  if (lines.length > MAX_LINES)
    throw new Error("Scripts are limited to 200 lines.");
  const program = [];
  const stack = [];
  let current = program;
  let statements = 0;
  let commands = 0;
  for (let index = 0; index < lines.length; index++) {
    const lineNumber = index + 1;
    const source = scriptLineWithoutComment(lines[index]).trim();
    if (!source) continue;
    if (/^else$/i.test(source)) {
      const frame = stack[stack.length - 1];
      if (!frame || frame.node.otherwise)
        throw new Error(`Line ${lineNumber}: else must appear once inside an if block.`);
      frame.node.otherwise = [];
      current = frame.node.otherwise;
      continue;
    }
    if (/^end$/i.test(source)) {
      const frame = stack.pop();
      if (!frame) throw new Error(`Line ${lineNumber}: end has no matching if.`);
      current = frame.parent;
      continue;
    }
    if (/^if\b/i.test(source)) {
      if (stack.length >= MAX_NESTING)
        throw new Error(`Line ${lineNumber}: if nesting is limited to 8 levels.`);
      const node = {
        type: "if",
        condition: parseScriptCondition(source, lineNumber),
        then: [],
        otherwise: null,
        line: lineNumber,
      };
      current.push(node);
      stack.push({ node, parent: current });
      current = node.then;
      statements++;
    } else {
      let node = null;
      let match = /^let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/i.exec(source);
      if (match) {
        node = scriptCommand(match[2], lineNumber);
        node.assign = match[1];
      } else if ((match = /^run\s+(.+)$/i.exec(source))) {
        node = scriptCommand(match[1], lineNumber);
        node.assign = "last";
      } else if ((match = /^set\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/i.exec(source))) {
        let value = match[2].trim();
        if (
          (value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))
        ) {
          const pieces = scriptTokens(value);
          if (pieces.length !== 1)
            throw new Error(`Line ${lineNumber}: set accepts one quoted string or plain text.`);
          value = pieces[0];
        }
        node = { type: "set", name: match[1], value, line: lineNumber };
      } else if ((match = /^print\s+(.+)$/i.exec(source))) {
        let value = match[1].trim();
        if (
          (value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))
        ) {
          const pieces = scriptTokens(value);
          if (pieces.length !== 1)
            throw new Error(`Line ${lineNumber}: print accepts one quoted string or plain text.`);
          value = pieces[0];
        }
        node = { type: "print", value, line: lineNumber };
      } else {
        throw new Error(
          `Line ${lineNumber}: unknown statement. Use let, run, set, print, if, else, or end.`,
        );
      }
      current.push(node);
      statements++;
      if (node.type === "command") commands++;
    }
    if (statements > MAX_STATEMENTS)
      throw new Error("Scripts are limited to 100 statements.");
  }
  if (stack.length) {
    const frame = stack[stack.length - 1];
    throw new Error(`Line ${frame.node.line}: if block is missing end.`);
  }
  if (!statements) throw new Error("Add at least one command, assignment, print, or if statement.");
  return { program, statements, commands };
}

export function scriptCommandNodes(nodes, result = []) {
  for (const node of nodes) {
    if (node.type === "command") result.push(node);
    else if (node.type === "if") {
      scriptCommandNodes(node.then, result);
      if (node.otherwise) scriptCommandNodes(node.otherwise, result);
    }
  }
  return result;
}

export function interpolateScript(text, variables) {
  return String(text).replace(
    /\$\{([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*))?\}/g,
    (_match, name, property) => {
      if (!Object.prototype.hasOwnProperty.call(variables, name))
        throw new Error(`Variable '${name}' has not been assigned.`);
      const value = variables[name];
      if (!property)
        return value && typeof value === "object" ? JSON.stringify(value) : String(value);
      const known = property === "exitCode" || property === "stdout" ||
                  property === "stderr" || property === "durationMs";
      if (!known)
        throw new Error(`Variable '${name}' has no '${property}' value.`);
      if (!value || typeof value !== "object" || !(property in value))
        throw new Error(`Variable '${name}' has no '${property}' value.`);
      return String(value[property] ?? "");
    },
  );
}

export function evaluateScriptCondition(condition, variables) {
  if (!Object.prototype.hasOwnProperty.call(variables, condition.variable))
    throw new Error(`Variable '${condition.variable}' has not been assigned.`);
  const value = variables[condition.variable]?.[condition.property];
  if (value == null)
    throw new Error(`Variable '${condition.variable}.${condition.property}' has no '${condition.value}' value.`);
  if (condition.operator === "contains")
    return String(value).includes(condition.value);
  const left = Number(value);
  const right = Number(condition.value);
  if (!Number.isFinite(left))
    throw new Error(`Variable '${condition.variable}.${condition.property}' is not numeric.`);
  return ({
    "==": left === right,
    "!=": left !== right,
    ">": left > right,
    "<": left < right,
    ">=": left >= right,
    "<=": left <= right,
  })[condition.operator];
}

export function cliForm(verb, args, extra = {}) {
  const body = new URLSearchParams();
  body.set("verb", verb);
  body.set("argc", String(args.length));
  args.forEach((value, index) => body.set(`arg${index}`, value));
  for (const [key, value] of Object.entries(extra)) body.set(key, value);
  return body;
}

export function displayCliArg(value) {
  return /^[A-Za-z0-9_./:\\-]+$/.test(value) ? value : JSON.stringify(value);
}

export function scriptCommandDisplay(node) {
  return `wintcp.exe ${[node.verb, ...node.args].map(displayCliArg).join(" ")}`;
}

export function escapeHtml(text) {
  return esc(text);
}
