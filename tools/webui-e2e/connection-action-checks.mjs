import { spawn } from "node:child_process";
import dgram from "node:dgram";
import net from "node:net";

const urlIndex = process.argv.indexOf("--url");
const baseUrl = urlIndex >= 0 ? process.argv[urlIndex + 1] : "";
if (!baseUrl) throw new Error("Pass --url with the isolated dashboard URL");
const expectUnelevated = process.env.WINTCP_EXPECT_UNELEVATED === "1";

let passed = 0;
let failed = 0;
const check = (name, ok, detail = "") => {
  if (ok) {
    passed++;
    console.log(`[ ok ] ${name}`);
  } else {
    failed++;
    console.error(`[FAIL] ${name}${detail ? `: ${detail}` : ""}`);
  }
};

const serverSockets = new Set();
const clients = [];
let listener;
let listener6;
let udpSocket;
let unknownOwnerChild;

async function request(path, token, options = {}) {
  const response = await fetch(new URL(path, baseUrl), {
    ...options,
    headers: {
      "X-WinTCP-Token": token,
      Origin: new URL(baseUrl).origin,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
  return { status: response.status, body: await response.json() };
}

function connect(port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port }, () => resolve(socket));
    socket.once("error", reject);
  });
}

function closeSocket(socket) {
  if (!socket || socket.destroyed) return Promise.resolve();
  return new Promise((resolve) => {
    socket.once("close", resolve);
    socket.destroy();
  });
}

async function findOwnedRow(token, clientPort, serverPort) {
  const deadline = Date.now() + 12000;
  while (Date.now() < deadline) {
    const snapshot = await request("/api/connections", token);
    const row = snapshot.body.connections?.find((item) =>
      Number(item.pid) === process.pid && item.removed !== true &&
      String(item.proto || "").startsWith("TCPv4") && item.state === "ESTABLISHED" &&
      Number(item.lport) === clientPort && Number(item.rport) === serverPort &&
      item.local === "127.0.0.1" && item.remote === "127.0.0.1" &&
      typeof item.processInstanceId === "string" && item.processInstanceId.length > 0);
    if (row) return row;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return null;
}

async function findOwnedListener(token, port, protocol = "TCPv4") {
  const deadline = Date.now() + 12000;
  while (Date.now() < deadline) {
    const snapshot = await request("/api/connections", token);
    const row = snapshot.body.connections?.find((item) =>
      Number(item.pid) === process.pid && item.removed !== true &&
      String(item.proto || "").startsWith(protocol) && item.state === "LISTENING" &&
      Number(item.lport) === port && typeof item.processInstanceId === "string");
    if (row) return row;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return null;
}

async function findOwnedUdpRow(token, port) {
  const deadline = Date.now() + 12000;
  while (Date.now() < deadline) {
    const snapshot = await request("/api/connections", token);
    const row = snapshot.body.connections?.find((item) =>
      Number(item.pid) === process.pid && item.removed !== true &&
      String(item.proto || "").startsWith("UDPv4") && Number(item.lport) === port &&
      typeof item.processInstanceId === "string");
    if (row) return row;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return null;
}

async function findOwnedProcess(token) {
  const deadline = Date.now() + 12000;
  let lastSnapshot = null;
  while (Date.now() < deadline) {
    const snapshot = await request("/api/processes?sort=pid&dir=asc&limit=2000", token);
    lastSnapshot = snapshot;
    const row = snapshot.body.processes?.find((item) => Number(item.pid) === process.pid);
    if (row) return row;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  const rows = lastSnapshot?.body?.processes;
  console.log(`[note] Process API owner lookup: status=${lastSnapshot?.status}, known=${lastSnapshot?.body?.known}, returned=${lastSnapshot?.body?.returned}, total=${lastSnapshot?.body?.total}, targetPid=${process.pid}, pidPresent=${Array.isArray(rows) && rows.some((row) => String(row.pid) === String(process.pid))}, sample=${Array.isArray(rows) ? rows.slice(0, 3).map((row) => row.pid).join(",") : JSON.stringify(lastSnapshot?.body).slice(0, 200)}`);
  return null;
}

async function findUnknownOwnerRow(token, clientPort, serverPort) {
  const deadline = Date.now() + 12000;
  while (Date.now() < deadline) {
    const snapshot = await request("/api/connections", token);
    const row = snapshot.body.connections?.find((item) =>
      item.removed !== true && String(item.proto || "").startsWith("TCPv4") &&
      Number(item.lport) === clientPort && Number(item.rport) === serverPort &&
      item.local === "127.0.0.1" && item.remote === "127.0.0.1" &&
      (item.pid === 0 || item.pid === "0"));
    if (row) return row;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return null;
}

function closeCapture(row) {
  return Object.fromEntries([
    "idExact", "processInstanceId", "pid", "proto", "local", "lport", "remote", "rport", "state",
  ].map((key) => [key, String(row[key])]));
}

try {
  const page = await fetch(new URL("index.html", baseUrl));
  const html = await page.text();
  const token = /<meta name="wintcp-api-token" content="([^"]+)"/.exec(html)?.[1];
  check("Isolated dashboard serves a mutation token", page.ok && Boolean(token));
  if (!page.ok || !token) throw new Error("No API token in the isolated dashboard shell");

  const firewallInventoryResponse = await request("/api/firewall", token);
  const firewallInventory = firewallInventoryResponse.body;
  check("Compiled firewall inventory reports availability, generation time and partial-read warnings",
    firewallInventoryResponse.status === 200 && typeof firewallInventory?.available === "boolean" &&
      Array.isArray(firewallInventory.rules) && typeof firewallInventory.generatedAt === "string" &&
      Array.isArray(firewallInventory.warnings) &&
      (firewallInventory.available || typeof firewallInventory.reason === "string"),
    JSON.stringify({ status: firewallInventoryResponse.status,
      available: firewallInventory?.available, generatedAt: firewallInventory?.generatedAt,
      warningCount: firewallInventory?.warnings?.length }));

  listener = net.createServer((socket) => {
    serverSockets.add(socket);
    socket.on("error", () => {});
    socket.on("end", () => socket.end());
    socket.once("close", () => serverSockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", resolve);
  });
  const serverPort = listener.address().port;
  const listeningRow = await findOwnedListener(token, serverPort);
  check("Compiled API reports the owned test listener", Boolean(listeningRow),
    JSON.stringify(listeningRow && { idExact: listeningRow.idExact, state: listeningRow.state, port: listeningRow.lport }));
  if (!listeningRow) throw new Error("Could not identify the owned listener in the live snapshot");

  unknownOwnerChild = spawn(process.execPath, ["-e",
    "const net=require('node:net');const s=net.connect({host:'127.0.0.1',port:Number(process.argv[1])},()=>{process.stdout.write(String(s.localPort));s.end()});s.once('error',()=>process.exitCode=1);s.once('close',()=>process.exit());",
    String(serverPort)], { windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  let unknownOwnerOutput = "";
  unknownOwnerChild.stdout.setEncoding("utf8");
  unknownOwnerChild.stdout.on("data", (chunk) => { unknownOwnerOutput += chunk; });
  const childExit = await new Promise((resolve) => {
    unknownOwnerChild.once("exit", (code, signal) => resolve({ code, signal }));
  });
  const unknownOwnerClientPort = Number(unknownOwnerOutput);
  check("Disposable owner process exits after closing its loopback connection",
    childExit.code === 0 && Number.isInteger(unknownOwnerClientPort) && unknownOwnerClientPort > 0,
    JSON.stringify({ childPid: unknownOwnerChild.pid, ...childExit, clientPort: unknownOwnerOutput }));
  const unknownOwnerRow = unknownOwnerClientPort > 0
    ? await findUnknownOwnerRow(token, unknownOwnerClientPort, serverPort) : null;
  const processSnapshot = unknownOwnerRow
    ? await request("/api/processes?sort=pid&dir=asc&limit=2000", token) : null;
  check("Compiled API retains a real ownerless TIME_WAIT row as unknown, not System",
    Boolean(unknownOwnerRow && Number(unknownOwnerRow.pid) === 0 &&
      unknownOwnerRow.process === "—" && unknownOwnerRow.processInstanceId === null &&
      !processSnapshot?.body.processes?.some((row) => Number(row.pid) === 0)),
    JSON.stringify({ connection: unknownOwnerRow && {
      pid: unknownOwnerRow.pid, process: unknownOwnerRow.process,
      state: unknownOwnerRow.state, processInstanceId: unknownOwnerRow.processInstanceId,
      removed: unknownOwnerRow.removed,
    }, processZeroPresent: processSnapshot?.body.processes?.some((row) => Number(row.pid) === 0) }));
  unknownOwnerChild = null;
  const listeningPreview = await request("/api/connections/action/preview", token, {
    method: "POST", body: JSON.stringify(closeCapture(listeningRow)),
  });
  check("Listener preview is disabled with an explicit reason and no nonce",
    listeningPreview.status === 200 && listeningPreview.body.canExecute === false &&
      !listeningPreview.body.nonce && listeningPreview.body.reason?.includes("established TCP"),
    JSON.stringify(listeningPreview.body));
  listener6 = net.createServer((socket) => {
    serverSockets.add(socket);
    socket.on("error", () => {});
    socket.once("close", () => serverSockets.delete(socket));
  });
  try {
    await new Promise((resolve, reject) => {
      listener6.once("error", reject);
      listener6.listen({ port: 0, host: "::1", ipv6Only: true }, resolve);
    });
    const listener6Row = await findOwnedListener(token, listener6.address().port, "TCPv6");
    check("Compiled API reports the owned IPv6 listener", Boolean(listener6Row),
      JSON.stringify(listener6Row && { proto: listener6Row.proto, local: listener6Row.local, state: listener6Row.state }));
    if (listener6Row) {
      const ipv6Preview = await request("/api/connections/action/preview", token, {
        method: "POST", body: JSON.stringify(closeCapture(listener6Row)),
      });
      check("IPv6 preview is disabled with an explicit reason and no nonce",
        ipv6Preview.status === 200 && ipv6Preview.body.canExecute === false &&
          !ipv6Preview.body.nonce && ipv6Preview.body.reason?.includes("public IPv6"),
        JSON.stringify(ipv6Preview.body));
    }
  } catch (error) {
    if (listener6.listening) await new Promise((resolve) => listener6.close(resolve));
    listener6 = null;
    console.log(`[skip] IPv6 loopback is unavailable: ${error.code || error.message}`);
  }
  udpSocket = dgram.createSocket("udp4");
  await new Promise((resolve, reject) => {
    udpSocket.once("error", reject);
    udpSocket.bind(0, "127.0.0.1", resolve);
  });
  const udpRow = await findOwnedUdpRow(token, udpSocket.address().port);
  check("Compiled API reports the owned UDP endpoint", Boolean(udpRow),
    JSON.stringify(udpRow && { idExact: udpRow.idExact, proto: udpRow.proto, port: udpRow.lport }));
  if (!udpRow) throw new Error("Could not identify the owned UDP endpoint in the live snapshot");
  const udpPreview = await request("/api/connections/action/preview", token, {
    method: "POST", body: JSON.stringify(closeCapture(udpRow)),
  });
  check("UDP preview is disabled with an explicit reason and no nonce",
    udpPreview.status === 200 && udpPreview.body.canExecute === false &&
      !udpPreview.body.nonce && udpPreview.body.reason?.includes("TCP connections only"),
    JSON.stringify({ response: udpPreview.body, target: closeCapture(udpRow) }));
  clients.push(await connect(serverPort), await connect(serverPort));
  const firstClientPort = clients[0].address().port;
  const secondClientPort = clients[1].address().port;
  check("Two disposable IPv4 loopback connections are open", firstClientPort !== secondClientPort && serverPort > 0);

  const [target, survivor] = await Promise.all([
    findOwnedRow(token, firstClientPort, serverPort),
    findOwnedRow(token, secondClientPort, serverPort),
  ]);
  check("Compiled API reports exact owned established endpoints", Boolean(target && survivor),
    JSON.stringify({ target: target && { idExact: target.idExact, pid: target.pid, tuple: [target.local, target.lport, target.remote, target.rport] },
      survivor: survivor && { idExact: survivor.idExact, pid: survivor.pid, tuple: [survivor.local, survivor.lport, survivor.remote, survivor.rport] } }));
  if (!target || !survivor) throw new Error("Could not identify both owned endpoints from the live snapshot");

  const owner = await findOwnedProcess(token);
  check("Compiled process API keeps PIDs numeric for the browser join",
    Boolean(owner && Number.isInteger(owner.pid) && owner.pid === process.pid),
    JSON.stringify(owner && { pid: owner.pid, type: typeof owner.pid }));
  const exactCounterShape = owner && ["memWs", "memPrivate", "ioRead", "ioWrite"].every((key) => {
    const value = owner[key];
    return value === null || (typeof value === "number" && Number.isSafeInteger(value)) ||
      (typeof value === "string" && /^\d+$/.test(value) && BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER));
  });
  check("Compiled process API keeps counters numeric when safe and exact decimal strings when unsafe",
    Boolean(exactCounterShape), JSON.stringify(owner && Object.fromEntries(
      ["memWs", "memPrivate", "ioRead", "ioWrite"].map((key) => [key, { value: owner[key], type: typeof owner[key] }]))));
  check("Compiled connection and process APIs join by exact lifetime",
    Boolean(owner && typeof target.pid === "string" &&
      Number(target.pid) === owner.pid && owner.instanceId === target.processInstanceId),
    JSON.stringify({ connection: { pid: target.pid, processInstanceId: target.processInstanceId },
      process: owner && { pid: owner.pid, instanceId: owner.instanceId } }));
  check("Compiled process API counts both owned live endpoints",
    Boolean(owner && Number.isInteger(owner.connections) && owner.connections >= 2),
    JSON.stringify(owner && { pid: owner.pid, connections: owner.connections }));

  if (owner && owner.instanceId && owner.path) {
    const applicationFields = {
      scope: "application",
      process: owner.path,
      pid: String(owner.pid),
      instanceId: owner.instanceId,
    };
    const applicationPreview = await request("/api/block/preview", token, {
      method: "POST",
      body: new URLSearchParams(applicationFields).toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    check("Application rule preview confirms the exact process lifetime and full path",
      applicationPreview.status === 200 && applicationPreview.body.scope === "application" &&
        applicationPreview.body.ruleName && applicationPreview.body.plan?.includes(`process=${owner.path}`) &&
        applicationPreview.body.requiresElevation === true &&
        (applicationPreview.body.canExecute === true
          ? typeof applicationPreview.body.nonce === "string"
          : !applicationPreview.body.nonce && applicationPreview.body.reason?.includes("administrator")),
      JSON.stringify(applicationPreview.body));
    const staleApplicationPreview = await request("/api/block/preview", token, {
      method: "POST",
      body: new URLSearchParams({ ...applicationFields, process: `${owner.path}.changed` }).toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    check("Application rule preview rejects a path changed after process selection",
      staleApplicationPreview.status === 409 && !staleApplicationPreview.body.nonce,
      JSON.stringify({ status: staleApplicationPreview.status, body: staleApplicationPreview.body }));
    const applicationAllowPreview = await request("/api/block/preview", token, {
      method: "POST",
      body: new URLSearchParams({ ...applicationFields, scope: "application-allow" }).toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    check("Application allow preview preserves the verified path and explicit allow action",
      applicationAllowPreview.status === 200 && applicationAllowPreview.body.scope === "application-allow" &&
        applicationAllowPreview.body.ruleName?.includes("allow") &&
        applicationAllowPreview.body.plan?.includes("allow  outbound to") &&
        applicationAllowPreview.body.plan?.includes(`process=${owner.path}`) &&
        !applicationAllowPreview.body.plan?.includes("block outbound to"),
      JSON.stringify({ status: applicationAllowPreview.status, body: applicationAllowPreview.body }));
    const customRuleFields = {
      direction: "inbound", action: "allow", proto: "tcp",
      address: "198.51.100.0/24", localAddress: "192.0.2.10",
      localPorts: "8443", remotePorts: "443,8443", process: owner.path,
      service: "Dnscache", profiles: "2", label: "Preview-only custom rule",
    };
    const customRulePreview = await request("/api/firewall/rule/create/preview", token, {
      method: "POST", body: new URLSearchParams(customRuleFields).toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    check("Custom rule API preview preserves direction, allow, address, port, path, service and profile scopes",
      customRulePreview.status === 200 && customRulePreview.body.operation === "create" &&
        customRulePreview.body.plan?.includes("allow  inbound from 198.51.100.0/24") &&
        customRulePreview.body.plan?.includes("local-address=192.0.2.10") &&
        customRulePreview.body.plan?.includes("local-ports=8443") &&
        customRulePreview.body.plan?.includes("remote-ports=443,8443") &&
        customRulePreview.body.plan?.includes(`process=${owner.path}`) &&
        customRulePreview.body.plan?.includes("service=Dnscache") &&
        customRulePreview.body.plan?.includes("profiles=2") &&
        (customRulePreview.body.canExecute === true
          ? typeof customRulePreview.body.nonce === "string"
          : !customRulePreview.body.nonce && customRulePreview.body.reason?.includes("administrator")),
      JSON.stringify({ status: customRulePreview.status, body: customRulePreview.body }));
    const invalidAnyRule = await request("/api/firewall/rule/create/preview", token, {
      method: "POST", body: new URLSearchParams({ ...customRuleFields,
        proto: "any", localPorts: "8443" }).toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    check("Custom rule API refuses protocol Any with constrained ports before execution",
      invalidAnyRule.status === 400 && /port/i.test(invalidAnyRule.body.message || invalidAnyRule.body.error || ""),
      JSON.stringify({ status: invalidAnyRule.status, body: invalidAnyRule.body }));
    const applicationPeerFields = {
      scope: "application-peer",
      process: owner.path,
      pid: String(target.pid),
      instanceId: target.processInstanceId,
      idExact: target.idExact,
      processInstanceId: target.processInstanceId,
      proto: target.proto,
      local: target.local,
      lport: target.lport,
      remote: target.remote,
      rport: target.rport,
      state: target.state,
    };
    const applicationPeerPreview = await request("/api/block/preview", token, {
      method: "POST",
      body: new URLSearchParams(applicationPeerFields).toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    check("Application-peer preview keeps the full tuple, verified process lifetime, and exact image path",
      applicationPeerPreview.status === 200 && applicationPeerPreview.body.scope === "application-peer" &&
        applicationPeerPreview.body.ruleName && applicationPeerPreview.body.plan?.includes(`process=${owner.path}`) &&
        applicationPeerPreview.body.requiresElevation === true &&
        (applicationPeerPreview.body.canExecute === true
          ? typeof applicationPeerPreview.body.nonce === "string"
          : !applicationPeerPreview.body.nonce && applicationPeerPreview.body.reason?.includes("administrator")),
      JSON.stringify({ status: applicationPeerPreview.status, body: applicationPeerPreview.body }));
    const staleApplicationPeerPreview = await request("/api/block/preview", token, {
      method: "POST",
      body: new URLSearchParams({ ...applicationPeerFields,
        rport: String(Number(target.rport) === 1 ? 2 : 1) }).toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    check("Application-peer preview refuses a changed connection tuple without issuing a nonce",
      staleApplicationPeerPreview.status === 409 && !staleApplicationPeerPreview.body.nonce,
      JSON.stringify({ status: staleApplicationPeerPreview.status, body: staleApplicationPeerPreview.body }));
    const unknownServicePreview = await request("/api/block/preview", token, {
      method: "POST",
      body: new URLSearchParams({ ...applicationPeerFields,
        scope: "service-peer", service: "Dnscache" }).toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    check("Service-peer preview refuses a service not reported for the captured connection",
      unknownServicePreview.status === 409 && !unknownServicePreview.body.nonce,
      JSON.stringify({ status: unknownServicePreview.status, body: unknownServicePreview.body }));
  } else {
    console.log("[skip] Application preview needs a readable owner path and process lifetime");
  }

  const capturedTarget = closeCapture(target);
  const alteredTarget = { ...capturedTarget, rport: String(Number(capturedTarget.rport) === 1 ? 2 : 1) };
  const alteredPreview = await request("/api/connections/action/preview", token, {
    method: "POST", body: JSON.stringify(alteredTarget),
  });
  check("A changed tuple is rejected before preview creation",
    alteredPreview.status === 409 && !alteredPreview.body.nonce,
    JSON.stringify({ status: alteredPreview.status, body: alteredPreview.body }));
  const preview = await request("/api/connections/action/preview", token, {
    method: "POST", body: JSON.stringify(capturedTarget),
  });
  check("Preview revalidates the exact tuple and exposes current privilege capability",
    preview.status === 200 && preview.body.ok === true && preview.body.snapshotKnown === true &&
      preview.body.requiresElevation === true &&
      (preview.body.canExecute === true || preview.body.reason?.includes("elevated WinTCP process")),
    JSON.stringify(preview.body));
  if (expectUnelevated) {
    const refusedForPrivilege = preview.body.canExecute === false && !preview.body.nonce &&
      preview.body.reason?.includes("elevated WinTCP process");
    check("Restricted-token service refuses close before issuing an execution token",
      refusedForPrivilege, JSON.stringify(preview.body));
    if (!refusedForPrivilege)
      throw new Error("The isolated service was not unelevated; no connection action was attempted");
  }

  if (preview.body.canExecute === true && preview.body.nonce) {
    if (preview.status !== 200 || preview.body.ok !== true ||
        preview.body.snapshotKnown !== true || preview.body.requiresElevation !== true) {
      throw new Error("Refusing execution because the preview did not confirm a fresh, elevated, exact target");
    }
    const expiryPreview = await request("/api/connections/action/preview", token, {
      method: "POST", body: JSON.stringify(closeCapture(survivor)),
    });
    check("A second exact live target receives its own expiring preview",
      expiryPreview.status === 200 && expiryPreview.body.canExecute === true &&
        typeof expiryPreview.body.nonce === "string" && expiryPreview.body.nonce !== preview.body.nonce,
      JSON.stringify(expiryPreview.body));
    const raceClient = await connect(serverPort);
    clients.push(raceClient);
    const raceRow = await findOwnedRow(token, raceClient.address().port, serverPort);
    check("Compiled API captures a separate target for execute-time revalidation", Boolean(raceRow),
      JSON.stringify(raceRow && { idExact: raceRow.idExact, port: raceRow.lport }));
    if (raceRow) {
      const racePreview = await request("/api/connections/action/preview", token, {
        method: "POST", body: JSON.stringify(closeCapture(raceRow)),
      });
      check("Target-exit race preview is exact and independently authorized",
        racePreview.status === 200 && racePreview.body.canExecute === true &&
          typeof racePreview.body.nonce === "string",
        JSON.stringify(racePreview.body));
      await closeSocket(raceClient);
      const raceExecute = await request("/api/connections/action/execute", token, {
        method: "POST", body: JSON.stringify({ nonce: racePreview.body.nonce }),
      });
      const afterRace = await request("/api/connections", token);
      check("A target that exits after preview is refused without affecting the survivor",
        raceExecute.status === 409 && raceExecute.body.error?.includes("no action was attempted") &&
          afterRace.body.connections?.some((row) => row.idExact === survivor.idExact &&
            row.removed !== true && row.state === "ESTABLISHED"),
        JSON.stringify({ response: raceExecute.body, survivor: survivor.idExact }));
    } else {
      await closeSocket(raceClient);
    }
    const executed = await request("/api/connections/action/execute", token, {
      method: "POST", body: JSON.stringify({ nonce: preview.body.nonce }),
    });
    check("Elevated execution closes only the captured test connection",
      executed.status === 200 && executed.body.ok === true && executed.body.connection?.status === "succeeded",
      JSON.stringify(executed));
    const deadline = Date.now() + 8000;
    let closed = false;
    let survivorActive = false;
    while (Date.now() < deadline) {
      const snapshot = await request("/api/connections", token);
      const rows = snapshot.body.connections || [];
      closed = rows.some((row) => row.idExact === target.idExact &&
        (row.removed === true || row.state !== "ESTABLISHED"));
      survivorActive = rows.some((row) => row.idExact === survivor.idExact &&
        row.removed !== true && row.state === "ESTABLISHED");
      if (closed && survivorActive) break;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    check("Target is no longer established while the second owned connection survives",
      closed && survivorActive, JSON.stringify({ closed, survivorActive }));
    const repeated = await request("/api/connections/action/execute", token, {
      method: "POST", body: JSON.stringify({ nonce: preview.body.nonce }),
    });
    check("One-use preview tokens cannot close a target twice", repeated.status === 410,
      JSON.stringify({ status: repeated.status, body: repeated.body }));
    const stalePreview = await request("/api/connections/action/preview", token, {
      method: "POST", body: JSON.stringify(capturedTarget),
    });
    check("A closed captured target cannot be previewed as live again",
      stalePreview.status === 200 && stalePreview.body.canExecute === false &&
        !stalePreview.body.nonce && stalePreview.body.reason?.includes("retained history"),
      JSON.stringify(stalePreview));
    if (expiryPreview.body.nonce) {
      await new Promise((resolve) => setTimeout(resolve, 31000));
      const expired = await request("/api/connections/action/execute", token, {
        method: "POST", body: JSON.stringify({ nonce: expiryPreview.body.nonce }),
      });
      const afterExpiry = await request("/api/connections", token);
      check("An expired preview cannot execute and leaves the other target active",
        expired.status === 410 && afterExpiry.body.connections?.some((row) =>
          row.idExact === survivor.idExact && row.removed !== true && row.state === "ESTABLISHED"),
        JSON.stringify({ status: expired.status, body: expired.body }));
    }
  } else {
    const stillLive = await request("/api/connections", token);
    const rows = stillLive.body.connections || [];
    check("Unelevated preview refuses execution without changing either owned endpoint",
      preview.body.canExecute === false && !preview.body.nonce &&
      rows.some((row) => row.idExact === target.idExact && row.state === "ESTABLISHED") &&
      rows.some((row) => row.idExact === survivor.idExact && row.state === "ESTABLISHED"),
      JSON.stringify({ reason: preview.body.reason }));
  }
} catch (error) {
  failed++;
  console.error(`[FAIL] Disposable connection action integration: ${error.message}`);
} finally {
  if (unknownOwnerChild?.pid && unknownOwnerChild.exitCode === null) {
    unknownOwnerChild.kill();
    await new Promise((resolve) => unknownOwnerChild.once("exit", resolve));
  }
  await Promise.all(clients.map(closeSocket));
  await Promise.all([...serverSockets].map(closeSocket));
  if (listener?.listening) await new Promise((resolve) => listener.close(resolve));
  if (listener6?.listening) await new Promise((resolve) => listener6.close(resolve));
  if (udpSocket?.address()) await new Promise((resolve) => udpSocket.close(resolve));
}

console.log(`${passed} passed, ${failed} failed.`);
process.exitCode = failed ? 1 : 0;
