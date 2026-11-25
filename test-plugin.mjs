// Functional test harness for the RDAP IP plugin in pluginpack-ip-recon/dist/pack.mjs.
// Run: node test-plugin.mjs
//
// The plugin asks rdap.org, whose redirect to the regional registry ctx.net.fetch follows, so the
// fake net answers the rdap.org URL with the registry's answer, as the host would. Which registry
// that is comes from the IANA bootstrap table built into the pack, never from a fetch. The answers
// follow the RFC 9083 ip network object shape with the cidr0 extension, as ARIN and RIPE send it.
import { readFileSync } from "node:fs";
import pack from "./dist/pack.mjs";

const rdapPlugin = pack.plugins.find((p) => p.manifest.identifier === "run.vineyard.plugins.rdap_ip");
const ok = [];
const fail = [];
const check = (name, cond) => (cond ? ok : fail).push(name);

function makeGraph(nodeById) {
  const createdNodes = [];
  const createdEdges = [];
  const updates = [];
  return {
    createdNodes,
    createdEdges,
    updates,
    async get(id) {
      return nodeById[id] || null;
    },
    async createNode(draft) {
      const node = { id: `n${createdNodes.length + 1}`, type: draft.type, data: draft.data };
      createdNodes.push(node);
      return node;
    },
    async updateNode(id, data) {
      updates.push({ id, data });
    },
    async createEdge(edge) {
      createdEdges.push(edge);
    },
  };
}

/** `respond` returns {status, body, headers} or {throws: true} for a request that never landed. */
function makeNet(respond) {
  const calls = [];
  return {
    calls,
    async fetch(url, init) {
      calls.push({ url, init });
      const r = respond(url, init, calls.length);
      if (r.throws) throw new TypeError("Failed to fetch");
      const { status, body, headers } = r;
      const text = typeof body === "string" ? body : JSON.stringify(body);
      return {
        ok: status >= 200 && status < 300,
        status,
        headers: headers ?? {},
        async json() {
          return JSON.parse(text);
        },
        async text() {
          return text;
        },
      };
    },
  };
}

function ctxFor({ nodes, selection, respond }) {
  const graph = makeGraph(nodes);
  const net = makeNet(respond);
  const logs = [];
  return {
    graph,
    net,
    logs,
    ctx: {
      run: { runId: "r1", projectId: "p1", pluginId: "run.vineyard.plugins.rdap_ip", grantedScopes: {}, platform: "web" },
      input: { selection },
      params: {},
      graph,
      net,
      progress: { set() {}, log: (m) => logs.push(m) },
      signal: undefined,
    },
  };
}

// An end assignment (198.51.100.0/24), so a second address inside it is answered without asking again.
const assignmentBody = {
  objectClassName: "ip network",
  handle: "NET-198-51-100-0-1",
  startAddress: "198.51.100.0",
  endAddress: "198.51.100.255",
  ipVersion: "v4",
  name: "EXAMPLE-NET",
  type: "ASSIGNMENT",
  country: "us",
  cidr0_cidrs: [{ v4prefix: "198.51.100.0", length: 24 }],
  entities: [
    {
      objectClassName: "entity",
      roles: ["registrant"],
      vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Hosting LLC"], ["kind", {}, "text", "org"]]],
    },
  ],
};
// Spaced as the registry sent it, so a re-serialised parse would not match the kept text.
const assignmentText = JSON.stringify(assignmentBody, null, 1);
// An allocation (203.0.113.0/24), which can hold more specific registrations, so it is never reused.
const allocationText = JSON.stringify({ ...assignmentBody, handle: "NET-203-0-113-0-1", startAddress: "203.0.113.0", endAddress: "203.0.113.255", type: "ALLOCATION", name: "ALLOC-NET", cidr0_cidrs: [{ v4prefix: "203.0.113.0", length: 24 }] }, null, 1);
const notFoundBody = { errorCode: 404, title: "Not Found", description: ["No registration for this address."] };
const RESPONSE_HEADERS = { "content-type": "application/rdap+json", etag: '"r-1"' };
// The IANA bootstrap lives at data.iana.org. The plugin must never fetch or keep one.
const IANA_MARK = "data.iana.org";

const ipNode = (id, ip, data = {}) => ({ id, type: "infrastructure.ip_address", data: { ip_address: ip, ...data } });

function retainSpy(answer = async () => ({ kept: true })) {
  const calls = [];
  const fn = async (...args) => {
    calls.push(args);
    return answer(...args);
  };
  fn.calls = calls;
  return fn;
}
const leaks = (calls) => {
  const s = JSON.stringify(calls);
  return ["http://", "https://", "rdap.org", IANA_MARK, "init", "url"].filter((x) => s.includes(x));
};

// ---- baseline: the plugin's own mapping ---------------------------------------------------------
{
  const t = ctxFor({ nodes: { i1: ipNode("i1", "198.51.100.7") }, selection: ["i1"], respond: () => ({ status: 200, body: assignmentText }) });
  const res = await rdapPlugin.run(t.ctx);
  check("rdap: one request, to rdap.org", t.net.calls.length === 1 && t.net.calls[0].url === "https://rdap.org/ip/198.51.100.7");
  check("rdap: a Netblock linked within netblock", t.graph.createdNodes.length === 1 && t.graph.createdNodes[0].data.cidr === "198.51.100.0/24" && t.graph.createdEdges[0]?.label === "within netblock");
  check("rdap: organization and country filled", res.counts.ips_updated === 1 && JSON.stringify(t.graph.updates[0]) === JSON.stringify({ id: "i1", data: { organization: "Example Hosting LLC", country_code: "US" } }));
}

// ---- raw results: ctx.retain ------------------------------------------------------------------
// Invariants, from the plugin raw results spec (§5, §12):
//   - RDAP IP keeps the registry's answer for each address on that IP's node, op "rdap", as the
//     text the registry sent. An address answered from an end assignment already fetched in the run
//     keeps nothing: no request was about it. Only a 2xx the fields are mapped from is kept
//     (analyst's decision, 2026-11-25): a 404, a 429, a 5xx, a request that never landed, and a 2xx
//     that is not JSON or is empty keep nothing. objectClassName is not required: an answer from a
//     server that omits it is mapped and kept as before. An empty answer is never reused.
//   - Only status, headers and body are handed over: no URL, nothing about the request.
//   - No bootstrap answer is ever kept: the bootstrap is a table in the pack, and rdap.org's
//     redirect is followed by the host.
//   - A refusal object or a throw from retain never fails the run, and is logged once per reason.
//   - A host without ctx.retain (every desktop build before it) runs exactly as before.
{
  const nodes = { i1: ipNode("i1", "198.51.100.7") };
  const spy = retainSpy();
  const t = ctxFor({ nodes, selection: ["i1"], respond: () => ({ status: 200, body: assignmentText, headers: RESPONSE_HEADERS }) });
  t.ctx.retain = spy;
  const res = await rdapPlugin.run(t.ctx);
  check("retain rdap: one call, on the looked-up IP, op rdap", spy.calls.length === 1 && spy.calls[0][0] === "i1" && spy.calls[0][1] === "rdap");
  check("retain rdap: the registry answer's own text, byte for byte", spy.calls[0]?.[2].body === assignmentText);
  check("retain rdap: status and the response's own headers", spy.calls[0]?.[2].status === 200 && spy.calls[0]?.[2].headers.etag === '"r-1"');
  check("retain rdap: only body, headers and status", spy.calls[0] && Object.keys(spy.calls[0][2]).sort().join() === "body,headers,status");
  check("retain rdap: no URL or request detail", leaks(spy.calls).length === 0);
  check("retain rdap: no bootstrap fetched, so none kept", t.net.calls.every((c) => !c.url.includes(IANA_MARK)) && spy.calls.length === 1);
  check("retain rdap: nothing kept on the Netblock it created", !spy.calls.some((c) => t.graph.createdNodes.some((n) => n.id === c[0])));

  // The same run on a host without retain: same graph, same result.
  const old = ctxFor({ nodes, selection: ["i1"], respond: () => ({ status: 200, body: assignmentText, headers: RESPONSE_HEADERS }) });
  const oldRes = await rdapPlugin.run(old.ctx);
  check("old host: no ctx.retain, the lookup runs as before", !("retain" in old.ctx) && JSON.stringify(oldRes) === JSON.stringify(res));
  check("old host: ...and stages the same graph writes", JSON.stringify(old.graph.createdNodes) === JSON.stringify(t.graph.createdNodes) && JSON.stringify(old.graph.createdEdges) === JSON.stringify(t.graph.createdEdges) && JSON.stringify(old.graph.updates) === JSON.stringify(t.graph.updates));
  check("old host: says nothing about raw results", !old.logs.some((l) => /not kept/.test(l)));
  const notFn = ctxFor({ nodes, selection: ["i1"], respond: () => ({ status: 200, body: assignmentText }) });
  notFn.ctx.retain = true;
  const notFnRes = await rdapPlugin.run(notFn.ctx).catch((e) => e);
  check("old host: a retain that is not a function is left alone", !(notFnRes instanceof Error) && notFnRes.counts.ips_updated === 1);
}
{
  // Reuse within a run: an address answered from an assignment already fetched keeps nothing,
  // since no request was about it; only the address that fetched keeps the answer.
  const spy = retainSpy();
  const t = ctxFor({
    nodes: { a: ipNode("a", "198.51.100.7"), b: ipNode("b", "198.51.100.9"), c: ipNode("c", "203.0.113.5"), d: ipNode("d", "203.0.113.6") },
    selection: ["a", "b", "c", "d"],
    respond: (url) => (url.includes("198.51.100.") ? { status: 200, body: assignmentText } : { status: 200, body: allocationText }),
  });
  t.ctx.retain = spy;
  const res = await rdapPlugin.run(t.ctx);
  const byNode = Object.fromEntries(spy.calls.map((c) => [c[0], c[2].body]));
  check("retain reuse: one call per request, op rdap", spy.calls.length === 3 && spy.calls.every((c) => c[1] === "rdap"));
  check("retain reuse: the address answered from a fetched assignment keeps nothing", res.counts.reused_in_run === 1 && byNode.a === assignmentText && !("b" in byNode));
  check("retain reuse: an allocation is asked again, and each keeps its own answer", res.counts.rdap_requests === 3 && byNode.c === allocationText && byNode.d === allocationText);
}
{
  // Only the 200 is kept: a 404, 429, 503 and a network failure keep nothing.
  const spy = retainSpy();
  const t = ctxFor({
    nodes: {
      a: ipNode("a", "192.0.2.1"),
      b: ipNode("b", "198.51.100.7"),
      c: ipNode("c", "192.0.2.3"),
      d: ipNode("d", "192.0.2.4"),
      e: ipNode("e", "192.0.2.5"),
    },
    selection: ["a", "b", "c", "d", "e"],
    respond: (url) =>
      url.endsWith("192.0.2.1")
        ? { status: 404, body: notFoundBody }
        : url.endsWith("192.0.2.3")
          ? { status: 429, body: { errorCode: 429 } }
          : url.endsWith("192.0.2.4")
            ? { status: 503, body: "<html>Service Unavailable</html>" }
            : url.endsWith("192.0.2.5")
              ? { throws: true }
              : { status: 200, body: assignmentText },
  });
  t.ctx.retain = spy;
  const res = await rdapPlugin.run(t.ctx);
  const kept = spy.calls.map((c) => `${c[0]}:${c[1]}:${c[2].status}`).sort().join();
  check("retain rdap: a 404 keeps nothing, and the 200 is kept as usual", kept === "b:rdap:200");
  check("retain rdap: 429, 503 and a network failure are not kept", !spy.calls.some((c) => ["a", "c", "d", "e"].includes(c[0])));
  check("retain rdap: no non-2xx is ever handed over", spy.calls.every((c) => c[2].status >= 200 && c[2].status < 300));
  check("retain rdap: misses still write nothing", res.counts.ips_updated === 1 && t.graph.updates.length === 1 && t.graph.updates[0].id === "b");
}
{
  // A 2xx the plugin maps nothing from keeps nothing: not JSON, an empty body, null, an array, or
  // an empty object.
  const answers = {
    "192.0.2.10": "<html>Welcome</html>",
    "192.0.2.11": "",
    "192.0.2.12": "null",
    "192.0.2.13": "[]",
    "192.0.2.14": "{}",
  };
  const ips = Object.keys(answers);
  const spy = retainSpy();
  const t = ctxFor({
    nodes: Object.fromEntries(ips.map((ip) => [ip, ipNode(ip, ip)])),
    selection: ips,
    respond: (url) => ({ status: 200, body: answers[url.slice(url.lastIndexOf("/") + 1)], headers: RESPONSE_HEADERS }),
  });
  t.ctx.retain = spy;
  const res = await rdapPlugin.run(t.ctx).catch((e) => e);
  check("retain rdap: a 2xx with nothing in it is asked for, and the run succeeds", t.net.calls.length === ips.length && !(res instanceof Error));
  check("retain rdap: a 2xx that is not JSON or is empty keeps nothing", spy.calls.length === 0);
  check("retain rdap: ...and writes nothing", !(res instanceof Error) && res.counts.ips_updated === 0 && t.graph.createdNodes.length === 0 && t.graph.createdEdges.length === 0 && t.graph.updates.length === 0);
  check("retain rdap: ...and logs no refusal", !t.logs.some((l) => /not kept/.test(l)));
}
{
  // A registry that omits objectClassName (not every server is RFC-strict) is mapped and kept as
  // any other answer, and its end assignment is still reused within the run.
  const { objectClassName, ...loose } = assignmentBody;
  const looseText = JSON.stringify(loose, null, 1);
  const nodes = { a: ipNode("a", "198.51.100.7"), b: ipNode("b", "198.51.100.9") };
  const spy = retainSpy();
  const t = ctxFor({ nodes, selection: ["a", "b"], respond: () => ({ status: 200, body: looseText }) });
  t.ctx.retain = spy;
  const res = await rdapPlugin.run(t.ctx);
  const strict = ctxFor({ nodes, selection: ["a", "b"], respond: () => ({ status: 200, body: assignmentText }) });
  const strictRes = await rdapPlugin.run(strict.ctx);
  check("retain rdap: an answer without objectClassName is mapped as one with it", JSON.stringify(res) === JSON.stringify(strictRes) && JSON.stringify(t.graph.createdNodes) === JSON.stringify(strict.graph.createdNodes) && JSON.stringify(t.graph.updates) === JSON.stringify(strict.graph.updates) && res.counts.reused_in_run === 1);
  check("retain rdap: ...and kept, as the registry sent it", spy.calls.length === 1 && spy.calls[0][0] === "a" && spy.calls[0][2].body === looseText);
}
{
  // An empty answer is never reused: the next address in the same range asks for its own.
  const spy = retainSpy();
  const t = ctxFor({
    nodes: { a: ipNode("a", "198.51.100.7"), b: ipNode("b", "198.51.100.9") },
    selection: ["a", "b"],
    respond: (url) => (url.endsWith("198.51.100.7") ? { status: 200, body: "{}" } : { status: 200, body: assignmentText }),
  });
  t.ctx.retain = spy;
  const res = await rdapPlugin.run(t.ctx);
  check("retain rdap: an empty answer is not reused, the next address asks for its own", res.counts.rdap_requests === 2 && res.counts.reused_in_run === 0 && t.net.calls.length === 2);
  check("retain rdap: ...and only that address's own answer is kept", spy.calls.map((c) => c[0]).join() === "b" && t.graph.updates.map((u) => u.id).join() === "b");
}
{
  // A host that answers a refused request with status 0 rather than throwing: never kept.
  const spy = retainSpy();
  const t = ctxFor({ nodes: { a: ipNode("a", "198.51.100.7") }, selection: ["a"], respond: () => ({ status: 0, body: "" }) });
  t.ctx.retain = spy;
  await rdapPlugin.run(t.ctx);
  check("retain rdap: status 0 is not a response and is not kept", spy.calls.length === 0);
}
{
  // A refusal is an object, not a throw — and either way the run carries on.
  const refuse = retainSpy(async () => ({ kept: false, reason: "over this run's raw-result budget" }));
  const t = ctxFor({
    nodes: { a: ipNode("a", "203.0.113.5"), b: ipNode("b", "203.0.113.6"), c: ipNode("c", "203.0.113.7") },
    selection: ["a", "b", "c"],
    respond: () => ({ status: 200, body: allocationText }),
  });
  t.ctx.retain = refuse;
  const res = await rdapPlugin.run(t.ctx).catch((e) => e);
  check("retain refusal: the run still succeeds", !(res instanceof Error) && res.counts.ips_updated === 3 && refuse.calls.length === 3);
  check("retain refusal: said once, not once per IP", t.logs.filter((l) => /^Raw rdap result not kept — over this run's raw-result budget$/.test(l)).length === 1);

  const thrower = retainSpy(async () => {
    throw new Error("host blew up");
  });
  const h = ctxFor({ nodes: { a: ipNode("a", "203.0.113.5"), b: ipNode("b", "203.0.113.6") }, selection: ["a", "b"], respond: () => ({ status: 200, body: allocationText }) });
  h.ctx.retain = thrower;
  const hres = await rdapPlugin.run(h.ctx).catch((e) => e);
  check("retain throw: the run still succeeds with everything mapped", !(hres instanceof Error) && hres.counts.ips_updated === 2 && hres.counts.netblocks === 1 && h.graph.createdEdges.length === 2);
  check("retain throw: logged once, without the host's message", h.logs.filter((l) => /^Raw rdap result not kept — the host could not keep it$/.test(l)).length === 1 && !h.logs.some((l) => /blew up/.test(l)));
}
{
  // Only RDAP IP keeps anything: InternetDB and IP Geolocation on a host with retain keep nothing.
  for (const id of ["run.vineyard.plugins.shodan_internetdb", "run.vineyard.plugins.ip_geolocation"]) {
    const plugin = pack.plugins.find((p) => p.manifest.identifier === id);
    const spy = retainSpy();
    const t = ctxFor({
      nodes: { a: ipNode("a", "198.51.100.7") },
      selection: ["a"],
      respond: (url) =>
        url.includes("internetdb")
          ? { status: 200, body: { ip: "198.51.100.7", ports: [443], cpes: [], hostnames: [], tags: [], vulns: [] } }
          : { status: 200, body: { success: true, ip: "198.51.100.7", city: "Springfield", country: "United States", country_code: "US", latitude: 1, longitude: 2, connection: { isp: "Example" } } },
    });
    t.ctx.retain = spy;
    await plugin.run(t.ctx);
    check(`other plugins: ${plugin.manifest.name} ran and keeps nothing`, t.net.calls.length >= 1 && spy.calls.length === 0);
  }
}
{
  check("pack version is 2.3.0", pack.version === "2.3.0");
  check("RDAP IP version is 1.3.0", rdapPlugin.manifest.version === "1.3.0");
  const json = JSON.parse(readFileSync(new URL("./plugins/ip-recon.manifest.json", import.meta.url), "utf8"));
  check("manifest JSON agrees with the bundle on versions", json.version === pack.version && pack.plugins.every((p) => json.plugins.find((m) => m.identifier === p.manifest.identifier)?.version === p.manifest.version));
}
for (const n of ok) console.log(`  ok   ${n}`);
for (const n of fail) console.log(`  FAIL ${n}`);
console.log(fail.length ? `\n${fail.length} FAILED` : `\nall ${ok.length} checks passed`);
process.exit(fail.length ? 1 : 0);
