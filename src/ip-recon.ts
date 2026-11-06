// IP Recon — passive, keyless, CORS-only enrichment for IP Address nodes.
//
// Three plugins, all browser-only (no server, no API key, no cost):
//   • RDAP IP            IP → allocating Netblock (CIDR / name / country) + owning organization,
//                        via the RDAP bootstrap (rdap.org → the authoritative RIR).
//   • Shodan InternetDB  IP → open ports (Host node), known CVEs (Vulnerability nodes), reverse
//                        hostnames (Domain nodes) and tags — from Shodan's FREE, keyless InternetDB.
//   • IP Geolocation     IP → approximate Location node (city / country / lat-lon), via ipwho.is.
//
// InternetDB (https://internetdb.shodan.io) and ipwho.is are keyless and send `access-control-
// allow-origin: *`; RDAP's rdap.org 302 is followed by the browser to an RIR that also sends CORS.
// These complement the Cymru "IP → ASN" pack (routing view) with allocation, exposure and geo views.
import { definePlugin, definePluginPack } from './sdk';
import type { HostContext, RunResult, GraphNode } from './sdk';

const isIp = (n: GraphNode) => n.type === 'infrastructure.ip_address';
const ipOf = (n: GraphNode) => String((n.data as any).ip_address ?? '').trim();
const cc2 = (s: unknown): string | undefined => {
    const v = String(s ?? '').toUpperCase();
    return /^[A-Z]{2}$/.test(v) ? v : undefined;
};

function vcardField(entity: any, field: string): string {
    const arr = entity?.vcardArray?.[1];
    if (!Array.isArray(arr)) return '';
    const row = arr.find((r: any) => Array.isArray(r) && r[0] === field);
    return row ? String(row[3] ?? '') : '';
}

/**
 * Canonical form of a written IPv6 address, so that two spellings of one address compare equal.
 * Expands `::`, drops leading zeros, lower-cases. Returns the input unchanged for anything that is
 * not IPv6, so IPv4 falls through untouched.
 */
function canonIp(raw: string): string {
    const ip = raw
        .trim()
        .replace(/^\[|\]$/g, '')
        .toLowerCase();
    if (!ip.includes(':')) return ip;
    const [head, tail = ''] = ip.split('::');
    const a = head ? head.split(':') : [];
    const b = tail ? tail.split(':') : [];
    if (ip.includes('::')) {
        const fill = 8 - a.length - b.length;
        if (fill < 0) return ip;
        a.push(...Array(fill).fill('0'), ...b);
    }
    const parts = ip.includes('::') ? a : ip.split(':');
    if (parts.length !== 8) return ip;
    return parts.map((h) => (parseInt(h || '0', 16) || 0).toString(16)).join(':');
}

/**
 * The organization that holds the network, or '' when the answer does not name one.
 *
 * The registrant when that is an organization, else the network's description, which is where KRNIC
 * and JPNIC name the holder. Never the administrative contact: on KRNIC that is the role name
 * 'IP Manager', and on RIPE it can be a maintainer handle.
 */
function holderOf(doc: any): string {
    const registrants = (doc?.entities || []).filter(
        (e: any) => Array.isArray(e?.roles) && e.roles.includes('registrant') && vcardField(e, 'fn'),
    );
    const holder =
        registrants.find((e: any) => vcardField(e, 'kind') === 'org') ??
        registrants.find((e: any) => !vcardField(e, 'kind'));
    if (holder) return vcardField(holder, 'fn').trim();
    const remark = (doc?.remarks || []).find((r: any) => String(r?.title ?? '').toLowerCase() === 'description');
    return Array.isArray(remark?.description) ? String(remark.description[0] ?? '').trim() : '';
}

// An end assignment is the last word on every address inside it, so its answer can be reused within
// a run. An allocation cannot: it can hold more specific registrations.
const END_ASSIGNMENT_TYPES = new Set([
    'ASSIGNMENT',
    'DIRECT ASSIGNMENT',
    'REASSIGNMENT',
    'ASSIGNED',
    'REASSIGNED',
    'ASSIGNED PA',
    'ASSIGNED PI',
    'ASSIGNED ANYCAST',
    'ALLOCATED-ASSIGNED PA',
    'ASSIGNED PORTABLE',
    'ASSIGNED NON-PORTABLE',
]);
const isEndAssignment = (doc: any): boolean =>
    END_ASSIGNMENT_TYPES.has(
        String(doc?.type ?? '')
            .toUpperCase()
            .replace(/\s+/g, ' ')
            .trim(),
    );

function ipToBigInt(raw: string): bigint | null {
    const ip = raw.trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
        const octets = ip.split('.').map(Number);
        if (octets.some((o) => o > 255)) return null;
        return octets.reduce((value, o) => (value << 8n) + BigInt(o), 0n);
    }
    const groups = canonIp(ip).split(':');
    if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
    return groups.reduce((value, g) => (value << 16n) + BigInt(parseInt(g, 16)), 0n);
}

// Which registry answers for an address, from the IANA RDAP bootstrap, embedded so that ordering the
// selection costs no request.
const RDAP_BOOTSTRAP: Record<string, string[]> = {
    AFRINIC: [
        '41.0.0.0/8', '102.0.0.0/8', '105.0.0.0/8', '154.0.0.0/8', '196.0.0.0/8', '197.0.0.0/8', '2001:4200::/23',
        '2c00::/12',
    ],
    APNIC: [
        '1.0.0.0/8', '14.0.0.0/8', '27.0.0.0/8', '36.0.0.0/8', '39.0.0.0/8', '42.0.0.0/8', '43.0.0.0/8',
        '49.0.0.0/8', '58.0.0.0/8', '59.0.0.0/8', '60.0.0.0/8', '61.0.0.0/8', '101.0.0.0/8', '103.0.0.0/8',
        '106.0.0.0/8', '110.0.0.0/8', '111.0.0.0/8', '112.0.0.0/8', '113.0.0.0/8', '114.0.0.0/8', '115.0.0.0/8',
        '116.0.0.0/8', '117.0.0.0/8', '118.0.0.0/8', '119.0.0.0/8', '120.0.0.0/8', '121.0.0.0/8', '122.0.0.0/8',
        '123.0.0.0/8', '124.0.0.0/8', '125.0.0.0/8', '126.0.0.0/8', '133.0.0.0/8', '150.0.0.0/8', '153.0.0.0/8',
        '163.0.0.0/8', '171.0.0.0/8', '175.0.0.0/8', '180.0.0.0/8', '182.0.0.0/8', '183.0.0.0/8', '202.0.0.0/8',
        '203.0.0.0/8', '210.0.0.0/8', '211.0.0.0/8', '218.0.0.0/8', '219.0.0.0/8', '220.0.0.0/8', '221.0.0.0/8',
        '222.0.0.0/8', '223.0.0.0/8', '2001:200::/23', '2001:4400::/23', '2001:8000::/19', '2001:a000::/20',
        '2001:b000::/20', '2001:c00::/23', '2001:e00::/23', '2400::/12', '2410::/12',
    ],
    ARIN: [
        '3.0.0.0/8', '4.0.0.0/8', '6.0.0.0/8', '7.0.0.0/8', '8.0.0.0/8', '9.0.0.0/8', '11.0.0.0/8', '12.0.0.0/8',
        '13.0.0.0/8', '15.0.0.0/8', '16.0.0.0/8', '17.0.0.0/8', '18.0.0.0/8', '19.0.0.0/8', '20.0.0.0/8',
        '21.0.0.0/8', '22.0.0.0/8', '23.0.0.0/8', '24.0.0.0/8', '26.0.0.0/8', '28.0.0.0/8', '29.0.0.0/8',
        '30.0.0.0/8', '32.0.0.0/8', '33.0.0.0/8', '34.0.0.0/8', '35.0.0.0/8', '38.0.0.0/8', '40.0.0.0/8',
        '44.0.0.0/8', '45.0.0.0/8', '47.0.0.0/8', '48.0.0.0/8', '50.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8',
        '55.0.0.0/8', '56.0.0.0/8', '63.0.0.0/8', '64.0.0.0/8', '65.0.0.0/8', '66.0.0.0/8', '67.0.0.0/8',
        '68.0.0.0/8', '69.0.0.0/8', '70.0.0.0/8', '71.0.0.0/8', '72.0.0.0/8', '73.0.0.0/8', '74.0.0.0/8',
        '75.0.0.0/8', '76.0.0.0/8', '96.0.0.0/8', '97.0.0.0/8', '98.0.0.0/8', '99.0.0.0/8', '100.0.0.0/8',
        '104.0.0.0/8', '107.0.0.0/8', '108.0.0.0/8', '128.0.0.0/8', '129.0.0.0/8', '130.0.0.0/8', '131.0.0.0/8',
        '132.0.0.0/8', '134.0.0.0/8', '135.0.0.0/8', '136.0.0.0/8', '137.0.0.0/8', '138.0.0.0/8', '139.0.0.0/8',
        '140.0.0.0/8', '142.0.0.0/8', '143.0.0.0/8', '144.0.0.0/8', '146.0.0.0/8', '147.0.0.0/8', '148.0.0.0/8',
        '149.0.0.0/8', '152.0.0.0/8', '155.0.0.0/8', '156.0.0.0/8', '157.0.0.0/8', '158.0.0.0/8', '159.0.0.0/8',
        '160.0.0.0/8', '161.0.0.0/8', '162.0.0.0/8', '164.0.0.0/8', '165.0.0.0/8', '166.0.0.0/8', '167.0.0.0/8',
        '168.0.0.0/8', '169.0.0.0/8', '170.0.0.0/8', '172.0.0.0/8', '173.0.0.0/8', '174.0.0.0/8', '184.0.0.0/8',
        '192.0.0.0/8', '198.0.0.0/8', '199.0.0.0/8', '204.0.0.0/8', '205.0.0.0/8', '206.0.0.0/8', '207.0.0.0/8',
        '208.0.0.0/8', '209.0.0.0/8', '214.0.0.0/8', '215.0.0.0/8', '216.0.0.0/8', '2001:1800::/23', '2001:400::/23',
        '2001:4800::/23', '2600::/12', '2610::/23', '2620::/23', '2630::/12',
    ],
    LACNIC: [
        '177.0.0.0/8', '179.0.0.0/8', '181.0.0.0/8', '186.0.0.0/8', '187.0.0.0/8', '189.0.0.0/8', '190.0.0.0/8',
        '191.0.0.0/8', '200.0.0.0/8', '201.0.0.0/8', '2001:1200::/23', '2800::/12',
    ],
    RIPE: [
        '2.0.0.0/8', '5.0.0.0/8', '25.0.0.0/8', '31.0.0.0/8', '37.0.0.0/8', '46.0.0.0/8', '51.0.0.0/8', '53.0.0.0/8',
        '57.0.0.0/8', '62.0.0.0/8', '77.0.0.0/8', '78.0.0.0/8', '79.0.0.0/8', '80.0.0.0/8', '81.0.0.0/8',
        '82.0.0.0/8', '83.0.0.0/8', '84.0.0.0/8', '85.0.0.0/8', '86.0.0.0/8', '87.0.0.0/8', '88.0.0.0/8',
        '89.0.0.0/8', '90.0.0.0/8', '91.0.0.0/8', '92.0.0.0/8', '93.0.0.0/8', '94.0.0.0/8', '95.0.0.0/8',
        '109.0.0.0/8', '141.0.0.0/8', '145.0.0.0/8', '151.0.0.0/8', '176.0.0.0/8', '178.0.0.0/8', '185.0.0.0/8',
        '188.0.0.0/8', '193.0.0.0/8', '194.0.0.0/8', '195.0.0.0/8', '212.0.0.0/8', '213.0.0.0/8', '217.0.0.0/8',
        '2001:1400::/22', '2001:1a00::/23', '2001:1c00::/22', '2001:2000::/19', '2001:4000::/23', '2001:4600::/23',
        '2001:4a00::/23', '2001:4c00::/23', '2001:5000::/20', '2001:600::/23', '2001:800::/22', '2003::/18',
        '2a00::/12', '2a10::/12',
    ],
};
const RDAP_RANGES = Object.entries(RDAP_BOOTSTRAP).flatMap(([registry, cidrs]) =>
    cidrs.map((cidr) => {
        const [base, bits] = cidr.split('/');
        const v6 = base.includes(':');
        const size = 1n << ((v6 ? 128n : 32n) - BigInt(bits));
        const start = ipToBigInt(base)!;
        return { registry, v6, start, end: start + size - 1n, bits: Number(bits) };
    }),
);

/** The most specific bootstrap entry covering this address. */
function registryOf(ip: string): string {
    const addr = ipToBigInt(ip);
    if (addr === null) return '';
    const v6 = ip.includes(':');
    let best: (typeof RDAP_RANGES)[number] | undefined;
    for (const range of RDAP_RANGES) {
        if (range.v6 === v6 && range.start <= addr && addr <= range.end && (!best || range.bits > best.bits)) {
            best = range;
        }
    }
    return best?.registry ?? '';
}

/** Takes turns across the groups, so a clustered selection does not send one registry a burst. */
function roundRobin<T>(items: T[], keyOf: (item: T) => string): T[] {
    const groups = new Map<string, T[]>();
    for (const item of items) {
        const key = keyOf(item);
        groups.set(key, [...(groups.get(key) ?? []), item]);
    }
    const ordered: T[] = [];
    const lists = [...groups.values()];
    for (let round = 0; ordered.length < items.length; round++) {
        for (const list of lists) if (round < list.length) ordered.push(list[round]);
    }
    return ordered;
}

// =====================================================================================
// Plugin 1 — RDAP IP (allocation / ownership)
// =====================================================================================
const rdapIp = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.rdap_ip',
        content_type: 'vineyard:plugin',
        name: 'RDAP IP',
        version: '1.1.1',
        description:
            'Looks up each selected IP Address in RDAP. Creates a Netblock node (CIDR, network name, country) linked "within netblock" and fills the IP\'s organization and country_code if empty.',
        icon: 'boxes',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: { primary: 'web', web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' } },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'netblock' },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'node:update', 'edge:create'],
            network: [
                {
                    endpoint: 'https://rdap.org/',
                    methods: ['GET'],
                    purpose: "Look up each selected IP's netblock and owner in RDAP.",
                },
            ],
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },
    async run(ctx): Promise<RunResult> {
        if (!ctx.net?.fetch)
            return { summary: 'Network capability not granted to this plugin', counts: { netblocks: 0 } };
        const ids = ctx.input.selection;
        if (!ids.length) return { summary: 'Select one or more IP Address nodes first', counts: { netblocks: 0 } };

        const netByCidr = new Map<string, string>(); // cidr -> netblock node id (reuse within a run)
        // Nothing is kept between runs: this only saves asking again for an address the same run
        // already has the answer to.
        const assignments: { v6: boolean; start: bigint; end: bigint; doc: any }[] = [];
        let netblocks = 0;
        let updated = 0;
        let lookups = 0;
        let reused = 0;

        const targets: { id: string; node: GraphNode; ip: string }[] = [];
        for (const id of ids) {
            const node = await ctx.graph!.get!(id);
            if (!node || !isIp(node)) continue;
            const ip = ipOf(node);
            if (ip) targets.push({ id, node, ip });
        }
        const ordered = roundRobin(targets, (t) => registryOf(t.ip));

        for (let i = 0; i < ordered.length; i++) {
            if (ctx.signal?.aborted) break;
            const { id, node, ip } = ordered[i];
            ctx.progress?.set?.({ percent: Math.round(((i + 1) / ordered.length) * 100), message: `RDAP ${ip}` });

            const addr = ipToBigInt(ip);
            const v6 = ip.includes(':');
            let doc: any =
                addr === null
                    ? undefined
                    : assignments.find((a) => a.v6 === v6 && a.start <= addr && addr <= a.end)?.doc;
            if (doc) {
                reused++;
            } else {
                try {
                    lookups++;
                    const res = await ctx.net!.fetch!(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
                        method: 'GET',
                    });
                    if (!res.ok) continue;
                    doc = await res.json();
                } catch {
                    continue;
                }
                const start = ipToBigInt(String(doc?.startAddress ?? ''));
                const end = ipToBigInt(String(doc?.endAddress ?? ''));
                if (
                    isEndAssignment(doc) &&
                    start !== null &&
                    end !== null &&
                    String(doc.startAddress).includes(':') === v6
                ) {
                    assignments.push({ v6, start, end, doc });
                }
            }

            const c0 = Array.isArray(doc.cidr0_cidrs) && doc.cidr0_cidrs[0];
            const cidr = c0
                ? `${c0.v4prefix ?? c0.v6prefix}/${c0.length}`
                : doc.startAddress && doc.endAddress
                ? `${doc.startAddress} - ${doc.endAddress}`
                : '';
            const country = cc2(doc.country);
            const org = holderOf(doc);

            if (cidr) {
                let netId = netByCidr.get(cidr);
                if (!netId) {
                    const netNode = await ctx.graph!.createNode!({
                        type: 'infrastructure.netblock',
                        data: {
                            cidr,
                            ...(doc.name ? { network_name: String(doc.name) } : {}),
                            ...(country ? { country_code: country } : {}),
                        },
                    });
                    netId = String(netNode.id);
                    netByCidr.set(cidr, netId);
                    netblocks++;
                }
                await ctx.graph!.createEdge!({ from: id, to: netId, label: 'within netblock' });
            }

            // Delta only — updateNode fill-merges what we send onto the live row at apply time.
            // Spreading ...node.data would re-send a stale copy of every other field and overwrite
            // whatever another run filled in between this read and the apply (the geolocation plugin
            // writes country_code and organization too, so the two clobbered each other).
            const patch: Record<string, unknown> = {};
            if (org && !node.data.organization) patch.organization = org;
            if (country && !node.data.country_code) patch.country_code = country;
            if (Object.keys(patch).length) {
                await ctx.graph!.updateNode!(id, patch);
                updated++;
            }
        }
        return {
            summary:
                `${netByCidr.size} netblock(s), ${updated} IP(s) enriched from RDAP` +
                (reused ? ` (${lookups} lookup(s); ${reused} answered from an assignment already fetched in this run)` : ''),
            counts: { netblocks: netByCidr.size, ips_updated: updated, rdap_requests: lookups, reused_in_run: reused },
        };
    },
});

// =====================================================================================
// Plugin 2 — Shodan InternetDB (free, keyless exposure data)
// =====================================================================================
/** Best-effort OS string from a Shodan CPE list (cpe:/o:vendor:product or cpe:2.3:o:vendor:product:...). */
function osFromCpes(cpes: string[]): string {
    for (const cpe of cpes || []) {
        const m = /cpe:(?:2\.3:)?\/?o:([^:]+):([^:]+)/i.exec(cpe);
        if (m) return `${m[1]} ${m[2]}`.replace(/_/g, ' ').trim();
    }
    return '';
}

const shodanInternetdb = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.shodan_internetdb',
        content_type: 'vineyard:plugin',
        name: 'Shodan InternetDB',
        version: '1.1.0',
        description:
            'Looks up each selected IP Address in Shodan InternetDB. Creates a Host node with the open ports (and OS when known) linked "exposes", Vulnerability nodes for known CVEs linked "affected by", and Domain nodes for reverse hostnames linked "resolves to", and writes Shodan\'s tags for the IP (e.g. cdn, cloud, honeypot, self-signed) onto it as shodan_tags.',
        icon: 'radar',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: { primary: 'web', web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' } },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'host' },
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'vulnerability' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'node:update', 'edge:create'],
            network: [
                {
                    endpoint: 'https://internetdb.shodan.io/',
                    methods: ['GET'],
                    purpose:
                        'Look up open ports, known CVEs, hostnames and tags for each selected IP in Shodan InternetDB.',
                },
            ],
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },
    async run(ctx): Promise<RunResult> {
        if (!ctx.net?.fetch)
            return { summary: 'Network capability not granted to this plugin', counts: { enriched: 0 } };
        const ids = ctx.input.selection;
        if (!ids.length) return { summary: 'Select one or more IP Address nodes first', counts: { enriched: 0 } };

        let hosts = 0;
        let vulns = 0;
        let hostnames = 0;
        let enriched = 0;
        const tagSet = new Set<string>();
        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) break;
            const node = await ctx.graph!.get!(ids[i]);
            if (!node || !isIp(node)) continue;
            const ip = ipOf(node);
            if (!ip) continue;
            ctx.progress?.set?.({ percent: Math.round(((i + 1) / ids.length) * 100), message: `InternetDB ${ip}` });

            let doc: { ports?: number[]; cpes?: string[]; hostnames?: string[]; tags?: string[]; vulns?: string[] };
            try {
                const res = await ctx.net!.fetch!(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
                    method: 'GET',
                });
                if (!res.ok) continue; // 404 = no data for this IP
                doc = (await res.json()) as any;
            } catch {
                continue;
            }
            const ports = doc.ports || [];
            const cves = doc.vulns || [];
            const names = doc.hostnames || [];
            const tags = (doc.tags || []).map(String).filter(Boolean);
            tags.forEach((t) => tagSet.add(t));
            if (!ports.length && !cves.length && !names.length && !tags.length) continue;
            enriched++;

            // Tags are a fact about this IP (cdn, cloud, honeypot, self-signed …), so they go on it —
            // a delta — under the same key Shodan Host writes.
            if (tags.length) await ctx.graph!.updateNode!(ids[i], { shodan_tags: tags.join(', ') });

            // Open ports → a Host node (service surface of this IP)
            if (ports.length) {
                const os = osFromCpes(doc.cpes || []);
                // Identity MUST be the IP: distinct IPs can share a reverse hostname (CDN/shared
                // hosting), and keying the Host node on that would collapse them and misattribute
                // ports. The reverse hostnames are captured separately as Domain nodes below.
                const hostNode = await ctx.graph!.createNode!({
                    type: 'infrastructure.host',
                    data: {
                        hostname: ip,
                        open_ports: [...ports].sort((a, b) => a - b).join(', '),
                        ...(os ? { operating_system: os } : {}),
                    },
                });
                await ctx.graph!.createEdge!({ from: ids[i], to: String(hostNode.id), label: 'exposes' });
                hosts++;
            }
            // Known CVEs → Vulnerability nodes
            for (const cve of cves) {
                if (!/^CVE-\d{4}-\d{4,}$/i.test(cve)) continue;
                const vNode = await ctx.graph!.createNode!({
                    type: 'threat.vulnerability',
                    data: { cve_id: String(cve).toUpperCase() },
                });
                await ctx.graph!.createEdge!({ from: ids[i], to: String(vNode.id), label: 'affected by' });
                vulns++;
            }
            // Reverse hostnames → Domain nodes
            for (const name of names) {
                const dn = String(name).trim().toLowerCase();
                if (!dn) continue;
                const dNode = await ctx.graph!.createNode!({
                    type: 'infrastructure.domain',
                    data: { domain_name: dn },
                });
                await ctx.graph!.createEdge!({ from: ids[i], to: String(dNode.id), label: 'resolves to' });
                hostnames++;
            }
        }
        const tags = tagSet.size ? ` · tags: ${[...tagSet].slice(0, 12).join(', ')}` : '';
        return {
            summary: `${enriched} IP(s): ${hosts} host(s), ${vulns} CVE(s), ${hostnames} hostname(s)${tags}`,
            counts: { enriched, hosts, vulnerabilities: vulns, hostnames },
        };
    },
});

// =====================================================================================
// Plugin 3 — IP Geolocation (ipwho.is)
// =====================================================================================
const ipGeolocation = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.ip_geolocation',
        content_type: 'vineyard:plugin',
        name: 'IP Geolocation',
        version: '1.0.2',
        description:
            'Geolocates each selected IP Address via ipwho.is. Creates a Location node (city, region, country, latitude/longitude) linked "geolocated to" and fills the IP\'s country_code and organization if empty.',
        icon: 'map-pin',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: { primary: 'web', web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' } },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
            ],
            produces: [{ typepack: 'run.vineyard.typepacks.geo', category: 'geo', name: 'location' }],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'node:update', 'edge:create'],
            network: [
                {
                    endpoint: 'https://ipwho.is/',
                    methods: ['GET'],
                    purpose: "Look up each selected IP's approximate location and ISP.",
                },
            ],
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },
    async run(ctx): Promise<RunResult> {
        if (!ctx.net?.fetch)
            return { summary: 'Network capability not granted to this plugin', counts: { located: 0 } };
        const ids = ctx.input.selection;
        if (!ids.length) return { summary: 'Select one or more IP Address nodes first', counts: { located: 0 } };

        let located = 0;
        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) break;
            const node = await ctx.graph!.get!(ids[i]);
            if (!node || !isIp(node)) continue;
            const ip = ipOf(node);
            if (!ip) continue;
            ctx.progress?.set?.({ percent: Math.round(((i + 1) / ids.length) * 100), message: `Geolocating ${ip}` });

            let doc: any;
            try {
                const res = await ctx.net!.fetch!(`https://ipwho.is/${encodeURIComponent(ip)}`, { method: 'GET' });
                if (!res.ok) continue;
                doc = await res.json();
            } catch {
                continue;
            }
            if (!doc || doc.success === false) continue;

            const city = String(doc.city ?? '').trim();
            const region = String(doc.region ?? '').trim();
            const country = String(doc.country ?? '').trim();
            const cc = cc2(doc.country_code);
            const name = [city || region, cc || country].filter(Boolean).join(', ') || country || ip;

            const locNode = await ctx.graph!.createNode!({
                type: 'geo.location',
                data: {
                    name,
                    ...(Number.isFinite(doc.latitude) ? { latitude: Number(doc.latitude) } : {}),
                    ...(Number.isFinite(doc.longitude) ? { longitude: Number(doc.longitude) } : {}),
                    ...(city ? { city } : {}),
                    ...(region ? { region } : {}),
                    ...(country ? { country } : {}),
                },
            });
            await ctx.graph!.createEdge!({ from: ids[i], to: String(locNode.id), label: 'geolocated to' });
            located++;

            // Delta only, for the same reason as the RDAP plugin above: RDAP IP fills these two
            // fields as well, and a full-snapshot patch from whichever ran second put back the copy
            // it had read before the first one's changes landed.
            const org = String(doc?.connection?.isp ?? doc?.connection?.org ?? '').trim();
            const patch: Record<string, unknown> = {};
            if (cc && !node.data.country_code) patch.country_code = cc;
            if (org && !node.data.organization) patch.organization = org;
            if (Object.keys(patch).length) await ctx.graph!.updateNode!(ids[i], patch);
        }
        return { summary: `${located}/${ids.length} IP(s) geolocated`, counts: { located } };
    },
});

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.ip_recon',
    content_type: 'vineyard:pluginpack',
    name: 'IP Recon',
    version: '2.0.1',
    description:
        'Enriches IP Address nodes with RDAP allocation, Shodan InternetDB open ports/CVEs/hostnames/tags, and geolocation.',
    plugins: [rdapIp, shodanInternetdb, ipGeolocation],
});
