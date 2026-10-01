# IP Recon

A Vineyard **plugin pack** for passive, keyless enrichment of **IP Address** nodes. Everything runs
in the browser sandbox — no server, no API key, no cost. Every endpoint is CORS-enabled and free, and
these views complement the Team Cymru **IP → ASN** pack (routing) with allocation, exposure and geo.

Four plugins:

- **RDAP IP** — looks up the IP in **RDAP**: creates a **Netblock** node (CIDR, network name,
  country) linked `within netblock` and fills the IP's organization and country_code if empty.
- **Shodan InternetDB** — looks up the IP in Shodan InternetDB: creates a **Host** node with the
  open ports (and OS when known) linked `exposes`, **Vulnerability** nodes for known CVEs linked
  `affected by`, and **Domain** nodes for reverse hostnames linked `resolves to`.
- **IP Geolocation** — geolocates the IP via `ipwho.is`: creates a **Location** node (city, region,
  country, latitude/longitude) linked `geolocated to` and fills the IP's country_code and
  organization if empty.
- **Tor Exit Node** — checks the IP against the Tor Project's list of exit relays and sets
  `is_tor_exit` (true/false) and `tor_exit_checked_at` on the IP. Creates no nodes.

## How it works

- **RDAP** lookups go to `rdap.org`, which redirects to the authoritative RIR
  (ARIN/RIPE/APNIC/LACNIC/AFRINIC). The CIDR is taken from `cidr0_cidrs`, falling back to the
  start/end address range.
- **Shodan InternetDB** (`internetdb.shodan.io/<ip>`) is a keyless endpoint returning an IP's open
  ports, CPEs, hostnames, tags and known CVEs. A `404` simply means Shodan has no data for that IP
  (handled gracefully).
- **ipwho.is** provides keyless geolocation. Geolocation is **approximate** — verify before relying
  on it.

Enrichment reuses nodes by identity (e.g. one Netblock per CIDR, one Vulnerability per CVE) and never
overwrites known fields with blanks.

## Layout

- `plugins/ip-recon.manifest.json` — the pack manifest (catalog entry source).
- `dist/pack.mjs` — the runnable bundle.

Data sources: the RDAP bootstrap (`rdap.org`), Shodan InternetDB (`internetdb.shodan.io`), and
`ipwho.is`. No credentials, no cost.
