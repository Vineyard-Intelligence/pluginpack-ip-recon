# IP Recon

A Vineyard **plugin pack** for passive, keyless enrichment of **IP Address** nodes. Everything runs
in the browser sandbox — no server, no API key, no cost. Every endpoint is CORS-enabled and free, and
these views complement the Team Cymru **IP → ASN** pack (routing) with allocation, exposure and geo.

Three plugins:

- **RDAP IP** — looks up the IP's allocation in **RDAP** (`rdap.org` bootstrap): adds the owning
  **Netblock** node (CIDR / network name / country, linked `within netblock`) and fills the IP's
  organization + country.
- **Shodan InternetDB** — enriches the IP from Shodan's **free, keyless** InternetDB: open ports become
  a **Host** node (`exposes`), known CVEs become **Vulnerability** nodes (`affected by`), and reverse
  hostnames become **Domain** nodes (`resolves to`).
- **IP Geolocation** — adds an approximate **Location** node (city / country / lat-lon) via `ipwho.is`,
  linked `geolocated to`, and fills the IP's country + organization if empty.

## How it works

- **RDAP** returns allocation JSON with permissive CORS. `rdap.org` 302-redirects to the authoritative
  RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC); the browser follows it and the final response also sends CORS.
  The CIDR is taken from `cidr0_cidrs`, falling back to the start/end address range.
- **Shodan InternetDB** (`internetdb.shodan.io/<ip>`) is a keyless endpoint returning an IP's open
  ports, CPEs, hostnames, tags and known CVEs — with `access-control-allow-origin: *`. A `404` simply
  means Shodan has no data for that IP (handled gracefully).
- **ipwho.is** provides keyless geolocation with CORS. Geolocation is **approximate** — verify before
  relying on it.

Enrichment reuses nodes by identity (e.g. one Netblock per CIDR, one Vulnerability per CVE) and never
overwrites known fields with blanks.

## Layout

- `plugins/ip-recon.manifest.json` — the pack manifest (catalog entry source).
- `dist/` — runnable bundle (see note; not built yet — plugins run as built-ins in-app today).

Data sources: the RDAP bootstrap (`rdap.org`), Shodan InternetDB (`internetdb.shodan.io`), and
`ipwho.is`. No credentials, no cost.
