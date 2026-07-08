<br />
<div align="center">

<pre>
  ____
 |  _ \ ___  ___ ___  _ __ __  __
 | |_) / _ \/ __/ _ \| '_ \\ \/ /
 |  _ <  __/ (_| (_) | | | |>  <
 |_| \_\___|\___\___/|_| |_/_/\_\
</pre>

**Fast, passive-only OSINT reconnaissance tool for subdomain enumeration, asset discovery, and domain intelligence gathering.**

[![Rust](https://img.shields.io/badge/Built_with-Rust-orange?logo=rust&style=flat-square)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Passive](https://img.shields.io/badge/Mode-Passive_Only-green?style=flat-square)](#)
[![Sources](https://img.shields.io/badge/Data_Sources-24+-purple?style=flat-square)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux_%7C_macOS_%7C_Windows-lightgrey?style=flat-square)](#)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Commands](#-commands) • [API Keys](#-api-keys) • [Reports](#-reports) • [Architecture](#-architecture)

</div>

---

## Why Reconx?

Reconx replaces the need to juggle SpiderFoot, Amass, theHarvester, and Recon-NG separately. One command queries **24+ passive data sources** concurrently, correlates results, scores risk, and generates professional reports — all without sending a single packet to the target.

| | Reconx | Amass | SpiderFoot | theHarvester |
|---|:---:|:---:|:---:|:---:|
| **Passive only** | Yes | Partial | No | Yes |
| **Concurrent sources** | 24+ | ~10 | 200+ (active) | ~15 |
| **Subdomain enum** | Yes | Yes | Yes | Yes |
| **Credential leaks** | Yes | No | Yes | Yes |
| **Wireless discovery** | Yes | No | No | No |
| **Asset mapping** | Yes | Partial | Yes | No |
| **HTML reports** | Yes | No | Yes | No |
| **Single binary** | Yes | Yes | No (Python) | No (Python) |
| **Speed** | <60s | ~5min | ~10min | ~2min |

---

## Features

- **24+ Passive Data Sources** — crt.sh, VirusTotal, Shodan, SecurityTrails, AlienVault OTX, HackerTarget, Wayback Machine, Common Crawl, Have I Been Pwned, GitHub, Wigle.net, and more
- **Concurrent Execution** — All collectors run in parallel via Tokio async runtime with configurable concurrency limits
- **Zero Active Scanning** — 100% passive reconnaissance. No port scans, no direct probing, no noise
- **Multi-Format Reports** — Self-contained HTML with dark theme, structured JSON, and flat CSV exports
- **Risk Scoring** — Automated risk assessment based on exposed surface area
- **Credential Leak Detection** — Searches breach databases, paste sites, and code repositories for leaked secrets
- **Wireless Network Discovery** — Queries Wigle.net for publicly known wireless networks associated with the target
- **Attack Surface Mapping** — Correlates subdomains, IPs, ports, services, and technologies into a unified view
- **Single Static Binary** — No runtime dependencies. Drop it anywhere and run

---

## Installation

### From Source

Requires [Rust](https://rustup.rs/) 1.70+.

```bash
git clone https://github.com/reconx/reconx.git
cd reconx
cargo build --release
```

The binary will be at `target/release/reconx`.

### Quick Install (Linux/macOS)

```bash
curl -L https://github.com/reconx/reconx/releases/latest/download/reconx-linux-amd64 -o reconx
chmod +x reconx
sudo mv reconx /usr/local/bin/
```

### Windows

Download the latest `.exe` from [Releases](https://github.com/reconx/reconx/releases) and add it to your PATH.

---

## Quick Start

```bash
# Subdomain enumeration (no API keys needed)
reconx enum -d example.com

# Full intelligence sweep
reconx intel -d example.com -v

# Find leaked credentials
reconx creds -d example.com -n "Example Corp"

# Discover wireless networks
reconx wireless -n "Example Corp"

# Generate reports from previous scan
reconx report -i findings.json -f html,csv
```

---

## Commands

### `reconx enum` — Subdomain Enumeration

Discovers subdomains from certificate transparency logs, passive DNS databases, search engines, and web archives.

```bash
reconx enum -d example.com
reconx enum -d example.com --sources crtsh,hackertarget,wayback
reconx enum -d example.com --exclude dnsdumpster -c 20 -t 60
```

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --domain` | Target domain | *required* |
| `-o, --output` | Output directory | `./reconx-output/<domain>/<timestamp>/` |
| `-f, --format` | Report formats (comma-separated) | `html,json,csv` |
| `-c, --concurrency` | Max parallel collectors | `10` |
| `-t, --timeout` | Per-source timeout (seconds) | `30` |
| `--sources` | Run only specific sources | all available |
| `--exclude` | Exclude specific sources | none |
| `-v, --verbose` | Show detailed collector logs | off |
| `-q, --quiet` | Suppress progress output | off |
| `--no-color` | Disable colored terminal output | off |

**Sources queried:** crt.sh, HackerTarget, DNSDumpster, Anubis, ThreatHunter, ThreatMiner, Wayback Machine, Common Crawl, DuckDuckGo, VirusTotal*, SecurityTrails*, AlienVault OTX*, URLScan*, FullHunt*, Censys*, IntelX*, CertStream

*Requires API key

---

### `reconx assets` — Asset Discovery

Discovers public-facing IPs, open ports, running services, and technology stacks from passive host databases.

```bash
reconx assets -d example.com
reconx assets -d example.com -f json
```

**Sources queried:** Shodan (passive), Censys (passive), BGPView, IPinfo, HackerTarget

---

### `reconx creds` — Credential & Breach Detection

Searches breach databases, paste sites, and code repositories for leaked credentials, API keys, and sensitive data associated with the target domain.

```bash
reconx creds -d example.com
reconx creds -d example.com -n "Example Corporation"
```

| Flag | Description |
|------|-------------|
| `-n, --name` | Organization name for broader search |

**Sources queried:** Have I Been Pwned, IntelX, GitHub code search, Pastebin

---

### `reconx wireless` — Wireless Network Discovery

Queries the Wigle.net wardriving database for publicly known wireless networks associated with the target organization.

```bash
reconx wireless -n "Example Corp"
reconx wireless -n "Example Corp" -f html,json
```

**Sources queried:** Wigle.net

**Data returned:** SSID, BSSID, encryption type, channel, geolocation, last seen date

---

### `reconx intel` — Full Intelligence Sweep

Runs **all** available modules in a single pass. The most comprehensive scan mode.

```bash
reconx intel -d example.com
reconx intel -d example.com -n "Example Corp" -v
reconx intel -d example.com --sources crtsh,shodan,hibp -f html
```

Accepts all flags from `enum` plus `-n, --name` for organization-level searches.

---

### `reconx report` — Report Generation

Generates reports from a previously saved JSON scan result.

```bash
reconx report -i ./reconx-output/example.com/20260708_120000/findings.json
reconx report -i findings.json -f html -o ./my-reports/
```

---

### `reconx config` — API Key Management

```bash
# Set an API key
reconx config set virustotal YOUR_API_KEY_HERE
reconx config set shodan YOUR_API_KEY_HERE

# View a key (masked)
reconx config get virustotal

# List all configured keys
reconx config list

# Show config file location
reconx config path
```

---

## API Keys

Reconx works out of the box with **10 free sources** that require no API keys. Configure API keys to unlock the full power of **24+ sources**.

### Configuring Keys

**Option 1: CLI (recommended)**
```bash
reconx config set <source> <api_key>
```

**Option 2: Config file**

Edit `~/.config/reconx/config.toml` (Linux/macOS) or `%APPDATA%\reconx\config.toml` (Windows):

```toml
concurrency = 10
timeout_secs = 30

[api_keys]
virustotal = "your-api-key"
shodan = "your-api-key"
securitytrails = "your-api-key"
alienvault = "your-api-key"
urlscan = "your-api-key"
fullhunt = "your-api-key"
censys = "id:secret"
intelx = "your-api-key"
hibp = "your-api-key"
github = "your-github-token"
wigle = "your-api-key"
ipinfo = "your-api-key"
```

### Complete API Key Reference

| Source | Key Name | Free Tier | Sign Up |
|--------|----------|-----------|---------|
| **VirusTotal** | `virustotal` | 500 req/day | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **Shodan** | `shodan` | 100 results/query | [shodan.io](https://account.shodan.io/register) |
| **SecurityTrails** | `securitytrails` | 50 req/month | [securitytrails.com](https://securitytrails.com/app/signup) |
| **AlienVault OTX** | `alienvault` | Unlimited | [otx.alienvault.com](https://otx.alienvault.com/) |
| **URLScan** | `urlscan` | 100 req/day | [urlscan.io](https://urlscan.io/user/signup) |
| **FullHunt** | `fullhunt` | 50 req/month | [fullhunt.io](https://fullhunt.io/) |
| **Censys** | `censys` | 250 req/month | [search.censys.io](https://search.censys.io/register) |
| **Intelligence X** | `intelx` | Limited free | [intelx.io](https://intelx.io/signup) |
| **Have I Been Pwned** | `hibp` | 10 req/min | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) |
| **GitHub** | `github` | 30 req/min | [github.com/settings/tokens](https://github.com/settings/tokens) |
| **Wigle.net** | `wigle` | 100 req/day | [wigle.net](https://wigle.net/register) |
| **IPinfo** | `ipinfo` | 50k req/month | [ipinfo.io](https://ipinfo.io/signup) |

> **Note:** Censys uses `id:secret` format (e.g., `reconx config set censys "abc123:def456"`)

### Sources That Need No API Key

These work immediately out of the box:

| Source | Category |
|--------|----------|
| crt.sh | Certificate Transparency |
| HackerTarget | DNS/Subdomain |
| DNSDumpster | DNS/Subdomain |
| Anubis | DNS/Subdomain |
| ThreatHunter | Threat Intel |
| ThreatMiner | Threat Intel |
| Wayback Machine | Web Archives |
| Common Crawl | Web Archives |
| DuckDuckGo | Search Engine |
| BGPView | WHOIS/ASN |
| CertStream | Certificate Transparency |
| Pastebin | Code/Doc Leaks |

---

## Reports

Every scan automatically generates reports in `./reconx-output/<domain>/<timestamp>/`:

### HTML Report

Self-contained single-file report with:
- Executive summary with risk score and metrics cards
- Color-coded severity badges (Critical / High / Medium / Low / Info)
- Collapsible sections per finding category
- Sortable data tables
- Dark theme, works offline

### JSON Export

Full structured data with source attribution and timestamps:
```json
[
  {
    "type": "Subdomain",
    "subdomain": "api.example.com",
    "source": "crt.sh",
    "ip_addresses": ["93.184.216.34"],
    "confidence": 3,
    "discovered_at": "2026-07-08T12:00:00Z"
  }
]
```

### CSV Exports

Flat tables per category for pipeline integration:
- `subdomains.csv` — subdomain, source, IPs, confidence, timestamp
- `assets.csv` — host, IP, ports, services, technologies, source, timestamp
- `credentials.csv` — email, breach source, data types, severity, source, timestamp
- `wireless.csv` — SSID, BSSID, encryption, channel, source, timestamp

---

## Architecture

```
reconx/
├── src/
│   ├── main.rs              Entry point & CLI dispatch
│   ├── cli.rs               Subcommand definitions (clap)
│   ├── config.rs            TOML config & API key management
│   ├── error.rs             Unified error types
│   ├── models/              Data structures
│   │   ├── finding.rs       Unified Finding enum & Severity
│   │   ├── subdomain.rs     Subdomain findings
│   │   ├── asset.rs         Asset/host findings
│   │   ├── credential.rs    Credential leak findings
│   │   ├── wireless.rs      Wireless network findings
│   │   └── vulnerability.rs Vulnerability findings
│   ├── collectors/          24 data source modules
│   │   ├── mod.rs           Collector trait & concurrent executor
│   │   ├── crtsh.rs         Certificate Transparency
│   │   ├── virustotal.rs    Passive DNS & subdomains
│   │   ├── shodan.rs        Passive host/service data
│   │   ├── ...              (21 more collectors)
│   │   └── wigle.rs         Wireless network data
│   ├── analyzers/           Intelligence processing
│   │   ├── correlator.rs    Cross-source dedup & merge
│   │   ├── risk_scorer.rs   Automated risk scoring
│   │   ├── tech_fingerprint.rs Technology identification
│   │   └── attack_surface.rs  Attack surface mapping
│   ├── reports/             Output generation
│   │   ├── html.rs          HTML report builder
│   │   ├── json.rs          JSON export
│   │   └── csv.rs           CSV export
│   └── output/              Terminal & file I/O
│       ├── terminal.rs      Progress bars & colored output
│       └── writer.rs        File output orchestration
└── Cargo.toml
```

### Key Design Decisions

- **Collector Trait** — Every data source implements a common async trait, making it trivial to add new sources
- **Arc-based Concurrency** — Collectors are wrapped in `Arc<dyn Collector>` for safe concurrent execution via `tokio::spawn`
- **Semaphore Control** — Configurable concurrency limit prevents API rate limiting and resource exhaustion
- **Graceful Degradation** — Missing API keys are skipped with a warning, not a crash

---

## Advanced Usage

### Pipeline Integration

```bash
# JSON-only output for piping to jq
reconx enum -d example.com -f json -q | jq '.[] | select(.type == "Subdomain") | .subdomain'

# Feed subdomains into another tool
reconx enum -d example.com -f json -q && \
  cat reconx-output/example.com/*/findings.json | \
  jq -r '.[] | select(.type == "Subdomain") | .subdomain' | \
  sort -u > subdomains.txt
```

### Custom Source Selection

```bash
# Only use fast, free sources
reconx enum -d example.com --sources crtsh,hackertarget,anubis,wayback

# Exclude slow sources
reconx enum -d example.com --exclude commoncrawl,certstream
```

### High-Concurrency Scans

```bash
# Max parallelism for fast results
reconx intel -d example.com -c 20 -t 60 -v
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Reconx
  run: |
    reconx intel -d ${{ secrets.TARGET_DOMAIN }} -f json -q
    cat reconx-output/*/findings.json > findings.json
```

---

## Performance

Benchmarked on a standard laptop (4 cores, 16GB RAM):

| Scan Mode | Typical Time | Findings (avg) |
|-----------|-------------|----------------|
| `enum` (free sources only) | 15-30s | 50-500 subdomains |
| `enum` (all sources) | 30-60s | 200-5000 subdomains |
| `intel` (all sources) | 45-90s | 500-10000+ findings |
| `creds` | 10-30s | 0-100 credential leaks |
| `wireless` | 5-15s | 0-50 networks |

Memory usage stays under 200MB even for large domains with 10,000+ subdomains.

---

## Contributing

Contributions are welcome. To add a new data source:

1. Create a new file in `src/collectors/` (e.g., `src/collectors/mysource.rs`)
2. Implement the `Collector` trait:

```rust
use async_trait::async_trait;
use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, Target};

pub struct MySourceCollector;

#[async_trait]
impl Collector for MySourceCollector {
    fn name(&self) -> &str { "mysource" }
    fn category(&self) -> CollectorCategory { CollectorCategory::DnsSubdomain }
    fn requires_api_key(&self) -> bool { false }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        // Your implementation here
        Ok(Vec::new())
    }
}
```

3. Register it in `src/collectors/mod.rs`
4. Submit a pull request

---

## Legal & Ethics

Reconx is designed for **authorized security testing** and **legitimate research** only. Users are responsible for:

- Obtaining proper authorization before scanning any target
- Complying with applicable laws and regulations
- Respecting API terms of service for all data sources
- Using findings responsibly and ethically

Reconx performs **zero active scanning** — it only queries publicly available data sources and APIs.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with Rust for speed, safety, and simplicity.**

`cargo build --release && ./target/release/reconx intel -d target.com`

</div>
