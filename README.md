<br />
<div align="center">

<pre>
  ____
 |  _ \ ___  ___ ___  _ __ __  __
 | |_) / _ \/ __/ _ \| '_ \\ \/ /
 |  _ <  __/ (_| (_) | | | |>  <
 |_| \_\___|\___\___/|_| |_/_/\_\
</pre>

**Fast, passive-only OSINT reconnaissance tool for subdomain enumeration, asset discovery, credential leak detection, and full domain intelligence.**

[![Rust](https://img.shields.io/badge/Built_with-Rust-orange?logo=rust&style=flat-square)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Passive](https://img.shields.io/badge/Mode-Passive_Only-green?style=flat-square)](#)
[![Sources](https://img.shields.io/badge/Data_Sources-36-purple?style=flat-square)](#-data-sources)
[![Platform](https://img.shields.io/badge/Platform-Linux_%7C_macOS_%7C_Windows-lightgrey?style=flat-square)](#)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Commands](#-commands) • [Data Sources](#-data-sources) • [API Keys](#-api-keys) • [Reports](#-reports) • [Architecture](#-architecture)

</div>

---

## Why Reconx?

Reconx replaces the need to juggle SpiderFoot, Amass, theHarvester, and Recon-NG separately. One command queries **36 passive data sources** concurrently, correlates results with confidence scoring, detects subdomain takeover vulnerabilities, enriches data with WHOIS intelligence, scores risk, and generates professional reports — all without sending a single packet to the target.

| | Reconx | Amass | SpiderFoot | theHarvester |
|---|:---:|:---:|:---:|:---:|
| **Passive only** | ✅ | Partial | Partial | ✅ |
| **Concurrent sources** | 36 | ~30+ | 200+ (active/passive) | ~15 |
| **Subdomain enum** | ✅ | ✅ | ✅ | ✅ |
| **Credential leaks** | ✅ | ❌ | ✅ | ✅ |
| **Subdomain takeover** | ✅ | ❌ | ❌ | ❌ |
| **WHOIS intelligence** | ✅ | ✅ | ✅ | ❌ |
| **Wireless discovery** | ✅ | ❌ | ❌ | ❌ |
| **Asset mapping** | ✅ | Partial | ✅ | ❌ |
| **Risk scoring** | ✅ | ❌ | ❌ | ❌ |
| **Historical diff** | ✅ | ❌ | ❌ | ❌ |
| **HTML + Markdown reports** | ✅ | ❌ | ✅ | ❌ |
| **Single binary** | ✅ | ✅ | ❌ (Python) | ❌ (Python) |
| **Execution Speed** | Very Fast | Slow | Slow | Fast |

---

## ✨ Features

### Core Intelligence
- **36 Passive Data Sources** — Certificate transparency, DNS, threat intel, search engines, breach databases, code leaks, wireless networks, and more
- **Concurrent Execution** — All collectors run in parallel via Tokio async runtime with configurable concurrency limits
- **Zero Active Scanning** — 100% passive reconnaissance. No port scans, no direct probing, no noise

### Analysis & Enrichment
- **🎯 Subdomain Takeover Detection** — Scans CNAME records against 65+ known vulnerable service fingerprints (AWS S3, Azure, Heroku, GitHub Pages, Netlify, etc.)
- **📋 WHOIS Intelligence** — Passive RDAP lookup for registrar, registration dates, expiry alerts, nameservers, and privacy protection status
- **🔒 SSL/TLS Intelligence** — Certificate metadata extraction via crt.sh, SAN discovery, expiry detection, and self-signed cert flagging
- **📊 Risk Scoring** — Weighted 0-10 risk score considering takeover candidates, exposed ports, credential leaks, and SSL issues with ranked Top Risk Factors

### Comparison & Monitoring
- **🔄 Historical Diff Mode** — Compare current scan against a previous JSON export to detect new subdomains, removed assets, and infrastructure drift
- **🔍 Confidence Scoring** — Multi-source correlation ranks subdomains by confidence (found by 3 sources = more reliable than 1)

### Probing
- **🌐 HTTP Probing** — Live web service detection with status codes, titles, and redirect chains
- **🔧 Technology Fingerprinting** — Detects web frameworks, CMS, CDNs, WAFs, and server software
- **🚪 Sensitive Path Detection** — Checks for exposed `/.env`, `/.git/config`, `/admin`, `/swagger-ui/`, `/phpinfo.php`, and more

### Reporting
- **📄 Multi-Format Reports** — HTML, JSON, CSV, and Markdown
- **📊 Executive Summary** — Risk score, top risk factors, and finding statistics
- **🔗 Markdown Reports** — Ready to paste into GitHub Issues, Notion, Obsidian, or pentest reports

---

## 🚀 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/redshadow912/Reconx.git
cd Reconx

# Build optimized release binary
cargo build --release

# Binary will be at ./target/release/reconx
```

### Requirements

- **Rust** 1.70+ ([Install Rust](https://rustup.rs/))
- Internet connection for passive API queries

---

## ⚡ Quick Start

```bash
# Basic subdomain enumeration (no API keys needed)
reconx enum -d example.com

# Full intelligence gathering with all modules
reconx intel -d example.com -v

# Subdomain enumeration with DNS resolution
reconx enum -d example.com --resolve --no-wildcard

# Compare against a previous scan
reconx enum -d example.com --diff ./reconx-output/example.com/20250101_120000/findings.json

# HTTP probe discovered subdomains
reconx probe -d example.com -v

# Asset discovery
reconx assets -d example.com

# Credential leak search
reconx creds -d example.com

# Wireless network discovery
reconx wireless -n "Company Name"
```

---

## 📖 Commands

### `reconx enum` — Subdomain Enumeration

Discovers subdomains from passive sources like certificate transparency logs, DNS databases, search engines, and web archives.

```
Usage: reconx enum [OPTIONS] --domain <DOMAIN>

Options:
  -d, --domain <DOMAIN>            Target domain
  -o, --output <OUTPUT>            Output directory
  -f, --format <FORMAT>            Report formats [possible values: html, json, csv, markdown]
  -c, --concurrency <CONCURRENCY>  Max parallel collectors [default: 10]
  -t, --timeout <TIMEOUT>          Per-source timeout in seconds [default: 30]
      --sources <SOURCES>          Run only specific sources (comma-separated)
      --exclude <EXCLUDE>          Exclude specific sources (comma-separated)
      --resolve                    Resolve subdomains to IP addresses
      --no-wildcard                Filter out wildcard subdomains
      --diff <DIFF>                Compare against previous scan JSON
  -v, --verbose                    Show detailed collector output
  -q, --quiet                      Suppress all progress output
```

### `reconx intel` — Full Intelligence Gathering

Runs **all** collector modules simultaneously — subdomains, assets, credentials, emails, code leaks, WHOIS, and wireless.

```bash
reconx intel -d example.com -v
```

### `reconx assets` — Asset Discovery

Discovers public-facing IP addresses, open ports, services, and technologies using Shodan, Censys, InternetDB, and other passive sources.

```bash
reconx assets -d example.com
```

### `reconx creds` — Credential Leak Detection

Searches Have I Been Pwned, IntelX, GitHub code leaks, and other breach databases for leaked credentials.

```bash
reconx creds -d example.com
```

### `reconx probe` — HTTP Probing

Probes discovered subdomains for live web services. Detects technologies, CDNs, WAFs, and sensitive exposed paths.

```bash
# Probe from previous enum results
reconx probe --input ./reconx-output/example.com/findings.json

# Or enumerate + probe in one step
reconx probe -d example.com -v
```

### `reconx wireless` — Wireless Network Discovery

Searches Wigle.net for wireless networks associated with the target organization.

```bash
reconx wireless -n "Company Name"
```

### `reconx config` — API Key Management

```bash
# Set an API key
reconx config set shodan YOUR_API_KEY

# List configured keys
reconx config list

# Show config file path
reconx config path
```

### `reconx report` — Regenerate Reports

Generate new reports from previously saved findings.

```bash
reconx report --input findings.json --format html,markdown
```

---

## 🔌 Data Sources

Reconx integrates **36 passive data sources** across 8 categories:

### Certificate Transparency
| Source | API Key | Description |
|--------|:-------:|-------------|
| [crt.sh](https://crt.sh/) | ❌ | Certificate transparency log search |
| [CertSpotter](https://sslmate.com/certspotter/) | ❌ | SSLMate certificate transparency monitoring |
| [CertStream](https://certstream.calidog.io/) | ❌ | Real-time certificate transparency log streaming |

### DNS & Subdomain Discovery
| Source | API Key | Description |
|--------|:-------:|-------------|
| [HackerTarget](https://hackertarget.com/) | ❌ | DNS lookup and host search |
| [Anubis](https://jldc.me/) | ❌ | Subdomain enumeration |
| [RapidDNS](https://rapiddns.io/) | ❌ | Fast DNS database search |
| [SubdomainCenter](https://www.subdomain.center/) | ❌ | Subdomain aggregation service |
| [ThreatCrowd](https://www.threatcrowd.org/) | ❌ | Threat intelligence search |
| [ThreatMiner](https://www.threatminer.org/) | ❌ | Threat intelligence data mining |
| [DNSDumpster](https://dnsdumpster.com/) | ❌ | DNS reconnaissance |
| [SecurityTrails](https://securitytrails.com/) | ✅ | Comprehensive DNS and domain intelligence |
| [Chaos](https://chaos.projectdiscovery.io/) | ✅ | ProjectDiscovery's asset database |

### Search Engines & Archives
| Source | API Key | Description |
|--------|:-------:|-------------|
| [Wayback Machine](https://web.archive.org/) | ❌ | Internet Archive historical URL data |
| [Common Crawl](https://commoncrawl.org/) | ❌ | Web crawl data repository |
| [DuckDuckGo](https://duckduckgo.com/) | ❌ | Privacy-focused search engine scraping |
| [URLScan](https://urlscan.io/) | ✅ | Website scanner and analysis |

### Threat Intelligence
| Source | API Key | Description |
|--------|:-------:|-------------|
| [VirusTotal](https://www.virustotal.com/) | ✅ | File and URL analysis platform |
| [AlienVault OTX](https://otx.alienvault.com/) | ✅ | Open threat intelligence community |
| [ThreatHunter](https://threathunter.ai/) | ❌ | AI-powered threat hunting |
| [Shodan](https://www.shodan.io/) | ✅ | Internet-connected device search |
| [Censys](https://censys.io/) | ✅ | Internet-wide scanning data |
| [InternetDB](https://internetdb.shodan.io/) | ❌ | Shodan's free lightweight API |
| [FullHunt](https://fullhunt.io/) | ✅ | Attack surface management |
| [IPInfo](https://ipinfo.io/) | ✅ | IP geolocation and ASN data |
| [BGPView](https://bgpview.io/) | ❌ | BGP and ASN lookup |

### Credential & Breach Intelligence
| Source | API Key | Description |
|--------|:-------:|-------------|
| [Have I Been Pwned](https://haveibeenpwned.com/) | ❌ | Breach notification service |
| [IntelX](https://intelx.io/) | ✅ | Intelligence search engine |
| [LeakIX](https://leakix.net/) | ✅ | Leaked database search |
| [Pastebin](https://pastebin.com/) | ❌ | Paste site monitoring |

### Code Leak Detection
| Source | API Key | Description |
|--------|:-------:|-------------|
| [GitHub Dorks](https://github.com/) | ✅ | GitHub code search for exposed secrets |

### Email Harvesting
| Source | API Key | Description |
|--------|:-------:|-------------|
| [Hunter.io](https://hunter.io/) | ✅ | Professional email finder |

### Domain Intelligence
| Source | API Key | Description |
|--------|:-------:|-------------|
| [WHOIS/RDAP](https://rdap.org/) | ❌ | Domain registration intelligence via RDAP |

### Search Engine Intelligence
| Source | API Key | Description |
|--------|:-------:|-------------|
| [FOFA](https://fofa.info/) | ✅ | Cyberspace search engine |
| [ZoomEye](https://www.zoomeye.org/) | ✅ | Cyberspace search engine |
| [Netlas](https://netlas.io/) | ✅ | Internet intelligence search |

### Wireless
| Source | API Key | Description |
|--------|:-------:|-------------|
| [Wigle.net](https://wigle.net/) | ✅ | Wireless network database |

> **Free sources work out of the box.** Add API keys for enhanced coverage. Most services offer free tiers.

---

## 🔑 API Keys

Configure API keys to unlock additional data sources:

```bash
# Essential (free tier available)
reconx config set virustotal YOUR_KEY
reconx config set shodan YOUR_KEY
reconx config set censys YOUR_KEY
reconx config set github YOUR_TOKEN

# Extended coverage
reconx config set alienvault YOUR_KEY
reconx config set urlscan YOUR_KEY
reconx config set intelx YOUR_KEY
reconx config set ipinfo YOUR_KEY
reconx config set hunter YOUR_KEY
reconx config set wigle YOUR_KEY
reconx config set securitytrails YOUR_KEY
reconx config set leakix YOUR_KEY
reconx config set fofa EMAIL:KEY
reconx config set zoomeye YOUR_KEY
reconx config set netlas YOUR_KEY
reconx config set fullhunt YOUR_KEY
reconx config set chaos YOUR_KEY
```

API keys are stored locally in your system config directory (`~/.config/reconx/config.toml`). They are **never** transmitted anywhere except to their respective APIs.

---

## 📊 Reports

Reconx generates reports in 4 formats:

| Format | File | Description |
|--------|------|-------------|
| **HTML** | `report.html` | Interactive report with statistics and tables |
| **Markdown** | `report.md` | Structured report with emoji badges, risk factors — paste into GitHub/Notion/Obsidian |
| **JSON** | `findings.json` | Machine-readable findings for integration with other tools |
| **CSV** | `subdomains.csv`, `assets.csv`, `credentials.csv`, etc. | Spreadsheet-friendly per-category exports |

Reports are saved to `./reconx-output/<domain>/<timestamp>/` by default.

### Example Markdown Report Structure

```
📊 Executive Summary
  Risk Score: 4.5/10 (MEDIUM)
  Subdomains: 570 | Assets: 2 | Credentials: 36

⚠️ Top Risk Factors
  🟠 Credential Leaks — 36 credential leaks
  🟡 Subdomain Exposure — 570 subdomains

🌐 Subdomains (with confidence scores)
🖥️ Assets & Services
🔑 Credential Leaks
📋 WHOIS Intelligence
🔒 SSL/TLS Certificates
```

---

## 🏗️ Architecture

```
src/
├── main.rs              # CLI entrypoint and orchestration
├── cli.rs               # Command-line argument definitions (clap)
├── config.rs            # API key management and persistence
├── error.rs             # Error types
├── dns/                 # DNS resolution and wildcard detection
├── collectors/          # 36 data source collectors
│   ├── mod.rs           # Collector trait + registry + async executor
│   ├── crtsh.rs         # Certificate Transparency
│   ├── shodan.rs        # Shodan API
│   ├── virustotal.rs    # VirusTotal API
│   ├── whois_rdap.rs    # WHOIS/RDAP intelligence
│   └── ...              # 32 more collectors
├── models/              # Data models
│   ├── finding.rs       # Core Finding enum (Subdomain, Asset, Credential, Whois, Ssl, ...)
│   ├── subdomain.rs     # Subdomain finding with confidence scoring
│   └── ...              # Per-type models
├── analyzers/           # Intelligence analysis pipeline
│   ├── correlator.rs    # Multi-source deduplication and confidence scoring
│   ├── risk_scorer.rs   # Weighted risk analysis with top factors
│   ├── takeover_detector.rs  # Subdomain takeover detection (65+ fingerprints)
│   ├── diff_engine.rs   # Historical scan comparison
│   ├── tech_fingerprint.rs   # Technology stack profiling
│   └── attack_surface.rs     # Attack surface mapping
├── probe/               # Active probing (opt-in)
│   ├── http.rs          # HTTP prober with sensitive path detection
│   ├── ssl_info.rs      # SSL certificate intelligence
│   ├── tech_detect.rs   # Technology detection engine
│   └── cdn_detect.rs    # CDN/WAF detection
├── output/              # Output formatting
│   ├── terminal.rs      # Colored terminal output with progress bars
│   └── writer.rs        # Multi-format report orchestration
└── reports/             # Report generators
    ├── html.rs          # Interactive HTML reports
    ├── markdown.rs      # Structured Markdown with risk badges
    ├── json.rs          # Machine-readable JSON
    └── csv.rs           # Per-category CSV exports
```

### Data Flow

```
Target Domain
    │
    ▼
┌─────────────────────┐
│  Collector Registry  │ ── 36 passive sources run concurrently
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│  Correlator          │ ── Dedup + multi-source confidence scoring
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│  Analyzers           │ ── Takeover detection, risk scoring,
│                      │    tech fingerprinting, attack surface
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│  Report Writers      │ ── HTML, Markdown, JSON, CSV
└─────────────────────┘
```

---

## 🔒 Passive-Only Philosophy

Reconx is designed to be **completely passive** by default:

- ❌ No port scanning
- ❌ No direct connection to target infrastructure
- ❌ No DNS brute-forcing
- ❌ No web crawling or spidering
- ✅ Only queries third-party APIs and public databases
- ✅ Safe for pre-engagement reconnaissance
- ✅ No risk of triggering IDS/IPS or WAF alerts

> **Note:** The `probe` command performs HTTP GET requests to discovered subdomains. This is opt-in and clearly separated from passive collection.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**Built with ❤️ and Rust 🦀**

*If you find Reconx useful, consider giving it a ⭐ on GitHub!*

</div>
