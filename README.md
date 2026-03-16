# Nmap Analyzer

Turn nmap XML into actionable pentest reports — AI attack plans, CVE matching,
risk scoring, and enumeration playbooks in one tool.

## Features

- **Infrastructure role detection** — groups hosts by role (Web Server, Domain Controller, File Server, SQL Server, etc.)
- **120+ enumeration playbooks** — 550+ service-specific commands (Apache, IIS, Tomcat, Samba, WinRM, MSSQL, etc.)
- **CVE cross-referencing** — matches service versions against a local NVD-sourced SQLite database, filters out DoS-only CVEs, ranks by relevance
- **Risk scoring** — prioritizes findings by service criticality, CVE severity, and host count
- **AI-enhanced suggestions** — optional per-service command suggestions via multiple providers
- **AI Attack Plan** — per-service exploitability assessment, attack paths, quick wins, and cross-service correlation analysis
- **Self-contained HTML report** — interactive tabbed dashboard with findings, commands, and attack plan
- **Robust** — handles any nmap XML (empty scans, tcpwrapped services, closed ports, malformed data)

## Quick Setup

```bash
python3 setup.py
```

This will create a virtual environment, install dependencies, and verify connectivity.

## Manual Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Playbook-only analysis (no AI)
./analyzer.sh scan.xml -C myproject

# With AI suggestions and attack plan
./analyzer.sh scan.xml -C myproject --ai alias1 --ai-timeout 120

# Build/update CVE database from NVD feeds
./analyzer.sh --cve-db-update

# Update CVE DB + analyze in one command
./analyzer.sh --cve-db-update scan.xml -C acme
```

Or run directly:
```bash
venv/bin/python3 nmap_analyzer.py scan.xml -C myproject --ai alias1
```

### AI Providers

| Provider | Flag | Required Env Vars |
|----------|------|-------------------|
| Ollama (local) | `--ai ollama` | `OLLAMA_HOST` (default: http://127.0.0.1:11434) |
| CAI Framework | `--ai alias1` | `CAI_API_KEY` or `OPENAI_API_KEY` + `CAI_API_BASE` |
| OpenAI | `--ai openai` | `OPENAI_API_KEY` |
| Claude | `--ai claude` | `ANTHROPIC_API_KEY` |

Store your keys in a `.env` file (auto-loaded by `analyzer.sh`):
```bash
CAI_API_KEY=your-key-here
CAI_API_BASE=https://your-cai-endpoint
```

### Common Options

| Flag | Description |
|------|-------------|
| `-C <name>` | Project name (report subfolder: `reports/<name>_<timestamp>/`) |
| `--ai <provider>` | Enable AI suggestions and attack plan |
| `--ai-model <model>` | Override AI model name |
| `--ai-timeout <secs>` | Timeout per AI request (default: 60) |
| `--playbooks <path>` | Custom playbooks JSON file |
| `--log-level` | Logging verbosity: DEBUG, INFO, WARNING, ERROR |
| `--debug` | Shortcut for `--log-level DEBUG` |

Reports (findings.txt, report.html) are saved to `reports/` automatically.

## Recommended Nmap Syntax

For best results, always use `-sV` to populate product and version fields:

```bash
# Internal — fast full scan
nmap -sV -sC -T4 --open -oX scan.xml TARGET_RANGE

# External — stealthier
nmap -sV -sC -p- -T3 --open -oX scan.xml TARGET_RANGE

# UDP essentials
nmap -sU -sV --top-ports 20 --open -oX udp_scan.xml TARGET_RANGE
```

## CVE Database

The tool uses a local SQLite database (`data/cve_database.db`) sourced from NVD JSON feeds.

```bash
# Build from scratch (first run)
./analyzer.sh --cve-db-update

# Incremental update
./analyzer.sh --cve-db-update

# Direct updater script
venv/bin/python3 update_cve_db.py --mode full --rebuild
venv/bin/python3 update_cve_db.py --mode incremental
```

Auto-detects whether to run a full or incremental import based on whether the DB exists.

## How It Works

```
Nmap XML → Parse → Detect Roles → Group Services → CVE Lookup → Playbook Match
    → AI Commands (optional) → Risk Score → AI Attack Plan (optional) → HTML Report
```

## Offline Operation

After the initial CVE feed download, scan analysis works fully offline using the local database. Incremental updates can use cached feeds with `--offline`.

## Running Tests

```bash
./venv/bin/python -m pytest tests/ -v
```
