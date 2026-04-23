# Nmap Analyzer

Turn nmap XML into actionable pentest reports — AI attack plans, CVE matching,
risk scoring, enumeration playbooks, and optional automated safe enumeration in one tool.

## Features

- **Infrastructure role detection** — groups hosts by role (Web Server, Domain Controller, File Server, SQL Server, etc.)
- **120+ enumeration playbooks** — 550+ service-specific commands (Apache, IIS, Tomcat, Samba, WinRM, MSSQL, etc.)
- **CVE cross-referencing** — matches service versions against a local NVD-sourced SQLite database; ranks by relevance, CISA KEV status, and exploit type (RCE, auth bypass, privesc)
- **Risk scoring** — prioritizes findings by service criticality, CVE severity, KEV status, and host count
- **AI-enhanced suggestions** — optional per-service command suggestions via local Ollama
- **AI Network Overview** — concise scan summary injected at the top of the report before the full attack plan
- **AI Attack Plan** — per-service exploitability assessment, attack paths, quick wins, and cross-service correlation analysis
- **Safe auto-execution** — `--execute` runs safe enumeration commands only (no brute force, no exploitation); brute force commands are kept as manual suggestions
- **SSH remote execution** — `--remote-host kali@IP` runs all commands on a remote Kali box via SSH ControlMaster while Ollama stays on your local machine
- **Live Findings tab** — execution results displayed in the HTML report with Ollama synthesis of all outputs
- **Pre-flight checks** — validates tool availability and passwordless sudo before executing
- **Self-contained HTML report** — interactive tabbed dashboard (Dashboard, Suggested Action, AI Report, Live Findings)
- **File logging** — every run writes a full debug log to `logs/run_<timestamp>.log`
- **Robust** — handles any nmap XML (empty scans, tcpwrapped services, closed ports, malformed data)

## Prerequisites

- **Python 3.10+** (tested on 3.11, 3.12, 3.14)
- **Nmap** — to generate XML scan files (`nmap -oX`)
- **Git** — to clone the repository
- **(Optional) Ollama** — for local AI suggestions (`--ai`). Must be installed manually by the user — see [ollama.com/download](https://ollama.com/download)

## Installation

### Step 1: Clone the repository

```bash
git clone https://github.com/noobytes/Nmap-Analyzer.git
cd Nmap-Analyzer
```

### Step 2: Run the setup script

```bash
python3 setup.py
```

This will automatically:
- Create a Python virtual environment (`venv/`)
- Install all dependencies (plotly, defusedxml, httpx)
- Create required data directories (`data/`, `data/nvd_feeds/`, `reports/`, `logs/`)
- Generate the `analyzer.sh` convenience script
- Verify the package installation
- Print a note on how to set up Ollama manually (optional, for `--ai`)

### Step 3 (Alternative): Manual setup

If you prefer manual installation:

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
mkdir -p data/nvd_feeds reports logs
```

### Step 4: Build the CVE database (recommended)

```bash
./analyzer.sh --cve-db-update
```

This downloads NVD JSON feeds and builds a local SQLite database at `data/cve_database.db`.
First run does a full import (2002–current year). Subsequent runs do incremental updates.

### Step 5: Set up Ollama (optional, for AI features)

Ollama is **not installed automatically**. If you want AI-powered suggestions (`--ai`), install it manually:

1. Download and install Ollama: https://ollama.com/download
2. Pull a model: `ollama pull gemma4:26b`
3. Start the Ollama server: `ollama serve`

If Ollama runs on a non-default host/port, set it in `.env`:

```bash
cp .env_example .env
# Edit .env and uncomment:
# OLLAMA_HOST=http://your-host:11434
```

The `analyzer.sh` script auto-loads `.env` on startup.

## Usage

### Basic analysis (playbooks only, no AI)

```bash
./analyzer.sh scan.xml -C myproject
```

### With AI suggestions and attack plan

```bash
# AI suggestions only (no profile — chunked per-service analysis)
./analyzer.sh scan.xml -C myproject --ai

# External pentest profile (internet-facing targets, initial access focus)
./analyzer.sh scan.xml -C myproject --ai --profile external

# Internal pentest profile (inside the network, lateral movement and AD focus)
./analyzer.sh scan.xml -C myproject --ai --profile internal

# Use a larger model
./analyzer.sh scan.xml -C myproject --ai --profile external
```

### Auto-execute safe enumeration commands

```bash
# Analyze + execute enumeration commands locally (prompts for confirmation)
./analyzer.sh scan.xml -C myproject --ai --execute

# Skip confirmation prompt
./analyzer.sh scan.xml -C myproject --ai --execute --no-confirm

# Limit to 20 commands, 90s timeout per command
./analyzer.sh scan.xml -C myproject --ai --execute --max-exec-commands 20 --exec-timeout 90
```

### Execute on a remote Kali box via SSH

Run Nmap Analyzer on your local Mac with Ollama running locally, but execute all enumeration commands on a remote Kali Linux box:

```bash
# Using SSH agent / default key
./analyzer.sh scan.xml -C myproject --ai --execute --remote-host kali@192.168.1.100

# Using a specific key file
./analyzer.sh scan.xml -C myproject --ai --execute \
  --remote-host kali@192.168.1.100 \
  --remote-key ~/.ssh/kali_key \
  --remote-port 22
```

### Update CVE database + analyze in one command

```bash
./analyzer.sh --cve-db-update scan.xml -C acme --ai
```

### Run directly (without analyzer.sh)

```bash
venv/bin/python3 nmap_analyzer.py scan.xml -C myproject --ai
```

### All available options

```
usage: nmap_analyzer.py [-h] [-C PROJECT] [--ai [PROVIDER]]
                        [--profile {external,internal}] [--ai-model AI_MODEL]
                        [--ai-key AI_KEY] [--ai-timeout AI_TIMEOUT]
                        [--max-ai-commands MAX_AI_COMMANDS] [--cve-db-update]
                        [--cve-rebuild]
                        [--cve-update-mode {auto,full,incremental}]
                        [--cve-force-download] [--nvd-api-key NVD_API_KEY]
                        [--min-cvss MIN_CVSS] [--execute]
                        [--exec-timeout EXEC_TIMEOUT]
                        [--max-exec-commands MAX_EXEC_COMMANDS] [--no-confirm]
                        [--remote-host USER@HOST] [--remote-key PATH]
                        [--remote-port REMOTE_PORT] [--playbooks PLAYBOOKS]
                        [--log-level {DEBUG,INFO,WARNING,ERROR}] [--debug]
                        [scan]
```

#### AI options

| Flag | Default | Description |
|------|---------|-------------|
| `--ai [PROVIDER]` | — | Enable AI via local Ollama |
| `--profile {external,internal}` | — | Engagement profile for attack plan (requires `--ai`) |
| `--ai-model <model>` | `gemma4:26b` | Override AI model name |
| `--ai-timeout <secs>` | `10` | Ollama **connection** timeout. Generation itself has no timeout — the model runs until done. |
| `--max-ai-commands <n>` | `8` | Max AI-generated commands per service |

#### Execution options

| Flag | Default | Description |
|------|---------|-------------|
| `--execute` | off | Execute safe enumeration commands (prompts for confirmation) |
| `--exec-timeout <secs>` | `60` | Per-command timeout during execution |
| `--max-exec-commands <n>` | `30` | Max commands to auto-execute |
| `--no-confirm` | off | Skip the confirmation prompt before executing |
| `--remote-host USER@HOST` | — | Run commands on a remote host via SSH |
| `--remote-key <path>` | — | SSH private key path (default: SSH agent / default key) |
| `--remote-port <port>` | `22` | SSH port for remote host |

#### CVE database options

| Flag | Default | Description |
|------|---------|-------------|
| `--cve-db-update` | — | Build/update local CVE database from NVD API |
| `--cve-rebuild` | off | Drop and rebuild CVE tables before importing |
| `--cve-update-mode` | `auto` | `auto`, `full`, or `incremental` |
| `--cve-force-download` | off | Re-fetch full window ignoring last-update timestamp |
| `--nvd-api-key <key>` | — | NVD API key for ~10× faster downloads (free at nvd.nist.gov) |
| `--min-cvss <score>` | `0.0` | Only store CVEs at or above this CVSS score |

#### Other options

| Flag | Default | Description |
|------|---------|-------------|
| `-C, --project <name>` | — | Project name — reports go to `reports/<name>_<timestamp>/` |
| `--playbooks <path>` | `data/enumeration_playbooks.json` | Custom playbooks file |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` |
| `--debug` | off | Shortcut for `--log-level DEBUG` |

## Output

Reports are saved to `reports/<project>_<timestamp>/`:

| File | Description |
|------|-------------|
| `findings.txt` | Plain text report — all findings, commands, and attack plan |
| `report.html` | Self-contained interactive HTML report |
| `ai_report.txt` | Raw AI attack plan text (when `--ai` is used) |
| `live_findings.txt` | Ollama synthesis of execution results (when `--execute --ai`) |
| `enumeration/` | Per-command output files (when `--execute` is used) |
| `logs/run_<timestamp>.log` | Full DEBUG log for every run |

### HTML Report Tabs

| Tab | Description |
|-----|-------------|
| **Dashboard** | Infrastructure overview, role distribution charts, risk heatmap, host inventory, pentest checklists |
| **Suggested Action** | Per-service findings with playbook commands, AI-suggested commands, CVE matches, and risk scores |
| **AI Report** | Network overview summary + per-service exploitability assessment, attack paths, quick wins, and cross-service correlation (requires `--ai`) |
| **Live Findings** | Execution results from `--execute` mode with Ollama synthesis of all outputs |

## AI Provider

| Provider | Flag | Model (default) | Notes |
|----------|------|-----------------|-------|
| Ollama | `--ai` | `gemma4:26b` | Free, local, no API key needed |

Override the model with `--ai-model <name>`, e.g.:
```bash
# Faster, lighter option
./analyzer.sh scan.xml -C test --ai --ai-model qwen2.5-coder:14b

# Smaller Gemma variant
./analyzer.sh scan.xml -C test --ai --ai-model gemma4:12b
```

## Engagement Profiles

Profiles control the AI Attack Plan analysis. Pass `--profile` alongside `--ai`.

| Profile | Flag | Focus | Use When |
|---------|------|-------|----------|
| External | `--profile external` | Internet-facing footprint, WAF/CDN detection, initial access paths from the public internet | External pentest / black-box assessment |
| Internal | `--profile internal` | Lateral movement, Active Directory, Kerberoasting, NTLM relay, privilege escalation | Internal pentest / assumed breach |

**Without `--profile`:** the attack plan falls back to chunked per-service analysis (exploitability + cross-service correlations).

## Execute Mode

`--execute` automatically runs safe enumeration commands against the scan targets after confirmation.

**What runs automatically:**
- Port scanning (nmap scripts), web probing (curl, nikto, nuclei, ffuf, gobuster)
- SMB/LDAP/SNMP enumeration, SSH audit, DNS queries, service fingerprinting

**What stays as manual suggestions only (never auto-run):**
- Brute force (hydra, medusa, hashcat, etc.)
- Exploitation (sqlmap, metasploit, impacket wmiexec/psexec, etc.)

**Pre-flight checks** run before execution:
- Verifies all required tools are installed on the target system
- Checks if passwordless sudo is available (warns if not)
- Validates all target IPs are within scan scope

**SSH remote execution** (`--remote-host`):
- Opens a single SSH ControlMaster connection — all commands reuse it (no repeated handshakes)
- Ollama AI stays on your local machine; only the enumeration commands run remotely
- Use this when your Kali attack box is separate from the machine running the tool

```bash
# Typical workflow: Mac running Ollama + Nmap Analyzer → Kali executing commands
./analyzer.sh scan.xml -C engagement --ai --profile internal \
  --execute --remote-host kali@10.10.10.5 --remote-key ~/.ssh/kali
```

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

The tool uses a local SQLite database (`data/cve_database.db`) sourced from official NVD JSON feeds.
CVEs are enriched with exploit type classification (RCE, auth bypass, privesc, SQLi, etc.) and CISA KEV status for improved ranking.

```bash
# Build from scratch (first run — downloads all feeds from 2002)
./analyzer.sh --cve-db-update

# Incremental update (only modified + recent feeds)
./analyzer.sh --cve-db-update

# Force full rebuild
./analyzer.sh --cve-db-update --cve-rebuild

# With NVD API key for ~10× faster downloads (free key)
./analyzer.sh --cve-db-update --nvd-api-key YOUR_KEY_HERE

# Direct updater script
venv/bin/python3 update_cve_db.py --mode full --rebuild
venv/bin/python3 update_cve_db.py --mode incremental
```

The tool auto-detects whether to run a full or incremental import based on whether the DB exists.

## How It Works

```
1. Nmap XML         → Parse hosts, services, versions
2. Role Detection   → Classify hosts (Web, DC, SQL, File Server, etc.)
3. Service Grouping → Group identical services across hosts
4. CVE Lookup       → Match versions against local NVD database
                       (ranked by CVSS, CISA KEV status, exploit type)
5. Playbook Match   → Select enumeration commands from 120+ playbooks
6. AI Commands      → (Optional) Generate additional commands per service
7. Risk Scoring     → Prioritize by criticality, CVEs, host count
8. AI Attack Plan   → (Optional) Network overview + comprehensive analysis:
                       --profile external: internet-facing footprint, initial access
                       --profile internal: lateral movement, AD chains, privesc
                       (no profile): chunked per-service exploitability + cross-service summary
9. Execute          → (Optional) Run safe enumeration commands locally or via SSH
                       Brute force / exploitation kept as manual suggestions only
10. Live Findings   → (Optional) Ollama synthesizes all execution outputs into a verdict
11. Report          → HTML dashboard + text findings + per-command output files
```

## Project Structure

```
Nmap-Analyzer/
├── analyzer.sh                    # Entry point script (auto-loads .env)
├── nmap_analyzer.py               # CLI interface
├── setup.py                       # Installation script
├── requirements.txt               # Python dependencies
├── .env_example                   # API key template
├── pentest_assistant/             # Core package
│   ├── __init__.py
│   ├── ai.py                     # AI command generation + attack plan + synthesis
│   ├── cve.py                    # CVE database lookup (KEV + exploit type aware)
│   ├── executor.py               # Safe execution engine + SSH ControlMaster
│   ├── models.py                 # Data models (Service, Host, Finding, etc.)
│   ├── parser.py                 # Nmap XML parser
│   ├── pipeline.py               # Main analysis pipeline
│   ├── playbooks.py              # Enumeration playbook matcher
│   ├── providers.py              # AI provider abstraction (Ollama)
│   ├── reporting.py              # HTML + text report generation
│   └── role_detection.py         # Host role classification
├── data/
│   └── enumeration_playbooks.json # 120+ service playbooks
├── logs/                          # Auto-created; run_<timestamp>.log per run
├── reports/                       # Auto-created; one subfolder per run
├── tests/
│   ├── test_assistant.py
│   ├── test_cve_updater.py
│   ├── test_dashboard.py
│   └── test_reporting.py
└── update_cve_db.py               # NVD feed downloader + importer
```

## Offline Operation

After the initial CVE feed download:
- Scan analysis works fully offline using `data/cve_database.db`
- CVE updates can use cached feeds with `--cve-offline`
- AI features (Ollama) run fully locally — no network access required
- `--execute` with `--remote-host` only needs SSH access to the remote box

## Running Tests

```bash
./venv/bin/python -m pytest tests/ -v
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Run `python3 setup.py` or `pip install -r requirements.txt` |
| `CVE database not found` | Run `./analyzer.sh --cve-db-update` |
| `Ollama unavailable` | Install from https://ollama.com/download, pull a model, run `ollama serve` |
| `Ollama model not found` | Run `ollama pull gemma4:26b` or specify another with `--ai-model` |
| AI Report tab empty | Model is still running — no timeout on generation. Check `logs/` for errors. |
| `stream idle timeout` | Fixed in current version (`read=None` on streaming). Update your copy. |
| SSH connection refused | Ensure `sshd` is running on the remote host: `sudo systemctl start ssh` |
| Tool not found on remote | Install missing tools on the Kali box, e.g. `sudo apt install ffuf gobuster` |
| Sudo password required | Add `kali ALL=(ALL) NOPASSWD: ALL` to `/etc/sudoers.d/` on remote box |
| `Permission denied: analyzer.sh` | Run `chmod +x analyzer.sh` |
| Reports not generated | Ensure `reports/` directory exists: `mkdir -p reports` |

## License

MIT
