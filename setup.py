#!/usr/bin/env python3
"""Installation script for Nmap Analyzer — turn nmap XML into actionable pentest reports."""

import os
import subprocess
import sys
from pathlib import Path

VENV_DIR = Path("venv")
REQUIREMENTS = [
    "plotly",
    "defusedxml",
    "httpx",
    "ollama",
    "openai",
    "cai-framework",
]


def create_venv() -> Path:
    """Create a Python virtual environment if it doesn't exist."""
    if VENV_DIR.exists():
        print(f"[*] Virtual environment already exists at: {VENV_DIR}")
    else:
        print(f"[+] Creating virtual environment at: {VENV_DIR}")
        subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
        print("[+] Virtual environment created.")

    if os.name == "nt":
        python = VENV_DIR / "Scripts" / "python.exe"
        pip = VENV_DIR / "Scripts" / "pip.exe"
    else:
        python = VENV_DIR / "bin" / "python3"
        pip = VENV_DIR / "bin" / "pip3"

    if not python.exists():
        # Some systems use 'python' instead of 'python3'
        python = VENV_DIR / "bin" / "python"
    if not pip.exists():
        pip = VENV_DIR / "bin" / "pip"

    return python, pip


def install_dependencies(pip: Path) -> None:
    """Install all required Python packages into the venv."""
    print("[+] Upgrading pip...")
    subprocess.check_call([str(pip), "install", "--upgrade", "pip"], stdout=subprocess.DEVNULL)

    print("[+] Installing dependencies...")
    for pkg in REQUIREMENTS:
        print(f"    Installing {pkg}...")
        subprocess.check_call([str(pip), "install", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[+] All dependencies installed.")


def setup_data_dirs() -> None:
    """Create required data directories."""
    dirs = [
        Path("data"),
        Path("data/nvd_feeds"),
        Path("reports"),
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    print("[+] Data directories ready.")


def check_ollama() -> None:
    """Check if Ollama is installed and running."""
    print("[*] Checking Ollama installation...")
    try:
        import httpx
        resp = httpx.get("http://127.0.0.1:11434/api/tags", timeout=5.0)
        models = resp.json().get("models", [])
        model_names = [m.get("name", m.get("model", "")) for m in models]
        print(f"[+] Ollama is running with {len(models)} model(s): {', '.join(model_names)}")
        if not any("qwen2.5-coder" in n for n in model_names):
            print("[!] Warning: Default model 'qwen2.5-coder:14b' not found.")
            print("    Pull it with: ollama pull qwen2.5-coder:14b")
    except Exception:
        print("[!] Ollama is not running or not installed.")
        print("    Install: https://ollama.com/download")
        print("    Pull model: ollama pull qwen2.5-coder:14b")
        print("    AI suggestions (--ai) will be unavailable without Ollama.")


def check_playbooks() -> None:
    """Check if playbook file exists."""
    playbook = Path("data/enumeration_playbooks.json")
    if playbook.exists():
        import json
        with playbook.open() as f:
            data = json.load(f)
        total_cmds = sum(len(v.get("commands", [])) for v in data.values())
        print(f"[+] Playbooks loaded: {len(data)} playbooks, {total_cmds} commands")
    else:
        print("[!] Warning: data/enumeration_playbooks.json not found.")


def check_cve_db() -> None:
    """Check CVE database status."""
    db_path = Path("data/cve_database.db")
    if db_path.exists():
        size_mb = db_path.stat().st_size / (1024 * 1024)
        print(f"[+] CVE database found: {size_mb:.1f} MB")
    else:
        print("[!] CVE database not found at data/cve_database.db")
        print("    Build it with: venv/bin/python3 nmap_analyzer.py --cve-db-update")


def create_run_script() -> None:
    """Create a convenience run script."""
    if os.name == "nt":
        script = Path("analyzer.bat")
        content = '@echo off\r\nvenv\\Scripts\\python.exe nmap_analyzer.py %*\r\n'
    else:
        script = Path("analyzer.sh")
        content = '#!/usr/bin/env bash\nDIR="$(cd "$(dirname "$0")" && pwd)"\n"$DIR/venv/bin/python3" "$DIR/nmap_analyzer.py" "$@"\n'

    script.write_text(content)
    if os.name != "nt":
        script.chmod(0o755)
    print(f"[+] Run script created: {script}")


def main() -> int:
    print("=" * 50)
    print("  Nmap Analyzer - Setup")
    print("=" * 50)
    print()

    # Step 1: Virtual environment
    python, pip = create_venv()
    print()

    # Step 2: Install dependencies
    install_dependencies(pip)
    print()

    # Step 3: Data directories
    setup_data_dirs()
    print()

    # Step 4: Create run script
    create_run_script()
    print()

    # Step 5: Verify installation
    print("[*] Verifying installation...")
    result = subprocess.run(
        [str(python), "-c", "from pentest_assistant import analyze_scan; print('[+] Package import OK')"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print(result.stdout.strip())
    else:
        print(f"[!] Import check failed: {result.stderr.strip()}")
        return 1
    print()

    # Step 6: Check external dependencies
    # Add venv site-packages to path for httpx import in check_ollama
    subprocess.run(
        [str(python), "-c",
         "import httpx; r=httpx.get('http://127.0.0.1:11434/api/tags',timeout=5); "
         "models=r.json().get('models',[]); names=[m.get('name','') for m in models]; "
         f"print('[+] Ollama running: ' + ', '.join(names)) if models else print('[!] Ollama: no models found')"],
        capture_output=True, text=True,
    )
    check_ollama_via_venv = subprocess.run(
        [str(python), "-c",
         "import httpx\n"
         "try:\n"
         "    r=httpx.get('http://127.0.0.1:11434/api/tags',timeout=5)\n"
         "    ms=r.json().get('models',[])\n"
         "    ns=[m.get('name','') for m in ms]\n"
         "    print(f'[+] Ollama running with {len(ms)} model(s): '+', '.join(ns))\n"
         "    if not any('qwen2.5-coder' in n for n in ns):\n"
         "        print('[!] Default model qwen2.5-coder:14b not found. Pull it: ollama pull qwen2.5-coder:14b')\n"
         "except Exception:\n"
         "    print('[!] Ollama not running. AI mode (--ai) unavailable.')\n"
         "    print('    Install: https://ollama.com/download')\n"
         "    print('    Pull model: ollama pull qwen2.5-coder:14b')\n"],
        capture_output=True, text=True,
    )
    print(check_ollama_via_venv.stdout.strip())
    check_playbooks()
    check_cve_db()
    print()

    # Summary
    print("=" * 50)
    print("  Setup Complete!")
    print("=" * 50)
    print()
    print("Usage:")
    print(f"  ./analyzer.sh scan.xml -C myproject          # Playbook-only analysis")
    print(f"  ./analyzer.sh scan.xml -C myproject --ai      # With AI suggestions")
    print(f"  ./analyzer.sh --cve-db-update                 # Build/update CVE database")
    print(f"  ./analyzer.sh scan.xml --help                 # Show all options")
    print()
    print("Or run directly:")
    print(f"  {python} nmap_analyzer.py scan.xml -C myproject --ai")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
