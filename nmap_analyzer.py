import argparse
import logging
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pentest_assistant.pipeline import AnalysisConfig, analyze_scan
from pentest_assistant.providers import DEFAULT_MODELS
from pentest_assistant.reporting import build_text_report, generate_html_report
from update_cve_db import UpdateConfig as CVEUpdateConfig
from update_cve_db import update_cve_database

AI_PROVIDERS = ["ollama", "alias1", "openai", "claude"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Nmap Analyzer — turn nmap XML into actionable pentest reports with AI attack plans, CVE matching, risk scoring, and enumeration playbooks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "reports are saved to reports/<project>_<timestamp>/ by default\n\n"
            "examples:\n"
            "  %(prog)s scan.xml -C acme                   Analyze with project name\n"
            "  %(prog)s scan.xml                           Analyze (playbooks only)\n"
            "  %(prog)s scan.xml --ai -C acme              Playbooks + AI (Ollama)\n"
            "  %(prog)s scan.xml --ai alias1 -C acme       Playbooks + AI (CAI Pro)\n"
            "  %(prog)s scan.xml --ai openai -C acme       Playbooks + AI (OpenAI)\n"
            "  %(prog)s scan.xml --ai claude -C acme       Playbooks + AI (Claude)\n"
            "  %(prog)s --cve-db-update                    Build/update CVE database\n\n"
            "AI provider env vars:\n"
            "  ollama    OLLAMA_HOST (default: http://127.0.0.1:11434)\n"
            "  alias1    CAI_API_KEY or OPENAI_API_KEY + CAI_API_BASE\n"
            "  openai    OPENAI_API_KEY\n"
            "  claude    ANTHROPIC_API_KEY"
        ),
    )
    parser.add_argument("scan", nargs="?", help="Nmap XML file to analyze")
    parser.add_argument("-C", "--project", default=None, help="Project name (used as report subfolder name)")

    # --- AI options ---
    ai_group = parser.add_argument_group("AI options")
    ai_group.add_argument(
        "--ai", nargs="?", const="ollama", default=None,
        choices=AI_PROVIDERS, metavar="PROVIDER",
        help="Enable AI suggestions. Providers: ollama (default), alias1, openai, claude",
    )
    ai_group.add_argument("--ai-model", default="", help="Override AI model name (default: auto per provider)")
    ai_group.add_argument("--ai-key", default=None, help="API key for AI provider (or use env vars)")
    ai_group.add_argument("--ai-timeout", type=float, default=60.0, help="Timeout per AI request in seconds (default: 60)")
    ai_group.add_argument("--max-ai-commands", type=int, default=8, help="Max AI commands per service (default: 8)")

    # --- CVE database update ---
    cve_group = parser.add_argument_group("CVE database update")
    cve_group.add_argument("--cve-db-update", action="store_true", help="Build/update local CVE database from NVD feeds")
    cve_group.add_argument("--cve-rebuild", action="store_true", help="Drop and rebuild CVE tables before importing")
    cve_group.add_argument("--cve-update-mode", choices=("auto", "full", "incremental"), default="auto", help="Update mode (default: auto)")
    cve_group.add_argument("--cve-offline", action="store_true", help="Use only locally cached NVD feed files")
    cve_group.add_argument("--cve-force-download", action="store_true", help="Force re-download of NVD feeds")
    cve_group.add_argument("--cve-start-year", type=int, default=2002, help=argparse.SUPPRESS)
    cve_group.add_argument("--cve-end-year", type=int, default=datetime.now(UTC).year, help=argparse.SUPPRESS)
    cve_group.add_argument("--cve-feed-dir", default="data/nvd_feeds", help=argparse.SUPPRESS)

    # --- Output options ---
    output_group = parser.add_argument_group("output options")
    output_group.add_argument("--playbooks", default="data/enumeration_playbooks.json", help="Path to playbooks JSON file (default: data/enumeration_playbooks.json)")
    output_group.add_argument("--db", default="data/cve_database.db", help=argparse.SUPPRESS)

    # --- Logging / debug ---
    log_group = parser.add_argument_group("logging")
    log_group.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity (default: INFO)")
    log_group.add_argument("--debug", action="store_true", help="Shortcut for --log-level DEBUG")
    return parser


def _preflight_scan(scan_path: str, playbook_path: str, cve_db_path: str) -> tuple[list[str], list[str]]:
    """Check file prerequisites. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    if not Path(scan_path).exists():
        errors.append(f"Nmap XML not found: {scan_path}")
    if not Path(playbook_path).exists():
        errors.append(f"Playbook file not found: {playbook_path}")
    if not Path(cve_db_path).exists():
        warnings.append(
            f"CVE database not found at {cve_db_path}. Vulnerability hints will be unavailable."
        )
    return errors, warnings


def _preflight_ai(provider_name: str, model: str, api_key: str | None) -> tuple[bool, list[str]]:
    """Validate AI provider availability. Returns (ok, warnings)."""
    warnings: list[str] = []

    if provider_name == "ollama":
        try:
            import httpx
            resp = httpx.get(
                os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434") + "/api/tags",
                timeout=5.0,
            )
            models_data = resp.json().get("models", [])
            model_names = set()
            for entry in models_data:
                for key in ("model", "name"):
                    val = entry.get(key) if isinstance(entry, dict) else getattr(entry, key, None)
                    if isinstance(val, str) and val.strip():
                        model_names.add(val.strip())

            resolved_model = model or DEFAULT_MODELS["ollama"]
            if model_names and resolved_model not in model_names:
                warnings.append(f"Ollama model '{resolved_model}' not found locally. AI disabled.")
                return False, warnings
        except Exception as exc:
            warnings.append(f"Ollama unavailable ({exc}). AI disabled.")
            return False, warnings

    elif provider_name in ("alias1", "openai", "claude"):
        from pentest_assistant.providers import _ENV_KEYS
        if not api_key:
            for env_key in _ENV_KEYS.get(provider_name, ()):
                if os.getenv(env_key, ""):
                    api_key = os.getenv(env_key)
                    break
        if not api_key:
            env_names = ", ".join(_ENV_KEYS.get(provider_name, ()))
            warnings.append(f"No API key for '{provider_name}'. Set --ai-key or env var ({env_names}). AI disabled.")
            return False, warnings

    return True, warnings


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if not args.scan and not args.cve_db_update:
        parser.error("scan is required unless --cve-db-update is used")

    log_level = "DEBUG" if args.debug else args.log_level
    logging.basicConfig(level=getattr(logging, log_level), format="%(levelname)s: %(message)s")

    if args.cve_db_update:
        db_path = Path(args.db)
        resolved_mode = args.cve_update_mode
        if resolved_mode == "auto":
            resolved_mode = "full" if not db_path.exists() else "incremental"

        update_config = CVEUpdateConfig(
            db_path=db_path,
            download_dir=Path(args.cve_feed_dir),
            mode=resolved_mode,
            start_year=args.cve_start_year,
            end_year=args.cve_end_year,
            force_download=args.cve_force_download,
            offline=args.cve_offline,
            rebuild=args.cve_rebuild,
            batch_size=1000,
            explicit_feeds=[],
        )
        try:
            update_cve_database(update_config)
        except Exception as exc:
            print(f"Error: CVE update failed: {exc}", file=sys.stderr)
            return 1
        if not args.scan:
            return 0

    # Preflight checks
    preflight_errors, preflight_warnings = _preflight_scan(
        scan_path=args.scan,
        playbook_path=args.playbooks,
        cve_db_path=args.db,
    )

    ai_provider = args.ai  # None if not set, "ollama"/"alias1"/"openai"/"claude" if set
    if ai_provider:
        ai_ok, ai_warnings = _preflight_ai(ai_provider, args.ai_model, args.ai_key)
        preflight_warnings.extend(ai_warnings)
        if not ai_ok:
            ai_provider = None

    for warning in preflight_warnings:
        print(f"Warning: {warning}", file=sys.stderr)
    if preflight_errors:
        for error in preflight_errors:
            print(f"Error: {error}", file=sys.stderr)
        return 1

    if ai_provider:
        resolved_model = args.ai_model or DEFAULT_MODELS.get(ai_provider, "")
        print(f"AI enabled: {ai_provider} (model: {resolved_model})", file=sys.stderr)

    config = AnalysisConfig(
        cve_db_path=args.db,
        playbook_path=args.playbooks,
        ai_provider=ai_provider,
        ai_model=args.ai_model,
        ai_key=args.ai_key or "",
        ai_timeout_seconds=max(1.0, args.ai_timeout),
        max_ai_commands=max(0, args.max_ai_commands),
    )

    try:
        result = analyze_scan(args.scan, config)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    text_report = build_text_report(result)
    print(text_report)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.project:
        safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", args.project).strip("_")
        folder_name = f"{safe_name}_{timestamp}"
    else:
        folder_name = timestamp
    report_dir = Path("reports") / folder_name
    report_dir.mkdir(parents=True, exist_ok=True)

    text_path = report_dir / "findings.txt"
    text_path.write_text(text_report + "\n", encoding="utf-8")

    generate_html_report(result, report_dir / "report.html", args.scan)

    print(f"\nReports saved to: {report_dir}/")
    print(f"  findings.txt")
    print(f"  report.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
