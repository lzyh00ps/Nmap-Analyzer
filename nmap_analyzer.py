import argparse
import logging
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pentest_assistant.pipeline import AnalysisConfig, analyze_scan
from pentest_assistant.providers import DEFAULT_MODELS
from pentest_assistant.reporting import build_text_report, generate_html_report
from update_cve_db import UpdateConfig as CVEUpdateConfig
from update_cve_db import update_cve_database

AI_PROVIDERS = ["ollama"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Nmap Analyzer — turn nmap XML into actionable pentest reports with AI attack plans, CVE matching, risk scoring, and enumeration playbooks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "reports are saved to reports/<project>_<timestamp>/ by default\n\n"
            "examples:\n"
            "  %(prog)s scan.xml -C acme                            Analyze with project name\n"
            "  %(prog)s scan.xml                                    Analyze (playbooks only)\n"
            "  %(prog)s scan.xml --ai -C acme                       Playbooks + AI (Ollama)\n"
            "  %(prog)s scan.xml --ai --profile external -C acme    External pentest profile\n"
            "  %(prog)s scan.xml --ai --profile internal -C acme    Internal pentest profile\n"
            "  %(prog)s --cve-db-update                             Build/update CVE database\n\n"
            "AI provider env vars:\n"
            "  ollama    OLLAMA_HOST (default: http://127.0.0.1:11434)"
        ),
    )
    parser.add_argument("scan", nargs="?", help="Nmap XML file to analyze")
    parser.add_argument("-C", "--project", default=None, help="Project name (used as report subfolder name)")

    # --- AI options ---
    ai_group = parser.add_argument_group("AI options")
    ai_group.add_argument(
        "--ai", nargs="?", const="ollama", default=None,
        choices=AI_PROVIDERS, metavar="PROVIDER",
        help="Enable AI suggestions using local Ollama (default: ollama)",
    )
    ai_group.add_argument(
        "--profile", choices=["external", "internal"], default=None,
        help=(
            "Engagement profile for AI attack plan analysis. "
            "'external' — internet-facing targets, initial access focus. "
            "'internal' — inside the network, lateral movement and AD focus. "
            "Requires --ai."
        ),
    )
    ai_group.add_argument("--ai-model", default="", help="Override AI model name (default: auto per provider)")
    ai_group.add_argument("--ai-key", default=None, help="API key for AI provider (or use env vars)")
    ai_group.add_argument("--ai-timeout", type=float, default=10.0, help="Ollama connection timeout in seconds (default: 10). Generation itself has no timeout — the model runs until done.")
    ai_group.add_argument("--max-ai-commands", type=int, default=8, help="Max AI commands per service (default: 8)")

    # --- CVE database update ---
    cve_group = parser.add_argument_group("CVE database update")
    cve_group.add_argument("--cve-db-update", action="store_true", help="Build/update local CVE database from NVD API")
    cve_group.add_argument("--cve-rebuild", action="store_true", help="Drop and rebuild CVE tables before importing")
    cve_group.add_argument("--cve-update-mode", choices=("auto", "full", "incremental"), default="auto", help="Update mode: auto (default), full, or incremental")
    cve_group.add_argument("--cve-force-download", action="store_true", help="Incremental: ignore last-update timestamp and re-fetch the full window")
    cve_group.add_argument("--nvd-api-key", default="", help="NVD API key for ~10x faster downloads. Free at nvd.nist.gov/developers/request-an-api-key. Can also set NVD_API_KEY env var.")
    cve_group.add_argument("--min-cvss", type=float, default=0.0, help="Only store CVEs with CVSS >= this value (default: 0.0 = all)")
    cve_group.add_argument("--cve-start-year", type=int, default=2018, help=argparse.SUPPRESS)
    cve_group.add_argument("--cve-end-year", type=int, default=datetime.now(UTC).year, help=argparse.SUPPRESS)
    # Legacy flags — accepted but unused
    cve_group.add_argument("--cve-offline", action="store_true", help=argparse.SUPPRESS)
    cve_group.add_argument("--cve-feed-dir", default="data/nvd_feeds", help=argparse.SUPPRESS)

    # --- Execution options ---
    exec_group = parser.add_argument_group("execution")
    exec_group.add_argument(
        "--execute", action="store_true",
        help="Execute safe enumeration commands against scan targets (requires confirmation)",
    )
    exec_group.add_argument(
        "--exec-timeout", type=float, default=60.0,
        help="Timeout per command in seconds (default: 60)",
    )
    exec_group.add_argument(
        "--max-exec-commands", type=int, default=30,
        help="Max commands to execute automatically (default: 30)",
    )
    exec_group.add_argument(
        "--no-confirm", action="store_true",
        help="Skip confirmation prompt before executing commands",
    )
    exec_group.add_argument(
        "--remote-host", default="", metavar="USER@HOST",
        help="Execute commands on a remote host via SSH (e.g. kali@192.168.1.100)",
    )
    exec_group.add_argument(
        "--remote-key", default="", metavar="PATH",
        help="Path to SSH private key for remote host (default: uses SSH agent / default key)",
    )
    exec_group.add_argument(
        "--remote-port", type=int, default=22,
        help="SSH port for remote host (default: 22)",
    )

    # --- Output options ---
    output_group = parser.add_argument_group("output options")
    output_group.add_argument("--playbooks", default="data/enumeration_playbooks.json", help="Path to playbooks JSON file (default: data/enumeration_playbooks.json)")
    output_group.add_argument("--db", default="data/cve_database.db", help=argparse.SUPPRESS)

    # --- Logging / debug ---
    log_group = parser.add_argument_group("logging")
    log_group.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity (default: INFO)")
    log_group.add_argument("--debug", action="store_true", help="Shortcut for --log-level DEBUG")
    return parser


def _print_execution_plan(plan: Any, remote_host: str = "") -> None:
    """Print the execution plan to terminal for user review."""
    print("\n" + "=" * 60)
    print("EXECUTION PLAN")
    print("=" * 60)
    mode = f"remote ({remote_host})" if remote_host else "local"
    print(f"Execution mode: {mode}")

    if plan.commands:
        print(f"\nCommands to execute ({len(plan.commands)}):\n")
        for i, cmd in enumerate(plan.commands, 1):
            print(f"  [{i:02d}] [{cmd.tool}] {cmd.command}")
    else:
        print("\n  No executable commands found.")

    if plan.manual_suggestions:
        print(f"\nManual suggestions — run these yourself ({len(plan.manual_suggestions)}):\n")
        for cmd in plan.manual_suggestions:
            print(f"  $ {cmd}")
    print()


def _confirm_execution() -> bool:
    """Ask user to confirm before executing commands."""
    try:
        answer = input("Proceed with execution? [y/N]: ").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        return False


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

    return True, warnings


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if not args.scan and not args.cve_db_update:
        parser.error("scan is required unless --cve-db-update is used")

    log_level = "DEBUG" if args.debug else args.log_level

    # Always write a full DEBUG log to logs/run_<timestamp>.log
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"run_{log_timestamp}.log"

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # File handler — always DEBUG, full format with timestamps
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s",
                          datefmt="%Y-%m-%d %H:%M:%S")
    )
    root_logger.addHandler(file_handler)

    # Console handler — respects --log-level, minimal format
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level))
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root_logger.addHandler(console_handler)

    logging.getLogger(__name__).info("Log file: %s", log_file)

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
            batch_size=5000,
            explicit_feeds=[],
            api_key=args.nvd_api_key,
            min_cvss=args.min_cvss,
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

    if args.profile and not args.ai:
        parser.error("--profile requires --ai (e.g. --ai --profile external)")

    ai_provider = args.ai  # None if not set, "ollama" if set
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
        profile_note = f", profile: {args.profile}" if args.profile else ""
        print(f"AI enabled: {ai_provider} (model: {resolved_model}{profile_note})", file=sys.stderr)

    if args.execute and not ai_provider:
        print("Warning: --execute works best with --ai for live findings synthesis.", file=sys.stderr)

    config = AnalysisConfig(
        cve_db_path=args.db,
        playbook_path=args.playbooks,
        ai_provider=ai_provider,
        ai_model=args.ai_model,
        ai_key=args.ai_key or "",
        ai_timeout_seconds=max(1.0, args.ai_timeout),
        max_ai_commands=max(0, args.max_ai_commands),
        profile=args.profile,
        execute=args.execute,
        max_exec_commands=max(1, args.max_exec_commands),
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

    # --- Execution phase ---
    if args.execute and result.execution_plan:
        plan = result.execution_plan
        _print_execution_plan(plan, remote_host=args.remote_host)

        should_run = bool(plan.commands) and (args.no_confirm or _confirm_execution())
        if should_run:
            from pentest_assistant.executor import (
                ExecutionEngine, SSHConfig, SSHMaster,
                check_tools_available, check_sudo_passwordless,
            )
            from pentest_assistant.ai import ScanAnalyzer
            from pentest_assistant.providers import create_provider

            ssh_config = None
            ssh_master_for_preflight: Any = None
            if args.remote_host:
                ssh_config = SSHConfig(
                    host=args.remote_host,
                    port=args.remote_port,
                    key_path=args.remote_key,
                )
                print(f"\nConnecting to {args.remote_host}...")

            # --- Pre-flight: tool availability + sudo check ---
            print("\nRunning pre-flight checks...")
            tools_needed = {cmd.tool for cmd in plan.commands}

            try:
                master_ctx = SSHMaster(ssh_config) if ssh_config else None
                if master_ctx:
                    master_ctx.connect()

                tool_status = check_tools_available(tools_needed, master_ctx)
                sudo_ok = check_sudo_passwordless(master_ctx)

                missing = [t for t, ok in tool_status.items() if not ok]
                if missing:
                    print(f"\n  WARNING — Tools not found on target system:")
                    for t in sorted(missing):
                        print(f"    ✗  {t}")
                    print("  Commands using these tools will fail. Install them or skip.\n")

                # Check if any planned command uses sudo
                uses_sudo = any("sudo" in cmd.command for cmd in plan.commands)
                if uses_sudo and not sudo_ok:
                    print(
                        "  WARNING — Some commands use sudo but sudo requires a password.\n"
                        "  Those commands will fail. To fix:\n"
                        "    echo 'kali ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/nmap-analyzer\n"
                        "  Or remove sudo from the relevant commands.\n"
                    )
                elif uses_sudo and sudo_ok:
                    print("  Sudo: passwordless ✓")

                if not missing and (not uses_sudo or sudo_ok):
                    print("  All checks passed ✓")

                if master_ctx:
                    master_ctx.disconnect()

            except Exception as exc:
                print(f"  Pre-flight check failed: {exc}")

            print(f"\nExecuting {len(plan.commands)} commands...\n")
            enum_dir = report_dir / "enumeration"
            engine = ExecutionEngine(timeout=args.exec_timeout, ssh_config=ssh_config)
            result.execution_results = engine.run(plan.commands, enum_dir)
            result.manual_suggestions = plan.manual_suggestions

            total_cmds = len(result.execution_results)
            successes = sum(1 for r in result.execution_results if r.success)
            failed = total_cmds - successes
            print(f"\nExecution complete: {successes}/{total_cmds} succeeded", end="")
            print(f", {failed} failed/timed out." if failed else ".")

            # AI synthesis — always runs after execution if AI is enabled,
            # regardless of how many commands succeeded. Partial results are
            # still valuable and Ollama explicitly notes what failed.
            if ai_provider and result.execution_results:
                print(
                    f"\nSynthesizing {total_cmds} enumeration results with Ollama...\n"
                    f"  Reading full output from: {enum_dir}/\n"
                    f"  This may take a few minutes depending on the model..."
                )
                try:
                    synth_provider = create_provider(
                        ai_provider,
                        model=args.ai_model or None,
                        timeout=args.ai_timeout,
                    )
                    analyzer = ScanAnalyzer(synth_provider, profile=args.profile)
                    result.live_findings = analyzer.synthesize_execution_results(
                        result.execution_results,
                        enum_dir=enum_dir,
                        profile=args.profile,
                    )
                    if result.live_findings:
                        print("  Synthesis complete.")
                    else:
                        print("  Warning: Ollama returned an empty synthesis.")
                except Exception as exc:
                    logging.getLogger(__name__).warning("Synthesis failed: %s", exc)
        else:
            result.manual_suggestions = plan.manual_suggestions
            if plan.commands and not should_run:
                print("Execution skipped.")

    # --- Save reports ---
    text_path = report_dir / "findings.txt"
    text_path.write_text(text_report + "\n", encoding="utf-8")

    generate_html_report(result, report_dir / "report.html", args.scan)

    print(f"\nReports saved to: {report_dir}/")
    print(f"  findings.txt")
    print(f"  report.html")

    if result.ai_analysis:
        ai_path = report_dir / "ai_report.txt"
        ai_path.write_text(result.ai_analysis + "\n", encoding="utf-8")
        print(f"  ai_report.txt")

    if result.execution_results:
        print(f"  enumeration/   ({len(result.execution_results)} command outputs)")

    if result.live_findings:
        lf_path = report_dir / "live_findings.txt"
        lf_path.write_text(result.live_findings + "\n", encoding="utf-8")
        print(f"  live_findings.txt")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
