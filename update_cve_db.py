"""
NVD CVE database updater — NVD REST API 2.0 + CISA KEV.

Only imports CVEs that are pentest-relevant:
  - In the CISA Known Exploited Vulnerabilities (KEV) catalog, OR
  - Have a classifiable exploit type (RCE, auth bypass, file read, SQLi,
    privilege escalation, SSRF, XXE, credential disclosure, file write)
    AND a CVSS score >= 6.0 AND are not DoS-only.

Data sources:
  NVD API  : https://services.nvd.nist.gov/rest/json/cves/2.0
  CISA KEV : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Rate limits:
  No API key  : 5 req / 30 s  → 6.1 s delay
  With API key: 50 req / 30 s → 0.65 s delay

Speed tip: export NVD_API_KEY=<key>  (free at nvd.nist.gov/developers/request-an-api-key)
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NVD_API_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_DB_PATH  = Path("data/cve_database.db")
DEFAULT_DOWNLOAD_DIR = Path("data/nvd_feeds")  # kept for backward compat, unused
DEFAULT_START_YEAR   = 2018
DEFAULT_BATCH_SIZE   = 5000
RESULTS_PER_PAGE     = 2000
HTTP_TIMEOUT         = 60
RETRY_COUNT          = 3
_MAX_WINDOW_DAYS     = 110
_DELAY_NO_KEY        = 6.1
_DELAY_KEYED         = 0.65
_MIN_CVSS_NON_KEV    = 6.0   # minimum CVSS for non-KEV CVEs with exploit type


# ---------------------------------------------------------------------------
# Exploit classification
# ---------------------------------------------------------------------------

# Patterns that indicate a CVE is useful for pentesting / red teaming.
# Order matters: first match wins (higher priority types listed first).
_EXPLOIT_PATTERNS: dict[str, tuple[str, ...]] = {
    "rce": (
        "remote code execution", "arbitrary code execution", "execute arbitrary code",
        "execute code", "arbitrary code", "code injection", "command injection",
        "os command injection", "shell injection", "arbitrary command",
        "execute arbitrary", "buffer overflow", "heap overflow", "stack overflow",
        "use-after-free", "use after free", "heap spray", "deserialization",
        "unsafe deserialization", "java deserialization", "type confusion",
        "out-of-bounds write", "memory corruption", "format string vulnerability",
        "arbitrary write", "write-what-where",
    ),
    "auth_bypass": (
        "authentication bypass", "bypass authentication", "unauthenticated access",
        "unauthenticated remote", "unauthenticated attacker", "improper authentication",
        "missing authentication", "no authentication required", "weak authentication",
        "bypass login", "login bypass", "bypass access control",
        "broken access control", "improper access control",
    ),
    "privesc": (
        "privilege escalation", "escalate privilege", "local privilege escalation",
        "gain elevated", "obtain elevated", "elevate privilege", "become root",
        "become administrator", "gain root", "gain admin", "gain system",
        "local root", "kernel exploit", "kernel privilege",
    ),
    "file_read": (
        "path traversal", "directory traversal", "arbitrary file read",
        "arbitrary file access", "read arbitrary file", "file disclosure",
        "local file inclusion", "remote file inclusion", " lfi ", " rfi ",
        "read files outside", "sensitive file", "passwd file", "shadow file",
        "directory listing", "expose files", "expose sensitive",
    ),
    "file_write": (
        "arbitrary file write", "arbitrary file upload", "unrestricted file upload",
        "write arbitrary file", "upload arbitrary files", "file upload vulnerability",
        "malicious file upload",
    ),
    "sqli": (
        "sql injection", "blind sql", "boolean-based sql", "time-based sql",
        "union-based sql", "inject sql", "sql query manipulation",
    ),
    "ssrf": (
        "server-side request forgery", "ssrf", "make the server perform",
        "cause the server to make", "internal network access",
    ),
    "xxe": (
        "xml external entity", " xxe ", "xxe injection", "xml injection",
    ),
    "credential_disclosure": (
        "hardcoded password", "hardcoded credential", "hardcoded secret",
        "plaintext password", "cleartext password", "credentials in plaintext",
        "credentials exposed", "password disclosure", "api key exposure",
        "private key disclosure", "access token exposure", "obtain credentials",
        "steal credentials", "harvest credentials", "credential leakage",
        "sensitive information disclosure", "obtain sensitive information",
        "sensitive data exposure", "disclose sensitive",
    ),
}

# If ALL matches come only from these patterns, the CVE is DoS-only → skip.
_DOS_PATTERNS: tuple[str, ...] = (
    "denial of service", "denial-of-service", " dos ", "cause a crash",
    "cause the application to crash", "cause the service to crash",
    "infinite loop", "resource exhaustion", "memory exhaustion", "cpu exhaustion",
    "out of memory", "stack exhaustion", "null pointer dereference",
    "application crash", "service crash", "forced crash", "forced reboot",
)

# If ANY of these appear alongside DoS patterns, it is NOT DoS-only.
_DOS_OVERRIDE: tuple[str, ...] = (
    "remote code", "arbitrary code", "execute", "injection", "bypass",
    "traversal", "escalat", "disclosure", "read arbitrary", "write arbitrary",
    "sql", "ssrf", "xxe", "deserialization", "upload", "credential",
)


def _classify_exploit(description: str) -> str:
    """
    Return the primary pentest-relevant exploit type from a CVE description,
    or an empty string if the CVE is not pentest-relevant (e.g. DoS-only).
    """
    desc = description.lower()

    # Rule out DoS-only CVEs
    has_dos = any(p in desc for p in _DOS_PATTERNS)
    has_override = any(p in desc for p in _DOS_OVERRIDE)
    if has_dos and not has_override:
        return ""

    for etype, patterns in _EXPLOIT_PATTERNS.items():
        if any(p in desc for p in patterns):
            return etype

    return ""


def _is_pentest_relevant(
    exploit_type: str,
    cvss_score: float,
    is_kev: bool,
    all_cves: bool,
) -> bool:
    """Return True if this CVE should be stored in the pentest-focused database."""
    if all_cves:
        return True
    if is_kev:
        return True                         # KEV = always relevant
    if not exploit_type:
        return False                        # DoS-only or unclassifiable
    return cvss_score >= _MIN_CVSS_NON_KEV  # exploit type + minimum impact


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

def _download_kev_set() -> set[str]:
    """
    Download the CISA Known Exploited Vulnerabilities catalog.
    Returns a set of CVE IDs (e.g. {'CVE-2021-44228', ...}).
    Falls back to an empty set on any network error.
    """
    print("[kev] Downloading CISA KEV catalog...")
    try:
        req = Request(CISA_KEV_URL, headers={"User-Agent": "nmap-analyzer-cve-updater/2.0"})
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        ids = {v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")}
        print(f"[kev] {len(ids):,} known exploited CVEs loaded from CISA KEV")
        return ids
    except Exception as exc:
        print(f"[kev] Warning: could not download CISA KEV ({exc}). Continuing without it.")
        return set()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class UpdateConfig:
    db_path: Path
    download_dir: Path        # unused — backward compat
    mode: str                 # "full" | "incremental"
    start_year: int
    end_year: int
    force_download: bool
    offline: bool             # unsupported with API, ignored
    rebuild: bool
    batch_size: int
    explicit_feeds: list[str] # unused — backward compat
    api_key: str = ""
    min_cvss: float = 0.0     # user-facing CVSS floor (on top of pentest filter)
    all_cves: bool = False     # bypass pentest filter, import everything


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _windows(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    out: list[tuple[datetime, datetime]] = []
    delta = timedelta(days=_MAX_WINDOW_DAYS)
    cur = start
    while cur < end:
        out.append((cur, min(cur + delta, end)))
        cur = out[-1][1]
    return out


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

def _fetch_page(params: dict, api_key: str) -> dict:
    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
    headers: dict[str, str] = {"User-Agent": "nmap-analyzer-cve-updater/2.0"}
    if api_key:
        headers["apiKey"] = api_key

    last_exc: Exception | None = None
    for attempt in range(RETRY_COUNT):
        try:
            with urlopen(Request(url, headers=headers), timeout=HTTP_TIMEOUT) as resp:
                return json.loads(resp.read())
        except HTTPError as exc:
            if exc.code == 403:
                print(f"\n  [warn] Rate-limited (HTTP 403) — waiting 35 s...")
                time.sleep(35)
            elif exc.code in (400, 404):
                raise RuntimeError(f"NVD API {exc.code}: {params}") from exc
            else:
                time.sleep(2 ** attempt)
            last_exc = exc
        except (URLError, TimeoutError, OSError) as exc:
            time.sleep(2 ** attempt)
            last_exc = exc

    raise RuntimeError(f"NVD API failed after {RETRY_COUNT} attempts: {last_exc}")


# ---------------------------------------------------------------------------
# SQLite layer
# ---------------------------------------------------------------------------

def _ensure_schema(conn: sqlite3.Connection, rebuild: bool = False) -> None:
    if rebuild:
        conn.execute("DROP TABLE IF EXISTS cves")
        conn.execute("DROP TABLE IF EXISTS cve_feed_metadata")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id       TEXT PRIMARY KEY,
            product      TEXT,
            version      TEXT,
            severity     TEXT,
            cvss_score   REAL,
            description  TEXT,
            exploit_type TEXT,
            is_kev       INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_feed_metadata (
            feed_name     TEXT PRIMARY KEY,
            last_modified TEXT,
            sha256        TEXT,
            source_url    TEXT,
            updated_at    TEXT,
            records       INTEGER
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_product      ON cves(product)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss         ON cves(cvss_score)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity     ON cves(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_exploit_type ON cves(exploit_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_is_kev       ON cves(is_kev)")
    conn.commit()


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Add new columns to existing databases without requiring a full rebuild."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(cves)").fetchall()}
    if "exploit_type" not in existing:
        conn.execute("ALTER TABLE cves ADD COLUMN exploit_type TEXT")
        print("[migrate] Added column: exploit_type")
    if "is_kev" not in existing:
        conn.execute("ALTER TABLE cves ADD COLUMN is_kev INTEGER DEFAULT 0")
        print("[migrate] Added column: is_kev")
    conn.commit()


def _upsert_rows(conn: sqlite3.Connection, rows: list[tuple]) -> None:
    conn.executemany("""
        INSERT INTO cves
            (cve_id, product, version, severity, cvss_score, description, exploit_type, is_kev)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            product      = excluded.product,
            version      = excluded.version,
            severity     = excluded.severity,
            cvss_score   = excluded.cvss_score,
            description  = excluded.description,
            exploit_type = excluded.exploit_type,
            is_kev       = excluded.is_kev
    """, rows)


def _save_metadata(conn: sqlite3.Connection, feed_name: str, records: int) -> None:
    conn.execute("""
        INSERT INTO cve_feed_metadata
            (feed_name, last_modified, sha256, source_url, updated_at, records)
        VALUES (?, '', '', ?, ?, ?)
        ON CONFLICT(feed_name) DO UPDATE SET
            updated_at = excluded.updated_at,
            records    = excluded.records
    """, (feed_name, NVD_API_URL, _utc_now_iso(), records))
    conn.commit()


def _get_last_update(conn: sqlite3.Connection) -> datetime | None:
    row = conn.execute(
        "SELECT updated_at FROM cve_feed_metadata WHERE feed_name = 'api-incremental'"
    ).fetchone()
    if row and row[0]:
        try:
            return datetime.fromisoformat(str(row[0]))
        except ValueError:
            pass
    return None


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------

def _pick_description(cve: dict) -> str:
    for item in cve.get("descriptions", []):
        if isinstance(item, dict) and item.get("lang") == "en":
            v = str(item.get("value", "")).strip()
            if v:
                return v
    for item in cve.get("descriptions", []):
        if isinstance(item, dict):
            v = str(item.get("value", "")).strip()
            if v:
                return v
    return ""


def _pick_cvss(cve: dict) -> tuple[float, str]:
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        return 0.0, "UNKNOWN"
    score, severity = 0.0, "UNKNOWN"
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            if not isinstance(m, dict):
                continue
            cd = m.get("cvssData") or {}
            try:
                s = float(cd.get("baseScore") or 0)
            except (TypeError, ValueError):
                s = 0.0
            sev = str(cd.get("baseSeverity") or m.get("baseSeverity") or "UNKNOWN").upper()
            if s >= score:
                score, severity = s, sev
    return score, severity


def _iter_cpe_matches(obj: object):
    if isinstance(obj, dict):
        if "criteria" in obj and isinstance(obj.get("criteria"), str):
            yield obj
        for v in obj.values():
            yield from _iter_cpe_matches(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_cpe_matches(item)


def _extract_products_versions(cve: dict) -> tuple[str, str]:
    products: list[str] = []
    versions: list[str] = []
    seen_p: set[str] = set()
    seen_v: set[str] = set()

    for m in _iter_cpe_matches(cve.get("configurations", [])):
        if m.get("vulnerable") is False:
            continue
        parts = str(m.get("criteria", "")).split(":")
        vendor  = parts[3] if len(parts) > 4 else ""
        product = parts[4] if len(parts) > 4 else ""
        version = parts[5] if len(parts) > 5 else ""

        pt = f"{vendor}:{product}" if vendor and product else (product or vendor)
        if pt and pt not in seen_p:
            seen_p.add(pt)
            products.append(pt)

        vt = ""
        if version and version not in ("*", "-"):
            vt = version
        else:
            ranges: list[str] = []
            if m.get("versionStartIncluding"): ranges.append(f">={m['versionStartIncluding']}")
            if m.get("versionStartExcluding"): ranges.append(f">{m['versionStartExcluding']}")
            if m.get("versionEndIncluding"):   ranges.append(f"<={m['versionEndIncluding']}")
            if m.get("versionEndExcluding"):   ranges.append(f"<{m['versionEndExcluding']}")
            if ranges:
                vt = ",".join(ranges)
        if vt and vt not in seen_v:
            seen_v.add(vt)
            versions.append(vt)

    return ";".join(products[:10]), ";".join(versions[:10])


def _extract_row(
    vuln: dict,
    kev_ids: set[str],
) -> tuple[str, str, str, str, float, str, str, int] | None:
    """
    Extract a CVE row from a NVD API vulnerability object.
    Returns (cve_id, product, version, severity, cvss, description, exploit_type, is_kev)
    or None if extraction fails.
    """
    cve = vuln.get("cve", vuln)
    if not isinstance(cve, dict):
        return None

    cve_id = str(cve.get("id", "")).strip()
    if not cve_id:
        return None

    # CISA KEV: check both the NVD API field and the downloaded KEV set
    is_kev = int(
        bool(cve.get("cisaExploitAdd"))
        or cve_id in kev_ids
    )

    product, version = _extract_products_versions(cve)
    cvss_score, severity = _pick_cvss(cve)
    description = _pick_description(cve)
    exploit_type = _classify_exploit(description)

    return (cve_id, product, version, severity, cvss_score, description, exploit_type, is_kev)


# ---------------------------------------------------------------------------
# Core fetch → store loop
# ---------------------------------------------------------------------------

def _fetch_and_store(
    conn: sqlite3.Connection,
    config: UpdateConfig,
    params: dict,
    delay: float,
    label: str,
    kev_ids: set[str],
) -> tuple[int, int]:
    """
    Paginate through NVD API results. Store only pentest-relevant CVEs.
    Returns (stored, skipped).
    """
    start_index  = 0
    total_results: int | None = None
    stored = skipped = 0
    batch: list[tuple] = []

    while True:
        page_params = {
            **params,
            "startIndex":     start_index,
            "resultsPerPage": RESULTS_PER_PAGE,
        }

        try:
            data = _fetch_page(page_params, config.api_key)
        except Exception as exc:
            print(f"\n  [warn] API request failed at offset {start_index}: {exc}")
            break

        if total_results is None:
            total_results = int(data.get("totalResults", 0))
            if total_results == 0:
                break
            pages = (total_results + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE
            print(f"  [{label}] {total_results:,} CVEs across {pages} page(s)")

        vulnerabilities: list[dict] = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for vuln in vulnerabilities:
            row = _extract_row(vuln, kev_ids)
            if row is None:
                skipped += 1
                continue

            _, _, _, _, cvss_score, _, exploit_type, is_kev = row

            # Pentest relevance filter
            if not _is_pentest_relevant(exploit_type, cvss_score, bool(is_kev), config.all_cves):
                skipped += 1
                continue

            # User-supplied minimum CVSS (applied on top of pentest filter)
            if config.min_cvss > 0.0 and cvss_score < config.min_cvss and not is_kev:
                skipped += 1
                continue

            batch.append(row)

        if len(batch) >= config.batch_size:
            _upsert_rows(conn, batch)
            conn.commit()
            stored += len(batch)
            batch.clear()
            pct = int(stored / total_results * 100) if total_results else 0
            print(f"  [{label}] stored {stored:,} / {total_results or '?':,} ({pct}%)...",
                  end="\r", flush=True)

        start_index += len(vulnerabilities)
        if total_results is not None and start_index >= total_results:
            break

        time.sleep(delay)

    if batch:
        _upsert_rows(conn, batch)
        conn.commit()
        stored += len(batch)

    if stored or skipped:
        print(f"  [{label}] {stored:,} stored, {skipped:,} skipped (not pentest-relevant).   ")

    return stored, skipped


# ---------------------------------------------------------------------------
# Full and incremental modes
# ---------------------------------------------------------------------------

def _run_full(
    conn: sqlite3.Connection, config: UpdateConfig, delay: float, kev_ids: set[str]
) -> int:
    start_dt = datetime(config.start_year, 1, 1, tzinfo=UTC)
    end_dt   = datetime(config.end_year, 12, 31, 23, 59, 59, tzinfo=UTC)
    wins     = _windows(start_dt, end_dt)

    print(f"[full] {config.start_year}–{config.end_year}: {len(wins)} date window(s)")
    if not config.api_key:
        est = int(len(wins) * 3 * delay / 60)
        print(f"[full] Estimated time without API key: ~{est}–{est + 5} min")
        print(f"[full] Tip: set NVD_API_KEY env var to go ~10x faster")

    total = 0
    for i, (w_start, w_end) in enumerate(wins, 1):
        label = f"{w_start.strftime('%Y-%m-%d')}→{w_end.strftime('%Y-%m-%d')} ({i}/{len(wins)})"
        stored, _ = _fetch_and_store(conn, config, {
            "pubStartDate": _fmt(w_start),
            "pubEndDate":   _fmt(w_end),
        }, delay, label, kev_ids)
        total += stored

    _save_metadata(conn, "api-full", total)
    return total


def _run_incremental(
    conn: sqlite3.Connection, config: UpdateConfig, delay: float, kev_ids: set[str]
) -> int:
    now  = datetime.now(UTC)
    last = _get_last_update(conn)

    if last and not config.force_download:
        start_dt = last - timedelta(hours=1)
        print(f"[incr] Fetching CVEs modified since {start_dt.strftime('%Y-%m-%d %H:%M')} UTC")
    else:
        start_dt = now - timedelta(days=_MAX_WINDOW_DAYS)
        print(f"[incr] No prior timestamp — fetching last {_MAX_WINDOW_DAYS} days")

    wins  = _windows(start_dt, now)
    total = 0

    for w_start, w_end in wins:
        label = f"{w_start.strftime('%Y-%m-%d')}→{w_end.strftime('%Y-%m-%d')}"
        stored, _ = _fetch_and_store(conn, config, {
            "lastModStartDate": _fmt(w_start),
            "lastModEndDate":   _fmt(w_end),
        }, delay, label, kev_ids)
        total += stored

    _save_metadata(conn, "api-incremental", total)
    return total


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def update_cve_database(config: UpdateConfig) -> int:
    if config.offline:
        print("[warn] --cve-offline is not supported with the NVD REST API — ignoring.")

    # Resolve API key from env var if not passed explicitly
    api_key = config.api_key or os.getenv("NVD_API_KEY", "")
    if api_key != config.api_key:
        config = UpdateConfig(**{**config.__dict__, "api_key": api_key})  # type: ignore[arg-type]

    config.db_path.parent.mkdir(parents=True, exist_ok=True)

    if config.all_cves:
        print("[filter] --all-cves: pentest filter disabled, importing all CVEs")
    else:
        print(f"[filter] Pentest filter ON — keeping: KEV + exploit-type CVEs (CVSS >= {_MIN_CVSS_NON_KEV})")

    # Download CISA KEV before opening DB (network call, no lock needed)
    kev_ids = _download_kev_set()

    conn = sqlite3.connect(config.db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=-65536")
        conn.execute("PRAGMA mmap_size=268435456")

        _ensure_schema(conn, rebuild=config.rebuild)
        _migrate_schema(conn)   # adds exploit_type / is_kev to existing DBs

        delay = _DELAY_KEYED if config.api_key else _DELAY_NO_KEY

        if config.mode == "incremental":
            total = _run_incremental(conn, config, delay, kev_ids)
        else:
            total = _run_full(conn, config, delay, kev_ids)

        conn.execute("PRAGMA synchronous=NORMAL")
        conn.commit()

        print(f"[done] {total:,} pentest-relevant CVE records stored")
        print(f"[done] database: {config.db_path}")
        return total
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CLI (standalone: python3 update_cve_db.py)
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Download NVD CVE data and build/update a local SQLite database.\n"
            "Only stores CVEs with known public exploits useful for pentesting:\n"
            "  RCE, auth bypass, privilege escalation, file read/write, SQLi,\n"
            "  SSRF, XXE, and credential disclosure — plus all CISA KEV entries."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 update_cve_db.py                       # incremental (fast)\n"
            "  python3 update_cve_db.py --mode full           # full build 2018-present\n"
            "  python3 update_cve_db.py --mode full --rebuild # drop + rebuild\n"
            "  python3 update_cve_db.py --min-cvss 7.0        # high-severity only\n"
            "  python3 update_cve_db.py --all-cves            # disable pentest filter\n\n"
            "speed:\n"
            "  export NVD_API_KEY=your-key  # ~10x faster\n"
            "  free key: https://nvd.nist.gov/developers/request-an-api-key"
        ),
    )
    parser.add_argument("--db-path", default=str(DEFAULT_DB_PATH),
                        help=f"SQLite database path (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--mode", choices=("full", "incremental"), default="incremental",
                        help="Update mode (default: incremental)")
    parser.add_argument("--start-year", type=int, default=DEFAULT_START_YEAR,
                        help=f"Oldest publication year for full mode (default: {DEFAULT_START_YEAR})")
    parser.add_argument("--end-year", type=int, default=datetime.now(UTC).year,
                        help="Newest publication year for full mode (default: current year)")
    parser.add_argument("--rebuild", action="store_true",
                        help="Drop and rebuild tables before importing")
    parser.add_argument("--force-download", action="store_true",
                        help="Incremental: ignore last-update timestamp")
    parser.add_argument("--nvd-api-key", default="",
                        help="NVD API key (~10x faster). Also reads NVD_API_KEY env var.")
    parser.add_argument("--min-cvss", type=float, default=0.0,
                        help="Only store non-KEV CVEs with CVSS >= this value (default: 0.0)")
    parser.add_argument("--all-cves", action="store_true",
                        help="Disable the pentest filter and import all CVEs (much larger DB)")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help=argparse.SUPPRESS)
    # Legacy compat — accepted but unused
    parser.add_argument("--download-dir", default=str(DEFAULT_DOWNLOAD_DIR), help=argparse.SUPPRESS)
    parser.add_argument("--offline", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--feed", action="append", default=[], help=argparse.SUPPRESS)
    return parser


def config_from_args(args: argparse.Namespace) -> UpdateConfig:
    return UpdateConfig(
        db_path=Path(args.db_path),
        download_dir=Path(args.download_dir),
        mode=args.mode,
        start_year=args.start_year,
        end_year=args.end_year,
        force_download=args.force_download,
        offline=args.offline,
        rebuild=args.rebuild,
        batch_size=args.batch_size,
        explicit_feeds=[str(f) for f in args.feed],
        api_key=args.nvd_api_key,
        min_cvss=args.min_cvss,
        all_cves=args.all_cves,
    )


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.end_year < args.start_year:
        parser.error("--end-year must be >= --start-year")

    try:
        update_cve_database(config_from_args(args))
        return 0
    except KeyboardInterrupt:
        print("\n[interrupted] partial data saved.")
        return 130
    except Exception as exc:
        print(f"[error] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
