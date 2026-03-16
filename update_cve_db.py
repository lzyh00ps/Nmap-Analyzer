from __future__ import annotations

import argparse
import gzip
import json
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

NVD_FEED_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
DEFAULT_DOWNLOAD_DIR = Path("data/nvd_feeds")
DEFAULT_DB_PATH = Path("data/cve_database.db")
DEFAULT_START_YEAR = 2002
DEFAULT_BATCH_SIZE = 1000
HTTP_TIMEOUT_SECONDS = 120
RETRY_COUNT = 3


@dataclass
class UpdateConfig:
    db_path: Path
    download_dir: Path
    mode: str
    start_year: int
    end_year: int
    force_download: bool
    offline: bool
    rebuild: bool
    batch_size: int
    explicit_feeds: list[str]


@dataclass
class FeedMetadata:
    feed_name: str
    last_modified: str
    sha256: str
    source_url: str


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _http_get_bytes(url: str) -> bytes:
    headers = {"User-Agent": "nmap-analyzer-cve-updater/1.0"}
    req = Request(url, headers=headers)

    last_error: Exception | None = None
    for _ in range(RETRY_COUNT):
        try:
            with urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
                return response.read()
        except (HTTPError, URLError, TimeoutError) as exc:
            last_error = exc

    if last_error is None:
        raise RuntimeError(f"HTTP download failed for {url}")
    raise RuntimeError(f"HTTP download failed for {url}: {last_error}") from last_error


def _http_get_text(url: str) -> str:
    return _http_get_bytes(url).decode("utf-8", errors="replace")


def _parse_meta_text(meta_text: str, feed_name: str, source_url: str) -> FeedMetadata:
    values: dict[str, str] = {}
    for line in meta_text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()

    return FeedMetadata(
        feed_name=feed_name,
        last_modified=values.get("lastModifiedDate", ""),
        sha256=values.get("sha256", ""),
        source_url=source_url,
    )


def _ensure_schema(conn: sqlite3.Connection, rebuild: bool = False) -> None:
    if rebuild:
        conn.execute("DROP TABLE IF EXISTS cves")
        conn.execute("DROP TABLE IF EXISTS cve_feed_metadata")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            product TEXT,
            version TEXT,
            severity TEXT,
            cvss_score REAL,
            description TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cve_feed_metadata (
            feed_name TEXT PRIMARY KEY,
            last_modified TEXT,
            sha256 TEXT,
            source_url TEXT,
            updated_at TEXT,
            records INTEGER
        )
        """
    )

    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_product ON cves(product)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_score)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity)")
    conn.commit()


def _load_feed_metadata_from_db(conn: sqlite3.Connection) -> dict[str, FeedMetadata]:
    rows = conn.execute(
        "SELECT feed_name, last_modified, sha256, source_url FROM cve_feed_metadata"
    ).fetchall()
    output: dict[str, FeedMetadata] = {}
    for row in rows:
        output[str(row[0])] = FeedMetadata(
            feed_name=str(row[0]),
            last_modified=str(row[1] or ""),
            sha256=str(row[2] or ""),
            source_url=str(row[3] or ""),
        )
    return output


def _target_feeds(config: UpdateConfig) -> list[str]:
    if config.explicit_feeds:
        return config.explicit_feeds

    if config.mode == "incremental":
        return ["nvdcve-2.0-modified", "nvdcve-2.0-recent"]

    feeds = [f"nvdcve-2.0-{year}" for year in range(config.start_year, config.end_year + 1)]
    feeds.extend(["nvdcve-2.0-modified", "nvdcve-2.0-recent"])
    return feeds


def _write_bytes_atomic(destination: Path, payload: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb", prefix="tmp-feed-", suffix=".part", dir=destination.parent, delete=False
    ) as tmp:
        tmp.write(payload)
        temp_path = Path(tmp.name)
    temp_path.replace(destination)


def _prepare_feed_file(
    feed_name: str,
    config: UpdateConfig,
    existing_meta: FeedMetadata | None,
) -> tuple[Path, FeedMetadata]:
    feed_base_url = f"{NVD_FEED_BASE_URL}/{feed_name}"
    gz_url = f"{feed_base_url}.json.gz"
    meta_url = f"{feed_base_url}.meta"
    gz_file = config.download_dir / f"{feed_name}.json.gz"
    meta_file = config.download_dir / f"{feed_name}.meta"

    if config.offline:
        if not gz_file.exists():
            raise RuntimeError(f"Offline mode requested but feed file is missing: {gz_file}")
        if meta_file.exists():
            meta_text = meta_file.read_text(encoding="utf-8", errors="replace")
            return gz_file, _parse_meta_text(meta_text, feed_name=feed_name, source_url=gz_url)
        return gz_file, FeedMetadata(feed_name=feed_name, last_modified="", sha256="", source_url=gz_url)

    remote_meta_text = _http_get_text(meta_url)
    remote_meta = _parse_meta_text(remote_meta_text, feed_name=feed_name, source_url=gz_url)
    _write_bytes_atomic(meta_file, remote_meta_text.encode("utf-8"))

    unchanged = (
        not config.force_download
        and gz_file.exists()
        and existing_meta is not None
        and existing_meta.last_modified == remote_meta.last_modified
        and existing_meta.sha256 == remote_meta.sha256
        and remote_meta.last_modified != ""
    )
    if unchanged:
        return gz_file, remote_meta

    payload = _http_get_bytes(gz_url)
    _write_bytes_atomic(gz_file, payload)
    return gz_file, remote_meta


def _iter_vulnerabilities_from_gzip(feed_path: Path) -> Iterable[dict]:
    """
    Stream vulnerability objects from a NVD JSON feed without loading the full document.
    """
    decoder = json.JSONDecoder()
    buffer = ""
    cursor = 0
    in_array = False
    eof = False

    with gzip.open(feed_path, mode="rt", encoding="utf-8", errors="replace") as handle:
        while True:
            if not eof and len(buffer) - cursor < 1_000_000:
                chunk = handle.read(1_000_000)
                if chunk:
                    buffer += chunk
                else:
                    eof = True

            if not in_array:
                key_index = buffer.find('"vulnerabilities"')
                if key_index == -1:
                    if eof:
                        raise ValueError(f"Feed does not contain vulnerabilities array: {feed_path}")
                    if len(buffer) > 128:
                        buffer = buffer[-128:]
                        cursor = 0
                    continue
                start_index = buffer.find("[", key_index)
                if start_index == -1:
                    if eof:
                        raise ValueError(f"Invalid feed JSON (missing '['): {feed_path}")
                    continue
                in_array = True
                cursor = start_index + 1

            parsed_any = False
            while in_array:
                while cursor < len(buffer) and buffer[cursor] in " \r\n\t,":
                    cursor += 1
                if cursor >= len(buffer):
                    break
                if buffer[cursor] == "]":
                    return

                try:
                    item, next_cursor = decoder.raw_decode(buffer, cursor)
                except json.JSONDecodeError:
                    break

                parsed_any = True
                cursor = next_cursor
                if isinstance(item, dict):
                    yield item

                if cursor > 1_000_000:
                    buffer = buffer[cursor:]
                    cursor = 0

            if eof:
                while cursor < len(buffer) and buffer[cursor] in " \r\n\t":
                    cursor += 1
                if cursor < len(buffer) and buffer[cursor] == "]":
                    return
                raise ValueError(f"Unexpected EOF while parsing feed: {feed_path}")

            if not parsed_any and cursor > 0 and cursor > len(buffer) // 2:
                buffer = buffer[cursor:]
                cursor = 0


def _pick_description(cve_payload: dict) -> str:
    descriptions = cve_payload.get("descriptions", [])
    if isinstance(descriptions, list):
        for item in descriptions:
            if isinstance(item, dict) and item.get("lang") == "en":
                value = str(item.get("value", "")).strip()
                if value:
                    return value
        for item in descriptions:
            if isinstance(item, dict):
                value = str(item.get("value", "")).strip()
                if value:
                    return value
    return ""


def _pick_cvss(cve_payload: dict) -> tuple[float, str]:
    metrics = cve_payload.get("metrics", {})
    if not isinstance(metrics, dict):
        return 0.0, "UNKNOWN"

    score = 0.0
    severity = "UNKNOWN"
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_group = metrics.get(key, [])
        if not isinstance(metric_group, list):
            continue
        for metric in metric_group:
            if not isinstance(metric, dict):
                continue
            cvss_data = metric.get("cvssData", {})
            if not isinstance(cvss_data, dict):
                cvss_data = {}
            raw_score = cvss_data.get("baseScore")
            try:
                candidate_score = float(raw_score)
            except (TypeError, ValueError):
                candidate_score = 0.0

            candidate_severity = str(
                cvss_data.get("baseSeverity") or metric.get("baseSeverity") or "UNKNOWN"
            ).upper()
            if candidate_score >= score:
                score = candidate_score
                severity = candidate_severity

    return score, severity


def _iter_cpe_match_objects(payload: object) -> Iterable[dict]:
    if isinstance(payload, dict):
        if "criteria" in payload and isinstance(payload.get("criteria"), str):
            yield payload
        for value in payload.values():
            yield from _iter_cpe_match_objects(value)
    elif isinstance(payload, list):
        for item in payload:
            yield from _iter_cpe_match_objects(item)


def _extract_products_and_versions(cve_payload: dict) -> tuple[str, str]:
    product_values: list[str] = []
    version_values: list[str] = []
    seen_product: set[str] = set()
    seen_version: set[str] = set()

    for match in _iter_cpe_match_objects(cve_payload.get("configurations", [])):
        if not isinstance(match, dict):
            continue
        if match.get("vulnerable") is False:
            continue

        criteria = str(match.get("criteria", "")).strip()
        if not criteria:
            continue

        # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
        parts = criteria.split(":")
        vendor = parts[3] if len(parts) > 4 else ""
        product = parts[4] if len(parts) > 4 else ""
        version = parts[5] if len(parts) > 5 else ""

        product_token = f"{vendor}:{product}" if vendor and product else (product or vendor)
        if product_token and product_token not in seen_product:
            seen_product.add(product_token)
            product_values.append(product_token)

        version_token = ""
        if version and version not in ("*", "-"):
            version_token = version
        else:
            start_inc = match.get("versionStartIncluding")
            start_exc = match.get("versionStartExcluding")
            end_inc = match.get("versionEndIncluding")
            end_exc = match.get("versionEndExcluding")
            range_parts: list[str] = []
            if start_inc:
                range_parts.append(f">={start_inc}")
            if start_exc:
                range_parts.append(f">{start_exc}")
            if end_inc:
                range_parts.append(f"<={end_inc}")
            if end_exc:
                range_parts.append(f"<{end_exc}")
            if range_parts:
                version_token = ",".join(range_parts)

        if version_token and version_token not in seen_version:
            seen_version.add(version_token)
            version_values.append(version_token)

    return ";".join(product_values[:10]), ";".join(version_values[:10])


def _extract_cve_row(vuln_item: dict) -> tuple[str, str, str, str, float, str] | None:
    cve_payload = vuln_item.get("cve", vuln_item)
    if not isinstance(cve_payload, dict):
        return None

    cve_id = str(cve_payload.get("id", "")).strip()
    if not cve_id:
        return None

    product, version = _extract_products_and_versions(cve_payload)
    cvss_score, severity = _pick_cvss(cve_payload)
    description = _pick_description(cve_payload)

    return (
        cve_id,
        product,
        version,
        severity,
        cvss_score,
        description,
    )


def _upsert_rows(conn: sqlite3.Connection, rows: list[tuple[str, str, str, str, float, str]]) -> None:
    conn.executemany(
        """
        INSERT INTO cves (cve_id, product, version, severity, cvss_score, description)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            product=excluded.product,
            version=excluded.version,
            severity=excluded.severity,
            cvss_score=excluded.cvss_score,
            description=excluded.description
        """,
        rows,
    )


def _process_feed(
    conn: sqlite3.Connection,
    feed_name: str,
    feed_path: Path,
    feed_meta: FeedMetadata,
    batch_size: int,
) -> int:
    total = 0
    batch: list[tuple[str, str, str, str, float, str]] = []

    for vulnerability in _iter_vulnerabilities_from_gzip(feed_path):
        row = _extract_cve_row(vulnerability)
        if row is None:
            continue
        batch.append(row)

        if len(batch) >= batch_size:
            _upsert_rows(conn, batch)
            conn.commit()
            total += len(batch)
            batch.clear()

    if batch:
        _upsert_rows(conn, batch)
        conn.commit()
        total += len(batch)

    conn.execute(
        """
        INSERT INTO cve_feed_metadata(feed_name, last_modified, sha256, source_url, updated_at, records)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(feed_name) DO UPDATE SET
            last_modified=excluded.last_modified,
            sha256=excluded.sha256,
            source_url=excluded.source_url,
            updated_at=excluded.updated_at,
            records=excluded.records
        """,
        (
            feed_name,
            feed_meta.last_modified,
            feed_meta.sha256,
            feed_meta.source_url,
            _utc_now_iso(),
            total,
        ),
    )
    conn.commit()
    return total


def update_cve_database(config: UpdateConfig) -> int:
    config.download_dir.mkdir(parents=True, exist_ok=True)
    config.db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(config.db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        _ensure_schema(conn, rebuild=config.rebuild)

        existing_feed_meta = _load_feed_metadata_from_db(conn)
        feeds = _target_feeds(config)
        if not feeds:
            raise ValueError("No feeds selected for update")

        total_processed = 0
        for feed_name in feeds:
            current_meta = existing_feed_meta.get(feed_name)
            feed_path, feed_meta = _prepare_feed_file(feed_name, config, existing_meta=current_meta)
            processed = _process_feed(
                conn=conn,
                feed_name=feed_name,
                feed_path=feed_path,
                feed_meta=feed_meta,
                batch_size=max(1, config.batch_size),
            )
            total_processed += processed
            print(f"[feed] {feed_name}: processed {processed} CVE records")

        print(f"[done] total processed records: {total_processed}")
        print(f"[done] database path: {config.db_path}")
        return total_processed
    finally:
        conn.close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download NVD CVE feeds and build/update a local SQLite database."
    )
    parser.add_argument("--db-path", default=str(DEFAULT_DB_PATH), help="SQLite database path")
    parser.add_argument(
        "--download-dir",
        default=str(DEFAULT_DOWNLOAD_DIR),
        help="Directory to store downloaded .json.gz and .meta feed files",
    )
    parser.add_argument(
        "--mode",
        choices=("full", "incremental"),
        default="incremental",
        help="Update mode: full (all yearly feeds) or incremental (modified + recent)",
    )
    parser.add_argument(
        "--start-year",
        type=int,
        default=DEFAULT_START_YEAR,
        help="Start year for full mode (default: 2002)",
    )
    parser.add_argument(
        "--end-year",
        type=int,
        default=datetime.now(UTC).year,
        help="End year for full mode (default: current year)",
    )
    parser.add_argument(
        "--feed",
        action="append",
        default=[],
        help="Explicit feed name override (repeatable), e.g. --feed nvdcve-2.0-2025",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Always download feeds even if metadata appears unchanged",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Do not use network; use only previously downloaded feed files",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Drop and rebuild database tables before importing",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="SQLite upsert batch size",
    )
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
        explicit_feeds=[str(feed) for feed in args.feed],
    )


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    config = config_from_args(args)

    if config.end_year < config.start_year:
        parser.error("--end-year must be >= --start-year")

    try:
        update_cve_database(config)
        return 0
    except Exception as exc:
        print(f"[error] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
