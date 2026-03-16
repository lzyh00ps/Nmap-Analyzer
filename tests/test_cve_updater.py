import gzip
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from update_cve_db import UpdateConfig, _extract_cve_row, _iter_vulnerabilities_from_gzip, update_cve_database


def _sample_feed_payload() -> dict:
    return {
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0001",
                    "descriptions": [
                        {"lang": "en", "value": "Example remote code execution flaw"},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }


class CVEUpdaterTests(unittest.TestCase):
    def test_extract_cve_row_maps_expected_fields(self) -> None:
        payload = _sample_feed_payload()["vulnerabilities"][0]
        row = _extract_cve_row(payload)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row[0], "CVE-2099-0001")
        self.assertEqual(row[1], "apache:http_server")
        self.assertEqual(row[2], "2.4.49")
        self.assertEqual(row[3], "CRITICAL")
        self.assertEqual(row[4], 9.8)
        self.assertIn("remote code execution", row[5])

    def test_update_database_offline_from_cached_feed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_path = root / "cves.db"
            feed_dir = root / "feeds"
            feed_dir.mkdir(parents=True, exist_ok=True)
            feed_name = "nvdcve-2.0-test"
            feed_path = feed_dir / f"{feed_name}.json.gz"

            payload = _sample_feed_payload()
            with gzip.open(feed_path, "wt", encoding="utf-8") as handle:
                json.dump(payload, handle)

            config = UpdateConfig(
                db_path=db_path,
                download_dir=feed_dir,
                mode="incremental",
                start_year=2002,
                end_year=2099,
                force_download=False,
                offline=True,
                rebuild=True,
                batch_size=100,
                explicit_feeds=[feed_name],
            )

            processed = update_cve_database(config)
            self.assertEqual(processed, 1)

            conn = sqlite3.connect(db_path)
            row = conn.execute(
                "SELECT cve_id, product, version, severity, cvss_score FROM cves WHERE cve_id='CVE-2099-0001'"
            ).fetchone()
            meta = conn.execute(
                "SELECT feed_name, records FROM cve_feed_metadata WHERE feed_name=?",
                (feed_name,),
            ).fetchone()
            conn.close()

            self.assertIsNotNone(row)
            self.assertEqual(row[1], "apache:http_server")
            self.assertEqual(row[2], "2.4.49")
            self.assertEqual(row[3], "CRITICAL")
            self.assertEqual(row[4], 9.8)
            self.assertEqual(meta[0], feed_name)
            self.assertEqual(meta[1], 1)

    def test_stream_parser_reads_vulnerabilities_array(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "feed.json.gz"
            payload = _sample_feed_payload()
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                json.dump(payload, handle)

            rows = list(_iter_vulnerabilities_from_gzip(path))
            self.assertEqual(len(rows), 1)
            self.assertIn("cve", rows[0])


if __name__ == "__main__":
    unittest.main()
