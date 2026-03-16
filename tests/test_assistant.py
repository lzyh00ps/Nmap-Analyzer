import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pentest_assistant.ai import AICommandGenerator
from pentest_assistant.cve import CVELookup
from pentest_assistant.models import Service
from pentest_assistant.parser import parse_nmap
from pentest_assistant.pipeline import AnalysisConfig, analyze_scan
from pentest_assistant.playbooks import PlaybookMatcher


class ParserTests(unittest.TestCase):
    def test_parser_handles_missing_service_and_address(self) -> None:
        xml = (
            "<nmaprun>"
            "<host>"
            "<ports>"
            "<port protocol='tcp' portid='22'>"
            "<state state='open'/>"
            "</port>"
            "</ports>"
            "</host>"
            "</nmaprun>"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".xml") as handle:
            handle.write(xml)
            handle.flush()
            hosts = parse_nmap(handle.name)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip, "unknown")
        self.assertEqual(hosts[0].services[0].name, "unknown")

    def test_parser_ignores_tcpwrapped_services(self) -> None:
        xml = (
            "<nmaprun>"
            "<host><address addr='10.0.0.10' addrtype='ipv4'/>"
            "<ports>"
            "<port protocol='tcp' portid='80'><state state='open'/><service name='http'/></port>"
            "<port protocol='tcp' portid='62078'><state state='open'/><service name='tcpwrapped'/></port>"
            "</ports></host>"
            "</nmaprun>"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".xml") as handle:
            handle.write(xml)
            handle.flush()
            hosts = parse_nmap(handle.name)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(len(hosts[0].services), 1)
        self.assertEqual(hosts[0].services[0].name, "http")


class PlaybookTests(unittest.TestCase):
    def test_playbook_match_scores_by_port_and_service(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "playbooks.json"
            path.write_text(
                json.dumps(
                    {
                        "http": {"commands": ["whatweb TARGET"]},
                        "sql": {"commands": ["nmap -sV -p 1433 TARGET"], "ports": [1433]},
                    }
                ),
                encoding="utf-8",
            )

            matcher = PlaybookMatcher.from_file(path)
            service = Service(port=1433, protocol="tcp", name="ms-sql-s", product="mssql", version="2019")
            commands = matcher.match(service, "SQL Server")

        self.assertIn("nmap -sV -p 1433 TARGET", commands)

    def test_product_specific_playbook_boosts_score(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "playbooks.json"
            path.write_text(
                json.dumps(
                    {
                        "http": {"commands": ["whatweb TARGET"], "ports": [80]},
                        "http_apache": {
                            "commands": ["curl -s http://TARGET/server-status"],
                            "ports": [80],
                            "services": ["http"],
                            "products": ["apache"],
                        },
                    }
                ),
                encoding="utf-8",
            )

            matcher = PlaybookMatcher.from_file(path)
            service = Service(port=80, protocol="tcp", name="http", product="Apache httpd", version="2.4.58")
            match = matcher.match_with_metadata(service, "Web Server")

        # Product-specific rule should be the top match
        self.assertEqual(match.matched_rules[0], "http_apache")
        self.assertIn("curl -s http://TARGET/server-status", match.commands)
        # Generic http commands should also be included
        self.assertIn("whatweb TARGET", match.commands)
        # Confidence should be higher than without product match
        self.assertGreater(match.confidence, 0.5)

    def test_playbook_rejects_non_list_commands(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "playbooks.json"
            path.write_text(json.dumps({"http": {"commands": "nikto -h TARGET"}}), encoding="utf-8")

            with self.assertRaises(ValueError):
                PlaybookMatcher.from_file(path)


class CVETests(unittest.TestCase):
    def test_cve_lookup_returns_ranked_entries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "cves.db"
            conn = sqlite3.connect(db)
            conn.execute("create table cves (cve_id text, cvss_score real, description text)")
            conn.executemany(
                "insert into cves values (?, ?, ?)",
                [
                    ("CVE-1", 6.0, "nginx vulnerability"),
                    ("CVE-2", 9.0, "critical nginx resolver vulnerability"),
                ],
            )
            conn.commit()
            conn.close()

            lookup = CVELookup(db, per_service_limit=1)
            service = Service(port=80, protocol="tcp", name="http", product="nginx", version="1.18")
            result = lookup.lookup(service)
            lookup.close()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].cve_id, "CVE-2")


class AISafetyTests(unittest.TestCase):
    def test_ai_safety_filters_dangerous_commands(self) -> None:
        raw = json.dumps(
            [
                "nmap -sV TARGET",
                "rm -rf /",
                "enum4linux TARGET && cat /etc/passwd",
                "whatweb TARGET",
            ]
        )
        commands = AICommandGenerator._extract_commands(raw, limit=10)
        self.assertEqual(commands, ["nmap -sV TARGET", "whatweb TARGET"])

    def test_ai_allowlist_blocks_unknown_or_write_commands(self) -> None:
        raw = json.dumps(
            [
                "python -c 'print(1)'",
                "curl -o out.txt http://TARGET",
                "ldapsearch -x -H ldap://TARGET",
            ]
        )
        commands = AICommandGenerator._extract_commands(raw, limit=10)
        self.assertEqual(commands, ["ldapsearch -x -H ldap://TARGET"])


class PipelineTests(unittest.TestCase):
    def test_ai_supplements_playbook_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "scan.xml"
            playbooks = root / "playbooks.json"
            scan.write_text(
                "<nmaprun><host><address addr='10.0.0.1' addrtype='ipv4'/>"
                "<ports><port protocol='tcp' portid='80'><state state='open'/>"
                "<service name='http' product='Apache'/></port></ports></host></nmaprun>",
                encoding="utf-8",
            )
            playbooks.write_text(json.dumps({"http": {"commands": ["whatweb TARGET"]}}), encoding="utf-8")

            config = AnalysisConfig(
                playbook_path=str(playbooks),
                cve_db_path=str(root / "missing.db"),
                ai_enabled=True,
            )
            with patch("pentest_assistant.pipeline.AICommandGenerator.generate") as generate_mock:
                generate_mock.return_value = ["nmap -sV TARGET"]
                result = analyze_scan(str(scan), config)

            self.assertEqual(generate_mock.call_count, 1)
            self.assertGreater(result.findings[0].playbook_confidence, 0.0)
            self.assertEqual(result.findings[0].ai_confidence, 0.45)
            sources = {s.source for s in result.findings[0].command_suggestions}
            self.assertEqual(sources, {"playbook", "ai"})

    def test_ai_disabled_uses_playbooks_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "scan.xml"
            playbooks = root / "playbooks.json"
            scan.write_text(
                "<nmaprun><host><address addr='10.0.0.1' addrtype='ipv4'/>"
                "<ports><port protocol='tcp' portid='80'><state state='open'/>"
                "<service name='http'/></port></ports></host></nmaprun>",
                encoding="utf-8",
            )
            playbooks.write_text(json.dumps({"http": {"commands": ["whatweb TARGET"]}}), encoding="utf-8")

            config = AnalysisConfig(
                playbook_path=str(playbooks),
                cve_db_path=str(root / "missing.db"),
                ai_enabled=False,
            )
            with patch("pentest_assistant.pipeline.AICommandGenerator.generate") as generate_mock:
                result = analyze_scan(str(scan), config)

            self.assertEqual(generate_mock.call_count, 0)
            self.assertEqual(result.findings[0].ai_commands, [])
            self.assertEqual(result.findings[0].ai_confidence, 0.0)
            self.assertTrue(all(s.source == "playbook" for s in result.findings[0].command_suggestions))

    def test_mixed_role_service_uses_highest_priority_role_for_risk(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "scan.xml"
            playbooks = root / "playbooks.json"
            scan.write_text(
                "<nmaprun>"
                "<host><address addr='10.0.0.5' addrtype='ipv4'/>"
                "<ports>"
                "<port protocol='tcp' portid='80'><state state='open'/><service name='http'/></port>"
                "<port protocol='tcp' portid='88'><state state='open'/><service name='kerberos'/></port>"
                "<port protocol='tcp' portid='389'><state state='open'/><service name='ldap'/></port>"
                "</ports></host>"
                "<host><address addr='10.0.0.8' addrtype='ipv4'/>"
                "<ports><port protocol='tcp' portid='80'><state state='open'/><service name='http'/></port></ports>"
                "</host>"
                "</nmaprun>",
                encoding="utf-8",
            )
            playbooks.write_text(json.dumps({"http": {"commands": ["whatweb TARGET"]}}), encoding="utf-8")

            config = AnalysisConfig(
                playbook_path=str(playbooks),
                cve_db_path=str(root / "missing.db"),
                ai_enabled=False,
            )
            result = analyze_scan(str(scan), config)

            http_finding = next(f for f in result.findings if f.service.port == 80)
            self.assertEqual(http_finding.risk_score, 5.0)

    def test_ai_confidence_is_set_for_ai_fallback_suggestions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "scan.xml"
            playbooks = root / "playbooks.json"
            scan.write_text(
                "<nmaprun><host><address addr='10.0.0.9' addrtype='ipv4'/>"
                "<ports><port protocol='tcp' portid='3000'><state state='open'/>"
                "<service name='grafana'/></port></ports></host></nmaprun>",
                encoding="utf-8",
            )
            playbooks.write_text(json.dumps({"http": {"commands": ["whatweb TARGET"]}}), encoding="utf-8")

            config = AnalysisConfig(
                playbook_path=str(playbooks),
                cve_db_path=str(root / "missing.db"),
                ai_enabled=True,
            )
            with patch("pentest_assistant.pipeline.AICommandGenerator.generate") as generate_mock:
                generate_mock.return_value = ["nmap -sV -p 3000 TARGET"]
                result = analyze_scan(str(scan), config)

            self.assertEqual(generate_mock.call_count, 1)
            self.assertEqual(result.findings[0].playbook_confidence, 0.0)
            self.assertEqual(result.findings[0].ai_confidence, 0.45)
            self.assertEqual(result.findings[0].command_suggestions[0].source, "ai")


class RobustnessTests(unittest.TestCase):
    """Edge-case tests to ensure the tool never crashes on unusual nmap input."""

    def test_empty_scan_no_hosts(self) -> None:
        """Scan with no hosts at all should return empty result, not crash."""
        xml = "<nmaprun></nmaprun>"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "empty.xml"
            scan.write_text(xml, encoding="utf-8")
            playbooks = root / "playbooks.json"
            playbooks.write_text(json.dumps({"http": {"commands": ["whatweb TARGET"]}}), encoding="utf-8")

            config = AnalysisConfig(
                playbook_path=str(playbooks),
                cve_db_path=str(root / "missing.db"),
            )
            result = analyze_scan(str(scan), config)

        self.assertEqual(result.hosts, [])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.role_groups, {})

    def test_hosts_with_all_ports_closed(self) -> None:
        """Hosts where all ports are closed/filtered should not crash."""
        xml = (
            "<nmaprun>"
            "<host><address addr='10.0.0.1' addrtype='ipv4'/>"
            "<ports>"
            "<port protocol='tcp' portid='80'><state state='closed'/></port>"
            "<port protocol='tcp' portid='443'><state state='filtered'/></port>"
            "</ports></host>"
            "</nmaprun>"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "closed.xml"
            scan.write_text(xml, encoding="utf-8")
            playbooks = root / "playbooks.json"
            playbooks.write_text(json.dumps({"http": {"commands": ["whatweb TARGET"]}}), encoding="utf-8")

            config = AnalysisConfig(
                playbook_path=str(playbooks),
                cve_db_path=str(root / "missing.db"),
            )
            result = analyze_scan(str(scan), config)

        self.assertEqual(result.hosts, [])
        self.assertEqual(result.findings, [])

    def test_missing_playbook_file_does_not_crash(self) -> None:
        """Missing playbook file should warn and continue, not crash."""
        xml = (
            "<nmaprun><host><address addr='10.0.0.1' addrtype='ipv4'/>"
            "<ports><port protocol='tcp' portid='80'><state state='open'/>"
            "<service name='http'/></port></ports></host></nmaprun>"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "scan.xml"
            scan.write_text(xml, encoding="utf-8")

            config = AnalysisConfig(
                playbook_path=str(root / "nonexistent_playbooks.json"),
                cve_db_path=str(root / "missing.db"),
            )
            result = analyze_scan(str(scan), config)

        self.assertEqual(len(result.hosts), 1)
        self.assertEqual(len(result.findings), 1)
        # No playbook commands since file was missing
        self.assertEqual(result.findings[0].playbook_commands, [])

    def test_strip_fences_handles_empty_and_none_like_input(self) -> None:
        """_strip_fences should handle empty strings safely."""
        self.assertEqual(AICommandGenerator._strip_fences(""), "")
        self.assertEqual(AICommandGenerator._strip_fences("   "), "")
        self.assertEqual(AICommandGenerator._strip_fences("```\n```"), "")
        self.assertEqual(AICommandGenerator._strip_fences("<think>reasoning</think>"), "")

    def test_extract_commands_handles_empty_response(self) -> None:
        """_extract_commands should return empty list for empty/garbage input."""
        self.assertEqual(AICommandGenerator._extract_commands("", limit=10), [])
        self.assertEqual(AICommandGenerator._extract_commands("   ", limit=10), [])
        self.assertEqual(AICommandGenerator._extract_commands("not json", limit=10), [])

    def test_scan_with_only_tcpwrapped_services(self) -> None:
        """Hosts where all services are tcpwrapped should be excluded."""
        xml = (
            "<nmaprun>"
            "<host><address addr='10.0.0.1' addrtype='ipv4'/>"
            "<ports>"
            "<port protocol='tcp' portid='80'><state state='open'/><service name='tcpwrapped'/></port>"
            "<port protocol='tcp' portid='443'><state state='open'/><service name='tcpwrapped'/></port>"
            "</ports></host>"
            "</nmaprun>"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scan = root / "wrapped.xml"
            scan.write_text(xml, encoding="utf-8")
            playbooks = root / "playbooks.json"
            playbooks.write_text(json.dumps({"http": {"commands": ["whatweb TARGET"]}}), encoding="utf-8")

            config = AnalysisConfig(
                playbook_path=str(playbooks),
                cve_db_path=str(root / "missing.db"),
            )
            result = analyze_scan(str(scan), config)

        # tcpwrapped services are filtered, so no hosts with open services
        self.assertEqual(result.hosts, [])

    def test_dos_cve_filter(self) -> None:
        """_is_dos_cve should correctly classify DoS vs RCE CVEs."""
        from pentest_assistant.ai import ScanAnalyzer

        # Pure DoS — should be filtered
        self.assertTrue(ScanAnalyzer._is_dos_cve("denial of service via crafted packet"))
        self.assertTrue(ScanAnalyzer._is_dos_cve("resource exhaustion leads to crash"))

        # RCE — should NOT be filtered
        self.assertFalse(ScanAnalyzer._is_dos_cve("remote code execution via buffer overflow"))
        self.assertFalse(ScanAnalyzer._is_dos_cve("command injection in web interface"))

        # Mixed DoS+RCE — should NOT be filtered (has RCE component)
        self.assertFalse(ScanAnalyzer._is_dos_cve(
            "buffer overflow allows denial of service or arbitrary code execution"
        ))

        # No indicators — should NOT be filtered
        self.assertFalse(ScanAnalyzer._is_dos_cve("information disclosure vulnerability"))
        self.assertFalse(ScanAnalyzer._is_dos_cve(""))


if __name__ == "__main__":
    unittest.main()
