import tempfile
import unittest
from pathlib import Path

from pentest_assistant.models import AnalysisResult, CVEEntry, Host, Service, ServiceFinding
from pentest_assistant.reporting import generate_html_report


class DashboardTests(unittest.TestCase):
    def test_dashboard_contains_expected_sections(self) -> None:
        hosts = [
            Host(
                ip="10.0.0.10",
                role="Web Server",
                services=[Service(port=80, protocol="tcp", name="http", product="Apache", version="2.4.58")],
            )
        ]
        findings = [
            ServiceFinding(
                service=hosts[0].services[0],
                ips=["10.0.0.10"],
                cves=[CVEEntry(cve_id="CVE-2099-0001", cvss_score=9.8, description="test cve")],
                playbook_commands=["nikto -h http://TARGET"],
                ai_commands=[],
                playbook_confidence=0.6,
                ai_confidence=0.0,
                command_suggestions=[],
                risk_score=12.8,
            )
        ]
        result = AnalysisResult(
            hosts=hosts,
            role_groups={"Web Server": ["10.0.0.10"]},
            findings=findings,
        )

        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "report.html"
            generate_html_report(result, output, "scan.xml")
            html = output.read_text(encoding="utf-8")

        # Dashboard sections
        self.assertIn("Network Overview", html)
        self.assertIn("Top Group Targets", html)
        self.assertIn("Service Groups", html)
        self.assertIn("Pentest Checklist Panel", html)
        self.assertIn("10.0.0.10", html)

        # Tab structure
        self.assertIn('id="dashboard-tab"', html)
        self.assertIn('id="findings-tab"', html)


if __name__ == "__main__":
    unittest.main()
