import tempfile
import unittest
from pathlib import Path

from pentest_assistant.models import AnalysisResult, CVEEntry, Host, Service, ServiceFinding
from pentest_assistant.reporting import build_text_report, generate_html_report


class ReportingTests(unittest.TestCase):
    def _make_result(self) -> AnalysisResult:
        service = Service(port=80, protocol="tcp", name="http", product="Apache", version="2.4.58")
        finding = ServiceFinding(
            service=service,
            ips=["10.10.10.1", "10.10.10.2"],
            cves=[CVEEntry(cve_id="CVE-2099-0001", cvss_score=9.8, description="test")],
            playbook_commands=["nikto -h http://TARGET"],
            ai_commands=["whatweb http://TARGET"],
            playbook_confidence=0.8,
            ai_confidence=0.4,
            command_suggestions=[],
            risk_score=12.8,
        )
        return AnalysisResult(
            hosts=[
                Host(ip="10.10.10.1", services=[service], role="Web Server"),
                Host(ip="10.10.10.2", services=[service], role="Web Server"),
            ],
            role_groups={"Web Server": ["10.10.10.1", "10.10.10.2"]},
            findings=[finding],
            ai_enabled=True,
        )

    def test_reports_use_grouped_target_placeholder(self) -> None:
        result = self._make_result()

        text = build_text_report(result)
        self.assertIn("nikto -h http://TARGET-IP", text)
        self.assertIn("whatweb http://TARGET-IP", text)
        self.assertIn("Targets: 10.10.10.1, 10.10.10.2", text)
        self.assertNotIn("nikto -h http://10.10.10.1", text)
        self.assertNotIn("nikto -h http://10.10.10.2", text)

        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "report.html"
            generate_html_report(result, report_path, "scan.xml")
            html = report_path.read_text(encoding="utf-8")

        self.assertIn("nikto -h http://TARGET-IP", html)
        self.assertIn("Targets:</b> 10.10.10.1, 10.10.10.2", html)
        self.assertNotIn("nikto -h http://10.10.10.1", html)

    def test_unified_report_has_tabs(self) -> None:
        result = self._make_result()

        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "report.html"
            generate_html_report(result, report_path, "scan.xml")
            html = report_path.read_text(encoding="utf-8")

        self.assertIn('id="dashboard-tab"', html)
        self.assertIn('id="findings-tab"', html)
        self.assertIn('class="tab-bar"', html)
        self.assertIn("Dashboard", html)
        self.assertIn("Findings", html)
        # Both sections exist in one file
        self.assertIn("SECTION 1", html)  # dashboard
        self.assertIn("Playbook Commands", html)  # findings


    def test_ai_analysis_tab_shown_when_present(self) -> None:
        result = self._make_result()
        result.ai_provider = "ollama"
        result.ai_analysis = "## Priority Targets\n- **10.10.10.1** — Web server with critical CVE"

        text = build_text_report(result)
        self.assertIn("=== Attack Plan ===", text)
        self.assertIn("Priority Targets", text)

        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "report.html"
            generate_html_report(result, report_path, "scan.xml")
            html = report_path.read_text(encoding="utf-8")

        self.assertIn('id="ai-tab"', html)
        self.assertIn("Attack Plan", html)
        self.assertIn("ai-analysis-content", html)

    def test_ai_analysis_tab_hidden_when_empty(self) -> None:
        result = self._make_result()
        result.ai_analysis = ""

        text = build_text_report(result)
        self.assertNotIn("Attack Plan", text)

        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "report.html"
            generate_html_report(result, report_path, "scan.xml")
            html = report_path.read_text(encoding="utf-8")

        self.assertNotIn('id="ai-tab"', html)


if __name__ == "__main__":
    unittest.main()
