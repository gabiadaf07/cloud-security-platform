from pathlib import Path
import unittest

from security_platform.investigation.cloudtrail_investigator import investigate
from security_platform.scanners.kubernetes_scanner import scan as scan_kubernetes
from security_platform.scanners.terraform_scanner import scan as scan_terraform


FIXTURES = Path(__file__).parent / "fixtures"


class TerraformScannerTests(unittest.TestCase):
    def test_detects_at_least_twelve_misconfiguration_categories(self) -> None:
        findings = scan_terraform([FIXTURES / "terraform" / "insecure"])
        rule_ids = {finding.rule_id for finding in findings}
        self.assertGreaterEqual(len(rule_ids), 12)
        self.assertIn("CSP-TF-001", rule_ids)
        self.assertIn("CSP-TF-002", rule_ids)
        self.assertIn("CSP-TF-015", rule_ids)
        self.assertIn("CSP-TF-020", rule_ids)

    def test_secure_fixture_has_no_high_or_critical_findings(self) -> None:
        findings = scan_terraform([FIXTURES / "terraform" / "secure"])
        self.assertFalse([item for item in findings if item.severity in {"HIGH", "CRITICAL"}])


class CloudTrailInvestigatorTests(unittest.TestCase):
    def test_detects_all_four_incident_categories(self) -> None:
        alerts = investigate([FIXTURES / "cloudtrail" / "suspicious.json"])
        self.assertEqual(
            {"credential-abuse", "privilege-escalation", "exfiltration", "evidence-destruction"},
            {item.category for item in alerts},
        )


class KubernetesScannerTests(unittest.TestCase):
    def test_detects_workload_and_rbac_failures(self) -> None:
        findings = scan_kubernetes([FIXTURES / "kubernetes" / "insecure"])
        rule_ids = {finding.rule_id for finding in findings}
        self.assertTrue({"CSP-K8S-001", "CSP-K8S-005", "CSP-K8S-011"}.issubset(rule_ids))

    def test_hardened_workload_passes_high_severity_gate(self) -> None:
        findings = scan_kubernetes([FIXTURES / "kubernetes" / "secure"])
        self.assertFalse([item for item in findings if item.severity in {"HIGH", "CRITICAL"}])


if __name__ == "__main__":
    unittest.main()
