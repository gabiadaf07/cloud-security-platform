from pathlib import Path
import unittest

from security_platform.investigation.cloudtrail_investigator import investigate, investigate_event
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

    def test_evaluated_plan_detects_jsonencoded_wildcards_and_missing_s3_block(self) -> None:
        findings = scan_terraform(
            [],
            [FIXTURES / "terraform" / "plans" / "insecure.json"],
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertTrue({"CSP-TF-009", "CSP-TF-015", "CSP-TF-016"}.issubset(rule_ids))

    def test_legitimate_global_action_is_not_excessive_resource_finding(self) -> None:
        findings = scan_terraform(
            [],
            [FIXTURES / "terraform" / "plans" / "legitimate-global-action.json"],
        )
        self.assertNotIn("CSP-TF-016", {finding.rule_id for finding in findings})

    def test_source_scan_detects_s3_bucket_without_public_access_block(self) -> None:
        findings = scan_terraform([FIXTURES / "terraform" / "regressions"])
        self.assertIn("CSP-TF-009", {finding.rule_id for finding in findings})


class CloudTrailInvestigatorTests(unittest.TestCase):
    def test_detects_all_four_incident_categories(self) -> None:
        alerts = investigate([FIXTURES / "cloudtrail" / "suspicious.json"])
        self.assertEqual(
            {"credential-abuse", "privilege-escalation", "exfiltration", "evidence-destruction"},
            {item.category for item in alerts},
        )

    def test_null_response_elements_is_safe(self) -> None:
        event = {
            "eventName": "ConsoleLogin",
            "responseElements": None,
            "errorCode": "Failed authentication",
            "userIdentity": None,
        }
        alerts = investigate_event(event, Path("null-response.json"))
        self.assertIn("CSP-CT-001", {item.rule_id for item in alerts})

    def test_passrole_is_inferred_from_role_bearing_service_call(self) -> None:
        impossible_event = {"eventName": "PassRole", "requestParameters": {"roleArn": "arn:example"}}
        service_event = {
            "eventName": "CreateFunction",
            "requestParameters": {"role": "arn:aws:iam::123456789012:role/lambda-runtime"},
        }
        self.assertNotIn(
            "CSP-CT-005",
            {item.rule_id for item in investigate_event(impossible_event, Path("pass-role.json"))},
        )
        self.assertIn(
            "CSP-CT-005",
            {item.rule_id for item in investigate_event(service_event, Path("create-function.json"))},
        )

    def test_common_activity_is_classified_as_triage_not_incident_proof(self) -> None:
        get_object = investigate_event({"eventName": "GetObject"}, Path("get-object.json"))
        iam_change = investigate_event({"eventName": "AttachRolePolicy"}, Path("iam-change.json"))
        self.assertEqual("LOW", get_object[0].severity)
        self.assertEqual("HIGH", iam_change[0].severity)
        self.assertTrue(all(item.classification == "triage-signal" for item in get_object + iam_change))


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
