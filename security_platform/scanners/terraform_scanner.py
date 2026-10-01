#!/usr/bin/env python3
"""Terraform source and evaluated-plan security scanner for core controls.

Source scanning gives fast feedback for literal resource blocks. ``--plan-json``
accepts the output of ``terraform show -json`` so policies produced by
``jsonencode``, locals, variables and modules are inspected after evaluation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Block:
    resource_type: str
    name: str
    text: str
    file: Path
    line: int


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    resource: str


RESOURCE_START = re.compile(
    r'\bresource\s+"(?P<type>[A-Za-z0-9_]+)"\s+"(?P<name>[A-Za-z0-9_-]+)"\s*\{'
)

# These APIs do not support resource-level permissions. A wildcard Resource is
# therefore not excessive when every action in the statement is in this small,
# reviewed set. This is deliberately an allowlist rather than a generic
# suppression for read/list actions.
GLOBAL_RESOURCE_ACTIONS = {
    "ecr:GetAuthorizationToken",
    "s3:ListAllMyBuckets",
    "sts:GetCallerIdentity",
}


def strip_comments(source: str) -> str:
    """Remove comments while preserving line count and quoted string contents."""
    output: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
        elif char == "#" or (char == "/" and nxt == "/"):
            while index < len(source) and source[index] != "\n":
                output.append(" ")
                index += 1
        elif char == "/" and nxt == "*":
            output.extend("  ")
            index += 2
            while index < len(source) and not (
                source[index] == "*" and index + 1 < len(source) and source[index + 1] == "/"
            ):
                output.append("\n" if source[index] == "\n" else " ")
                index += 1
            output.extend("  ")
            index += 2
        else:
            output.append(char)
            index += 1
    return "".join(output)


def extract_blocks(path: Path) -> list[Block]:
    source = strip_comments(path.read_text(encoding="utf-8"))
    blocks: list[Block] = []
    for match in RESOURCE_START.finditer(source):
        depth = 1
        in_string = False
        escaped = False
        cursor = match.end()
        while cursor < len(source) and depth:
            char = source[cursor]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            cursor += 1
        if depth == 0:
            blocks.append(
                Block(
                    match.group("type"),
                    match.group("name"),
                    source[match.start() : cursor],
                    path,
                    source.count("\n", 0, match.start()) + 1,
                )
            )
    return blocks


def assignment(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*([^\n]+)", text)
    return match.group(1).strip() if match else None


def literal_bool(text: str, key: str) -> bool | None:
    value = assignment(text, key)
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def scan_block(block: Block, all_blocks: list[Block]) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule_id: str, severity: str, message: str) -> None:
        findings.append(
            Finding(
                rule_id,
                severity,
                message,
                str(block.file),
                block.line,
                f"{block.resource_type}.{block.name}",
            )
        )

    text = block.text
    kind = block.resource_type

    if kind == "aws_security_group":
        ingress_blocks = re.findall(r"\bingress\s*\{(.*?)\}", text, flags=re.DOTALL)
        if any(re.search(r'"(?:0\.0\.0\.0/0|::/0)"', item) for item in ingress_blocks):
            add("CSP-TF-001", "CRITICAL", "Ingress is open to the internet.")
    elif kind == "aws_security_group_rule":
        if re.search(r'\btype\s*=\s*"ingress"', text) and re.search(r'"(?:0\.0\.0\.0/0|::/0)"', text):
            add("CSP-TF-001", "CRITICAL", "Ingress is open to the internet.")
    elif kind == "aws_vpc_security_group_ingress_rule" and re.search(r'"(?:0\.0\.0\.0/0|::/0)"', text):
        add("CSP-TF-001", "CRITICAL", "Ingress is open to the internet.")

    if kind in {"aws_db_instance", "aws_rds_cluster"}:
        if literal_bool(text, "publicly_accessible") is True:
            add("CSP-TF-002", "CRITICAL", "Database is publicly accessible.")
        if literal_bool(text, "storage_encrypted") is not True:
            add("CSP-TF-003", "HIGH", "Database storage encryption is not explicitly enabled.")
        if literal_bool(text, "deletion_protection") is not True:
            add("CSP-TF-004", "MEDIUM", "Database deletion protection is not enabled.")
        password = assignment(text, "password") or assignment(text, "master_password")
        if password and re.match(r'".+"', password):
            add("CSP-TF-005", "CRITICAL", "Database password is hard-coded in Terraform.")

    if kind == "aws_db_instance":
        retention = assignment(text, "backup_retention_period")
        if retention is None or retention == "0":
            add("CSP-TF-006", "MEDIUM", "Automated database backups are not configured.")

    if kind == "aws_ebs_volume" and literal_bool(text, "encrypted") is not True:
        add("CSP-TF-007", "HIGH", "EBS encryption is not explicitly enabled.")

    if kind == "aws_s3_bucket_acl" and re.search(r'\bacl\s*=\s*"public-(?:read|read-write)"', text):
        add("CSP-TF-008", "CRITICAL", "S3 bucket ACL is public.")

    if kind == "aws_s3_bucket_public_access_block":
        required = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
        if any(literal_bool(text, key) is not True for key in required):
            add("CSP-TF-009", "HIGH", "S3 public-access block is incomplete.")

    if kind == "aws_s3_bucket":
        reference = f"aws_s3_bucket.{block.name}"
        encryption_blocks = [
            item
            for item in all_blocks
            if item.resource_type == "aws_s3_bucket_server_side_encryption_configuration"
            and reference in item.text
        ]
        if not encryption_blocks:
            add("CSP-TF-010", "HIGH", "S3 bucket has no server-side encryption configuration.")
        public_access_blocks = [
            item
            for item in all_blocks
            if item.resource_type == "aws_s3_bucket_public_access_block"
            and reference in item.text
        ]
        if not public_access_blocks:
            add("CSP-TF-009", "HIGH", "S3 bucket has no public-access block.")

    if kind == "aws_kms_key" and literal_bool(text, "enable_key_rotation") is not True:
        add("CSP-TF-011", "HIGH", "KMS automatic key rotation is not enabled.")

    if kind == "aws_cloudtrail":
        if literal_bool(text, "is_multi_region_trail") is not True:
            add("CSP-TF-012", "HIGH", "CloudTrail is not explicitly multi-Region.")
        if literal_bool(text, "enable_log_file_validation") is not True:
            add("CSP-TF-013", "HIGH", "CloudTrail log-file validation is not enabled.")
        if assignment(text, "kms_key_id") is None:
            add("CSP-TF-014", "HIGH", "CloudTrail is not configured with a KMS key.")

    if kind in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}:
        if re.search(r'(?i)"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])', text):
            add("CSP-TF-015", "CRITICAL", "IAM policy grants wildcard actions.")
        if re.search(r'(?i)"Resource"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])', text):
            add("CSP-TF-016", "HIGH", "IAM policy grants access to wildcard resources.")

    if kind in {"aws_instance", "aws_launch_template"}:
        if not re.search(r'http_tokens\s*=\s*"required"', text):
            add("CSP-TF-017", "HIGH", "EC2 IMDSv2 is not required.")

    if kind == "aws_eks_cluster":
        if literal_bool(text, "endpoint_public_access") is not False:
            add("CSP-TF-018", "HIGH", "EKS public API endpoint is not explicitly disabled.")
        if literal_bool(text, "endpoint_private_access") is not True:
            add("CSP-TF-019", "HIGH", "EKS private API endpoint is not explicitly enabled.")

    if kind == "aws_backup_vault" and assignment(text, "kms_key_arn") is None:
        add("CSP-TF-020", "HIGH", "Backup vault does not use a customer-managed KMS key.")

    if re.search(
        r'(?i)(password|secret|token|access_key)\s*=\s*"(?!\$\{|<|example|changeme)[^"\n]{8,}"',
        text,
    ):
        add("CSP-TF-021", "CRITICAL", "Possible hard-coded credential in resource configuration.")

    return findings


def terraform_files(paths: Iterable[Path]) -> list[Path]:
    files: set[Path] = set()
    for path in paths:
        if path.is_file() and path.suffix == ".tf":
            files.add(path)
        elif path.is_dir():
            files.update(
                item
                for item in path.rglob("*.tf")
                if ".terraform" not in item.parts
            )
    return sorted(files)


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _plan_resources(module: dict[str, Any]) -> list[dict[str, Any]]:
    resources = [item for item in module.get("resources", []) if isinstance(item, dict)]
    for child in module.get("child_modules", []):
        if isinstance(child, dict):
            resources.extend(_plan_resources(child))
    return resources


def _configuration_references(plan: dict[str, Any]) -> dict[str, set[str]]:
    references: dict[str, set[str]] = {}

    def visit(module: dict[str, Any]) -> None:
        for resource in module.get("resources", []):
            if not isinstance(resource, dict):
                continue
            address = resource.get("address")
            expressions = resource.get("expressions", {})
            if not isinstance(address, str) or not isinstance(expressions, dict):
                continue
            found: set[str] = set()
            for expression in expressions.values():
                if isinstance(expression, dict):
                    found.update(
                        item
                        for item in expression.get("references", [])
                        if isinstance(item, str)
                    )
            references[address] = found
        for child in module.get("module_calls", {}).values():
            if isinstance(child, dict) and isinstance(child.get("module"), dict):
                visit(child["module"])

    root = plan.get("configuration", {}).get("root_module", {})
    if isinstance(root, dict):
        visit(root)
    return references


def _policy_statements(policy: Any) -> list[dict[str, Any]]:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return []
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [item for item in statements if isinstance(item, dict)] if isinstance(statements, list) else []


def scan_plan(path: Path) -> list[Finding]:
    """Inspect an evaluated ``terraform show -json`` document."""
    source = sys.stdin.read() if str(path) == "-" else path.read_text(encoding="utf-8")
    payload = json.loads(source)
    root = payload.get("planned_values", {}).get("root_module", {})
    if not isinstance(root, dict):
        raise ValueError(f"{path} is not a Terraform plan JSON document")
    resources = _plan_resources(root)
    references = _configuration_references(payload)
    findings: list[Finding] = []

    def add(resource: dict[str, Any], rule_id: str, severity: str, message: str) -> None:
        address = str(resource.get("address", resource.get("type", "unknown")))
        findings.append(Finding(rule_id, severity, message, str(path), 1, address))

    iam_types = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}
    for resource in resources:
        if resource.get("type") not in iam_types:
            continue
        values = resource.get("values", {})
        policy = values.get("policy") if isinstance(values, dict) else None
        for statement in _policy_statements(policy):
            if str(statement.get("Effect", "Allow")).lower() != "allow":
                continue
            actions = _string_list(statement.get("Action"))
            resource_arns = _string_list(statement.get("Resource"))
            wildcard_actions = [action for action in actions if "*" in action]
            if wildcard_actions:
                severity = "CRITICAL" if "*" in wildcard_actions else "HIGH"
                add(resource, "CSP-TF-015", severity, "Evaluated IAM policy grants wildcard actions.")
            if "*" in resource_arns and any(
                action not in GLOBAL_RESOURCE_ACTIONS for action in actions
            ):
                add(
                    resource,
                    "CSP-TF-016",
                    "HIGH",
                    "Evaluated IAM policy uses a wildcard resource for an action that supports or requires review of resource scoping.",
                )

    buckets = [item for item in resources if item.get("type") == "aws_s3_bucket"]
    access_blocks = [
        item for item in resources if item.get("type") == "aws_s3_bucket_public_access_block"
    ]
    for bucket in buckets:
        address = str(bucket.get("address", ""))
        bucket_name = (bucket.get("values") or {}).get("bucket")
        matching = []
        for access_block in access_blocks:
            block_address = str(access_block.get("address", ""))
            block_bucket = (access_block.get("values") or {}).get("bucket")
            block_references = references.get(block_address, set())
            if any(item == address or item.startswith(f"{address}.") for item in block_references) or (
                bucket_name is not None and block_bucket == bucket_name
            ):
                matching.append(access_block)
        if not matching:
            add(bucket, "CSP-TF-009", "HIGH", "Evaluated S3 bucket has no public-access block.")
            continue
        required = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
        if not any(
            all((block.get("values") or {}).get(key) is True for key in required)
            for block in matching
        ):
            add(bucket, "CSP-TF-009", "HIGH", "Evaluated S3 public-access block is incomplete.")

    return findings


def scan(paths: Iterable[Path], plan_paths: Iterable[Path] = ()) -> list[Finding]:
    blocks = [block for path in terraform_files(paths) for block in extract_blocks(path)]
    source_findings = [finding for block in blocks for finding in scan_block(block, blocks)]
    plan_findings = [finding for path in plan_paths for finding in scan_plan(path)]
    return source_findings + plan_findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan Terraform for cloud security misconfigurations.")
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default="HIGH")
    parser.add_argument(
        "--plan-json",
        action="append",
        default=[],
        type=Path,
        help="Evaluated plan produced by: terraform show -json PLAN > plan.json (repeatable)",
    )
    args = parser.parse_args(argv)
    if not args.paths and not args.plan_json:
        parser.error("provide at least one Terraform source path or --plan-json")

    try:
        findings = scan(args.paths, args.plan_json)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Terraform scan failed: {error}", file=sys.stderr)
        return 2
    if args.format == "json":
        rendered = json.dumps({"findings": [asdict(item) for item in findings]}, indent=2)
    else:
        rendered = "\n".join(
            f"{item.severity} {item.rule_id} {item.file}:{item.line} {item.resource} - {item.message}"
            for item in findings
        ) or "No Terraform security findings."

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[item.severity] >= threshold for item in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
