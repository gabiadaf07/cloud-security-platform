#!/usr/bin/env python3
"""Dependency-free Terraform security scanner for the platform's core controls.

The parser intentionally handles literal Terraform resource blocks. Findings
that require evaluated modules or variable values should also be covered by a
plan-aware scanner such as Trivy in CI.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


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


def scan(paths: Iterable[Path]) -> list[Finding]:
    blocks = [block for path in terraform_files(paths) for block in extract_blocks(path)]
    return [finding for block in blocks for finding in scan_block(block, blocks)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan Terraform for cloud security misconfigurations.")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default="HIGH")
    args = parser.parse_args(argv)

    findings = scan(args.paths)
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
