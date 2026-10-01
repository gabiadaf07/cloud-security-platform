#!/usr/bin/env python3
"""Validate Kubernetes workload hardening and RBAC boundaries."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    resource: str


def pod_spec(document: dict[str, Any]) -> dict[str, Any] | None:
    kind = document.get("kind")
    spec = document.get("spec", {})
    if kind == "Pod":
        return spec
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        return spec.get("template", {}).get("spec", {})
    if kind == "CronJob":
        return spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
    return None


def scan_document(document: dict[str, Any], path: Path) -> list[Finding]:
    findings: list[Finding] = []
    kind = document.get("kind", "Unknown")
    name = document.get("metadata", {}).get("name", "unnamed")
    resource = f"{kind}/{name}"

    def add(rule_id: str, severity: str, message: str) -> None:
        findings.append(Finding(rule_id, severity, message, str(path), resource))

    spec = pod_spec(document)
    if kind in WORKLOAD_KINDS and spec is not None:
        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(field) is True:
                add("CSP-K8S-001", "CRITICAL", f"{field} exposes the host namespace.")

        pod_security = spec.get("securityContext", {})
        if pod_security.get("runAsNonRoot") is not True:
            add("CSP-K8S-002", "HIGH", "Pod does not require a non-root identity.")
        if pod_security.get("seccompProfile", {}).get("type") not in {"RuntimeDefault", "Localhost"}:
            add("CSP-K8S-003", "HIGH", "Pod does not use an explicit seccomp profile.")
        if spec.get("automountServiceAccountToken") is not False:
            add("CSP-K8S-004", "MEDIUM", "Service-account token automount is not disabled.")

        containers = list(spec.get("initContainers", [])) + list(spec.get("containers", []))
        for container in containers:
            container_name = container.get("name", "unnamed")
            security = container.get("securityContext", {})
            prefix = f"Container {container_name}"
            if security.get("privileged") is True:
                add("CSP-K8S-005", "CRITICAL", f"{prefix} is privileged.")
            if security.get("allowPrivilegeEscalation") is not False:
                add("CSP-K8S-006", "HIGH", f"{prefix} permits privilege escalation.")
            if security.get("readOnlyRootFilesystem") is not True:
                add("CSP-K8S-007", "MEDIUM", f"{prefix} root filesystem is writable.")
            if "ALL" not in security.get("capabilities", {}).get("drop", []):
                add("CSP-K8S-008", "HIGH", f"{prefix} does not drop all Linux capabilities.")
            if str(container.get("image", "")).endswith(":latest") or ":" not in str(container.get("image", "")):
                add("CSP-K8S-009", "HIGH", f"{prefix} uses an unpinned image tag.")
            resources = container.get("resources", {})
            if not resources.get("limits", {}).get("cpu") or not resources.get("limits", {}).get("memory"):
                add("CSP-K8S-010", "MEDIUM", f"{prefix} has incomplete resource limits.")

    if kind in {"Role", "ClusterRole"}:
        for rule in document.get("rules", []):
            if "*" in rule.get("verbs", []) or "*" in rule.get("resources", []):
                add("CSP-K8S-011", "CRITICAL", "RBAC rule contains wildcard verbs or resources.")

    if kind == "ClusterRoleBinding" and any(
        subject.get("name") in {"system:anonymous", "system:unauthenticated"}
        for subject in document.get("subjects", [])
    ):
        add("CSP-K8S-012", "CRITICAL", "Cluster role is bound to an anonymous group or user.")
    if kind == "ClusterRoleBinding" and document.get("roleRef", {}).get("name") == "cluster-admin":
        add("CSP-K8S-013", "CRITICAL", "Binding grants cluster-admin privileges.")

    if kind == "Service" and document.get("spec", {}).get("type") in {"LoadBalancer", "NodePort"}:
        add("CSP-K8S-014", "MEDIUM", "Service exposes a direct external entry point.")

    return findings


def yaml_files(paths: Iterable[Path]) -> list[Path]:
    files: set[Path] = set()
    for path in paths:
        if path.is_file() and path.suffix in {".yaml", ".yml"}:
            files.add(path)
        elif path.is_dir():
            files.update(path.rglob("*.yaml"))
            files.update(path.rglob("*.yml"))
    return sorted(files)


def scan(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in yaml_files(paths):
        try:
            documents = yaml.safe_load_all(path.read_text(encoding="utf-8"))
            findings.extend(
                finding
                for document in documents
                if isinstance(document, dict) and document.get("apiVersion") and document.get("kind")
                for finding in scan_document(document, path)
            )
        except yaml.YAMLError as error:
            findings.append(Finding("CSP-K8S-000", "HIGH", f"Invalid YAML: {error}", str(path), "YAML"))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan Kubernetes YAML for hardening and RBAC issues.")
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
            f"{item.severity} {item.rule_id} {item.file} {item.resource} - {item.message}"
            for item in findings
        ) or "No Kubernetes security findings."
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[item.severity] >= threshold for item in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
