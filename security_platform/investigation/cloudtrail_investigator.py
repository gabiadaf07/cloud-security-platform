#!/usr/bin/env python3
"""Rule-based CloudTrail triage for credential and control-plane abuse."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Alert:
    rule_id: str
    category: str
    severity: str
    event_name: str
    event_time: str
    principal: str
    source_ip: str
    message: str
    source_file: str
    classification: str = "triage-signal"


PRIVILEGE_EVENTS = {
    "AttachGroupPolicy",
    "AttachRolePolicy",
    "AttachUserPolicy",
    "CreatePolicyVersion",
    "PutGroupPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
}
CREDENTIAL_EVENTS = {"CreateAccessKey", "CreateLoginProfile", "UpdateAccessKey", "UpdateLoginProfile"}
EXFILTRATION_EVENTS = {
    "GetObject",
    "ModifySnapshotAttribute",
    "PutBucketAcl",
    "PutBucketPolicy",
    "ShareSnapshot",
}
DESTRUCTION_EVENTS = {
    "DeleteEventDataStore",
    "DeleteLogGroup",
    "DeleteRecoveryPoint",
    "DeleteTrail",
    "DisableKey",
    "PutEventSelectors",
    "ScheduleKeyDeletion",
    "StopLogging",
    "UpdateTrail",
}
ROLE_BEARING_EVENTS = {
    "CreateCluster",
    "CreateFunction",
    "CreateJobDefinition",
    "CreateNotebookInstance",
    "CreateService",
    "CreateStateMachine",
    "RegisterTaskDefinition",
    "UpdateFunctionConfiguration",
    "UpdateService",
    "UpdateStateMachine",
}
ROLE_PARAMETER_NAMES = {
    "executionrolearn",
    "jobrolearn",
    "role",
    "rolearn",
    "servicerolearn",
    "taskrolearn",
}


def object_field(event: dict[str, Any], key: str) -> dict[str, Any]:
    """Return a CloudTrail object field even when AWS serializes it as null."""
    value = event.get(key)
    return value if isinstance(value, dict) else {}


def principal(event: dict[str, Any]) -> str:
    identity = object_field(event, "userIdentity")
    session_context = identity.get("sessionContext")
    session_context = session_context if isinstance(session_context, dict) else {}
    session_issuer = session_context.get("sessionIssuer")
    session_issuer = session_issuer if isinstance(session_issuer, dict) else {}
    return (
        identity.get("arn")
        or identity.get("principalId")
        or session_issuer.get("arn")
        or "unknown"
    )


def mfa_authenticated(event: dict[str, Any]) -> bool:
    identity = object_field(event, "userIdentity")
    session_context = identity.get("sessionContext")
    session_context = session_context if isinstance(session_context, dict) else {}
    attributes = session_context.get("attributes")
    attributes = attributes if isinstance(attributes, dict) else {}
    value = attributes.get("mfaAuthenticated")
    return str(value).lower() == "true"


def contains_role_reference(value: Any) -> bool:
    """Detect a role-bearing request parameter on an API call that can pass a role."""
    if isinstance(value, dict):
        return any(
            (str(key).lower() in ROLE_PARAMETER_NAMES and isinstance(item, str) and bool(item))
            or contains_role_reference(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(contains_role_reference(item) for item in value)
    return False


def alert(event: dict[str, Any], path: Path, rule_id: str, category: str, severity: str, message: str) -> Alert:
    return Alert(
        rule_id,
        category,
        severity,
        str(event.get("eventName", "unknown")),
        str(event.get("eventTime", "unknown")),
        principal(event),
        str(event.get("sourceIPAddress", "unknown")),
        message,
        str(path),
    )


def investigate_event(event: dict[str, Any], path: Path) -> list[Alert]:
    alerts: list[Alert] = []
    name = str(event.get("eventName", ""))
    identity_type = object_field(event, "userIdentity").get("type")
    response_elements = object_field(event, "responseElements")
    request_parameters = object_field(event, "requestParameters")

    if name == "ConsoleLogin" and (
        response_elements.get("ConsoleLogin") == "Failure" or event.get("errorCode")
    ):
        alerts.append(alert(event, path, "CSP-CT-001", "credential-abuse", "HIGH", "Failed console authentication."))

    if name in CREDENTIAL_EVENTS:
        alerts.append(
            alert(event, path, "CSP-CT-002", "credential-abuse", "HIGH", "Long-lived credential material was created or changed.")
        )

    if name == "AssumeRole" and identity_type in {"IAMUser", "Root"} and not mfa_authenticated(event):
        alerts.append(alert(event, path, "CSP-CT-003", "credential-abuse", "HIGH", "Role assumed without MFA."))

    if name in PRIVILEGE_EVENTS:
        alerts.append(
            alert(
                event,
                path,
                "CSP-CT-004",
                "privilege-escalation",
                "HIGH",
                "IAM permission or trust-policy change observed; validate the diff and authorization context.",
            )
        )

    # iam:PassRole is a permission check, not a standalone API event. Detect
    # service operations that carry a role instead.
    if name in ROLE_BEARING_EVENTS and contains_role_reference(request_parameters):
        alerts.append(
            alert(
                event,
                path,
                "CSP-CT-005",
                "privilege-escalation",
                "HIGH",
                "Service operation supplied an IAM role; review iam:PassRole authorization and the target service.",
            )
        )

    if name in EXFILTRATION_EVENTS:
        severity = "LOW" if name == "GetObject" else "HIGH"
        alerts.append(
            alert(
                event,
                path,
                "CSP-CT-006",
                "exfiltration",
                severity,
                "Data-read or resource-sharing activity is a triage signal; correlate it with volume, identity, network and baseline context.",
            )
        )

    if name in DESTRUCTION_EVENTS:
        alerts.append(
            alert(
                event,
                path,
                "CSP-CT-007",
                "evidence-destruction",
                "HIGH",
                "Logging, encryption or recovery configuration changed; validate authorization and resulting control state.",
            )
        )

    if identity_type == "Root":
        alerts.append(alert(event, path, "CSP-CT-008", "credential-abuse", "CRITICAL", "Root identity use observed; validate whether this exceptional operation was authorized."))

    return alerts


def load_events(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        records = payload.get("Records", [payload])
    elif isinstance(payload, list):
        records = payload
    else:
        raise ValueError("CloudTrail input must be an object, a Records object, or a list")
    return [item for item in records if isinstance(item, dict)]


def investigate(paths: Iterable[Path]) -> list[Alert]:
    alerts: list[Alert] = []
    for path in paths:
        files = sorted(path.rglob("*.json")) if path.is_dir() else [path]
        for file in files:
            for event in load_events(file):
                alerts.extend(investigate_event(event, file))
    return alerts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triage CloudTrail events for four abuse categories.")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER))
    args = parser.parse_args(argv)
    try:
        alerts = investigate(args.paths)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"CloudTrail investigation failed: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = json.dumps({"alerts": [asdict(item) for item in alerts]}, indent=2)
    else:
        rendered = "\n".join(
            f"{item.severity} {item.rule_id} {item.event_time} {item.category} {item.classification} {item.principal} - {item.message}"
            for item in alerts
        ) or "No suspicious CloudTrail events detected."
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        return 1 if any(SEVERITY_ORDER[item.severity] >= threshold for item in alerts) else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
