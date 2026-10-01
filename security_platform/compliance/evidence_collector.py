#!/usr/bin/env python3
"""Build a hashed evidence manifest from the control catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect(catalog_path: Path, repository_root: Path) -> dict[str, Any]:
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    controls: list[dict[str, Any]] = []
    for control in catalog.get("controls", []):
        artifacts = []
        for relative in control.get("implementation", []):
            artifact = repository_root / relative
            artifacts.append(
                {
                    "path": relative,
                    "present": artifact.is_file(),
                    "sha256": sha256(artifact) if artifact.is_file() else None,
                }
            )
        controls.append(
            {
                "id": control["id"],
                "title": control["title"],
                "frameworks": control.get("frameworks", {}),
                "status": "implemented" if artifacts and all(item["present"] for item in artifacts) else "incomplete",
                "artifacts": artifacts,
                "runtime_evidence": control.get("runtime_evidence", []),
            }
        )
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "catalog": str(catalog_path),
        "controls": controls,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a deterministic compliance evidence manifest.")
    parser.add_argument("--catalog", type=Path, default=Path("controls/control-catalog.json"))
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("reports/evidence-manifest.json"))
    args = parser.parse_args(argv)
    try:
        manifest = collect(args.catalog, args.repository_root)
    except (OSError, KeyError, json.JSONDecodeError) as error:
        print(f"Evidence collection failed: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    incomplete = [item["id"] for item in manifest["controls"] if item["status"] != "implemented"]
    print(f"Wrote {len(manifest['controls'])} controls to {args.output}")
    if incomplete:
        print(f"Incomplete controls: {', '.join(incomplete)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
