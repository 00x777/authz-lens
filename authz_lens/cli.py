"""Command line entry point: ``authz-lens PATH [--sarif out.sarif] [--llm] [--fail-on high]``."""
from __future__ import annotations

import argparse
import json
import sys

from .analyzer import DEFAULT_SCOPE_FIELDS, analyze_path
from .sarif import to_sarif

ORDER = {"low": 0, "medium": 1, "high": 2}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="authz-lens", description="Find missing object-level authorization in FastAPI apps.")
    p.add_argument("path", help="file or directory to scan")
    p.add_argument("--sarif", help="write SARIF 2.1.0 to this file")
    p.add_argument("--json", action="store_true", help="print findings as JSON")
    p.add_argument("--scope-field", action="append", default=[],
                   help="extra column name that ties a row to its owner/tenant (repeatable)")
    p.add_argument("--llm", action="store_true", help="triage each finding with an LLM (needs ANTHROPIC_API_KEY)")
    p.add_argument("--model", default="claude-sonnet-5-5")
    p.add_argument("--fail-on", choices=list(ORDER), help="exit 1 if any finding is at or above this severity")
    a = p.parse_args(argv)

    findings = analyze_path(a.path, DEFAULT_SCOPE_FIELDS | set(a.scope_field))

    triaged = None
    if a.llm and findings:
        from .llm import triage
        triaged = triage(findings, a.model)
        keep = {(t["finding"]["file"], t["finding"]["line"]) for t in triaged if t["verdict"] != "false_positive"}
        findings = [f for f in findings if (f.file, f.line) in keep]

    if a.sarif:
        with open(a.sarif, "w") as fh:
            json.dump(to_sarif(findings), fh, indent=2)

    if a.json:
        print(json.dumps(triaged if triaged is not None else [f.to_dict() for f in findings], indent=2))
    else:
        for f in findings:
            print(f"{f.file}:{f.line}: [{f.severity.upper()}] {f.cwe} {f.rule_id}\n    {f.message}\n    > {f.evidence}")
        print(f"\n{len(findings)} finding(s)")

    if a.fail_on and any(ORDER[f.severity] >= ORDER[a.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
