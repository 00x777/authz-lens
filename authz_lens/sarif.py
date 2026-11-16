"""SARIF 2.1.0 output so findings show up in GitHub code scanning."""
from __future__ import annotations

from . import __version__
from .analyzer import Finding

RULES = {
    "object-level-authz": {
        "name": "ObjectLevelAuthorization",
        "short": "Object loaded by client-supplied ID without caller scoping",
        "help": "Scope the query to the caller (e.g. owner_id == current_user.id, or the caller's tenant/group id) "
                "or perform an explicit ownership/policy check before returning or mutating the object.",
        "cwe": "CWE-639",
    },
    "missing-authentication": {
        "name": "MissingAuthentication",
        "short": "Route loads data by ID with no authentication dependency",
        "help": "Add an authentication dependency (Depends(get_current_user)) to the route or its router.",
        "cwe": "CWE-306",
    },
}
LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def to_sarif(findings: list[Finding]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "authz-lens",
                "version": __version__,
                "informationUri": "https://github.com/00x777/authz-lens",
                "rules": [{
                    "id": rid,
                    "name": r["name"],
                    "shortDescription": {"text": r["short"]},
                    "help": {"text": r["help"]},
                    "properties": {"tags": ["security", r["cwe"]]},
                } for rid, r in RULES.items()],
            }},
            "results": [{
                "ruleId": f.rule_id,
                "level": LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line},
                }}],
                "properties": {"cwe": f.cwe, "route": f"{f.method} {f.route}", "function": f.function},
            } for f in findings],
        }],
    }
