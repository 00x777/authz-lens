from pathlib import Path

from authz_lens.analyzer import analyze_path
from authz_lens.sarif import to_sarif

FIX = Path(__file__).parent / "fixtures"


def test_flags_every_vulnerable_handler():
    found = analyze_path(FIX / "vuln_app.py")
    by_fn = {f.function: f for f in found}
    assert set(by_fn) == {"read_note", "delete_invoice", "rename_category", "read_note_unauthenticated"}
    assert by_fn["read_note"].cwe == "CWE-639"
    assert by_fn["delete_invoice"].severity == "high"  # write method
    assert by_fn["rename_category"].cwe == "CWE-639"  # client-supplied tenant id is not a scope
    assert by_fn["read_note_unauthenticated"].cwe == "CWE-306"


def test_quiet_on_correctly_scoped_handlers():
    assert analyze_path(FIX / "safe_app.py") == []


def test_sarif_shape():
    sarif = to_sarif(analyze_path(FIX / "vuln_app.py"))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert len(run["results"]) == 4
    assert {r["ruleId"] for r in run["results"]} == {"object-level-authz", "missing-authentication"}
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] > 0 for r in run["results"])


def test_llm_triage_parses_verdict(monkeypatch):
    from authz_lens import llm

    finding = analyze_path(FIX / "vuln_app.py")[0]
    monkeypatch.setattr(llm, "_complete", lambda prompt, model: '{"verdict": "true_positive", '
                        '"confidence": 0.9, "reason": "no owner filter", "fix": "filter by owner_id"}')
    out = llm.triage([finding], model="test")
    assert out[0]["verdict"] == "true_positive"
    assert out[0]["finding"]["function"] == finding.function


def test_router_level_auth_is_inherited_across_modules():
    found = {f.function: f for f in analyze_path(FIX / "project")}
    # notes.router is mounted under an authenticated parent router -> authz problem, not authn
    assert found["get_note"].cwe == "CWE-639"
    # admin router is mounted with an admin dependency -> intended to access any object
    assert "admin_delete" not in found
    # public router has no auth at all
    assert found["shared"].cwe == "CWE-306"
