# authz-lens

**Find missing object-level authorization (IDOR / BOLA) in FastAPI + SQLAlchemy apps, then let an LLM triage the candidates.**

Broken object-level authorization is the most common serious bug I find in real web apps. For example, in
[GHSA-r278-7hwx-c6cr](https://github.com/mealie-recipes/mealie/security/advisories/GHSA-r278-7hwx-c6cr) one Mealie
group could take over another group's categories and tags. Linters and generic SAST rarely catch it, because the code
is not "wrong" in a syntactic sense. The query is valid; it just forgets *whose* row it is.

`authz-lens` is a guardrail for that one bug class:

1. **Static pass (deterministic, zero dependencies).** It walks every FastAPI route, finds database loads keyed by a
   client-supplied identifier (`session.get(Model, id)`, `.filter(Model.id == id)`, `select(...).where(...)`), and
   asks whether anything ties the object back to the **caller**: an owner or tenant predicate whose value comes from the
   authenticated user, an ownership comparison, a policy call, or a caller-aware query builder.
2. **LLM triage (optional, `--llm`).** Each candidate's handler is sent, alone, with one narrow question and a strict
   JSON answer format (`true_positive` / `false_positive` / `needs_context`, plus a minimal fix). The model removes
   noise; it does not invent findings.
3. **Developer workflow.** Plain-text, JSON or **SARIF** output, so findings show up inline on pull requests through
   GitHub code scanning. `--fail-on high` turns it into a CI gate.

```text
$ authz-lens tests/fixtures/vuln_app.py
tests/fixtures/vuln_app.py:24: [HIGH] CWE-639 object-level-authz
    DELETE /invoices/{invoice_id} loads Invoice by path parameter 'invoice_id' but never scopes it to the
    caller (no owner/tenant filter or ownership check). Possible IDOR/BOLA.
    > inv = db.query(Invoice).filter(Invoice.id == invoice_id).first()
tests/fixtures/vuln_app.py:33: [HIGH] CWE-639 object-level-authz
    PUT /categories/{slug} loads Category by path parameter 'group_id, slug' but never scopes it to the caller ...
    > stmt = select(Category).where(Category.slug == slug, Category.group_id == group_id)
...
4 finding(s)
```

The second finding shows the subtle case: there *is* a tenant filter (`group_id`), but its value comes from the
request rather than from the authenticated user. That is a cross-tenant write: the same class of bug as the Mealie
advisory, where client-supplied `id` and `group_id` values were trusted when resolving categories and tags.

## What it understands

| Pattern | Treated as |
|---|---|
| `Depends(get_current_user)`, `Annotated[User, Depends(...)]` aliases defined in another module, `current_user` / `auth_subject` style parameters | caller identity |
| `APIRouter(dependencies=[...])`, `parent.include_router(child, dependencies=[...])` across files and nested include chains, custom router classes like `UserAPIRouter` | inherited authentication |
| `Model.owner_id == user.id`, `filter_by(group_id=user.group_id)`, `if obj.account_id != user.account_id: raise` | scoped |
| `repo.get_readable_statement(auth_subject).where(...)`, `authorize(user, "read", obj)` | scoped (delegated) |
| `if obj == current_user`, `if not current_user.is_superuser: raise` | scoped |
| Admin- or superuser-only routers and dependencies | intentionally unscoped, skipped |
| Owner or tenant predicate whose value comes from the request | **not** scoped (cross-tenant) |

Tenancy columns default to common names (`owner_id`, `user_id`, `tenant_id`, `org_id`, `group_id`, `household_id`,
`practice_id`, `patient_id`, ...). Add your own with `--scope-field`.

## Signal vs. noise

The static pass was tuned against real, well-maintained FastAPI codebases until it stayed quiet on correct code:

| Codebase (commit) | Route handlers parsed | Findings |
|---|---|---|
| [fastapi/full-stack-fastapi-template](https://github.com/fastapi/full-stack-fastapi-template) `backend/app` (77e550a) | 23 | 0 |
| [mealie-recipes/mealie](https://github.com/mealie-recipes/mealie) `mealie/` (3d639dd) | 291 | 0 |
| [polarsource/polar](https://github.com/polarsource/polar) `server/polar` (18a7268) | 542 | 0 |
| full-stack template with the ownership check in `read_item` removed | 23 | **1, the removed check** |

Zero findings on mature code is the point, with one caveat: much of Mealie's data access goes through repository classes the static pass cannot follow yet (see Limits). Still, a guardrail that cries wolf gets turned off. The LLM step exists for the
grey zone, not to clean up a noisy rule.

## Usage

```bash
pip install git+https://github.com/00x777/authz-lens
authz-lens path/to/app                       # human-readable
authz-lens path/to/app --sarif out.sarif     # GitHub code scanning
authz-lens path/to/app --json                # machine-readable
authz-lens path/to/app --fail-on high        # CI gate
ANTHROPIC_API_KEY=... authz-lens path/to/app --llm   # LLM triage of each candidate
```

A ready-to-use workflow that comments on pull requests is in [`examples/github-action.yml`](examples/github-action.yml).

## Limits (honest)

- Python AST only. Class-based controllers that hide the session behind repository mixins (Mealie's own controllers,
  for example) are out of reach of the static pass. That is where an agentic reviewer that can read the repository
  layer helps, and it is the next step on the roadmap.
- Authentication applied by middleware, rather than by dependencies, is invisible. Such routes may be reported as
  `CWE-306` candidates; use the LLM step or a baseline file.
- It answers "is this object scoped to the caller?", not "is this field allowed to change?". Mass-assignment checks
  are on the roadmap.

## Roadmap

- [ ] Repository-layer awareness (follow `self.repo.get(id)` into the data-access class)
- [ ] Agentic mode: the model can ask for the definition of a dependency or repository method before answering
- [ ] Equivalent Semgrep rule pack for teams that already run Semgrep in CI
- [ ] Baseline / suppression file

## Development

```bash
pip install -e ".[dev]" && pytest -q
```

Built by [Jaeha (James) Yoo](https://github.com/00x777). I use the same approach in my vulnerability research
(8 reported vulnerabilities across 4 open-source projects so far, 3 published as advisories).
