"""Static detection of missing object-level authorization in FastAPI + SQLAlchemy code.

The analyzer looks for route handlers that load a database object using an
identifier supplied by the client (path, query or body parameter) and then
never tie that object back to the caller (user, tenant, group, organization).
That pattern is the root cause of most IDOR / BOLA bugs (CWE-639, CWE-862).

It is intentionally heuristic: it produces *candidates*, which can then be
triaged by a human or by the optional LLM step in ``authz_lens.llm``.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "api_route"}
WRITE_METHODS = {"post", "put", "patch", "delete"}

# Attribute / keyword names that usually express "this row belongs to someone".
DEFAULT_SCOPE_FIELDS = {
    "owner_id", "user_id", "created_by", "created_by_id", "author_id",
    "tenant_id", "org_id", "organization_id", "account_id", "workspace_id",
    "team_id", "group_id", "project_id", "household_id", "practice_id",
    "provider_id", "patient_id", "customer_id", "company_id",
    # relationship attributes compared against the caller object
    "owner", "user", "tenant", "organization", "group", "account", "workspace",
}

# Names of dependencies that identify the caller.
AUTH_DEP_HINTS = re.compile(
    r"(current_?user|current_active|get_user|authenticated|auth|require_|verify_|principal|session_user|get_actor|"
    r"superuser|admin|(user|private|protected|secure)\w*router)",
    re.I,
)

# Function names that perform an explicit authorization check.
AUTHZ_CALL_HINTS = re.compile(
    r"(authorize|check_access|check_perm|has_perm|ensure_|assert_owner|can_access|"
    r"require_owner|verify_owner|permission|policy|enforce|is_member|is_owner)",
    re.I,
)

# Parameter names that almost always hold the authenticated caller.
CALLER_PARAM = re.compile(
    r"^(current_\w+|auth_\w+|authenticated_\w+|user|me|principal|actor|viewer|identity|requester)$"
    r"|(_user|_subject|_principal|_actor|_identity)$", re.I)

ROLE_ATTRS = {"is_superuser", "is_admin", "is_staff", "role", "roles", "permissions", "scopes", "can_manage"}

# Dependencies that restrict a route to privileged staff; object scoping is not expected there.
PRIVILEGED_DEP = re.compile(r"(superuser|admin|staff|is_root)", re.I)

PATH_PARAM = re.compile(r"{(\w+)(?::[^}]*)?}")


@dataclass
class Finding:
    rule_id: str
    cwe: str
    severity: str
    file: str
    line: int
    function: str
    route: str
    method: str
    message: str
    evidence: str
    source: str = field(repr=False, default="")

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("source", None)
        return d


@dataclass
class _Route:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    method: str
    path: str
    dependencies: list[str]  # router-level + decorator-level dependency names


def _call_name(node: ast.AST) -> str:
    """Return dotted name for a call target, e.g. ``db.query`` or ``Depends``."""
    if isinstance(node, ast.Call):
        node = node.func
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _attrs_in(node: ast.AST) -> set[str]:
    out = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
    out |= {k.arg for n in ast.walk(node) if isinstance(n, ast.Call) for k in n.keywords if k.arg}
    return out


def _depends_target(default: ast.AST | None) -> str | None:
    """If ``default`` is ``Depends(x)`` / ``Security(x)`` return the name of x."""
    if isinstance(default, ast.Call) and _call_name(default).split(".")[-1] in {"Depends", "Security"}:
        if default.args:
            return _call_name(default.args[0]) or ast.unparse(default.args[0])
        return "<annotated>"
    return None


class _ModuleAnalyzer:
    def __init__(self, path: Path, source: str, scope_fields: set[str], aliases: dict[str, str] | None = None,
                 inherited: dict[str, list[str]] | None = None):
        self.path = path
        self.source = source
        self.lines = source.splitlines()
        self.tree = ast.parse(source, filename=str(path))
        self.scope_fields = scope_fields
        self.router_deps = self._router_dependencies()
        for name, deps in (inherited or {}).items():  # deps added where this router is included elsewhere
            self.router_deps.setdefault(name, [])
            self.router_deps[name] = self.router_deps[name] + deps
        # Annotated aliases: CurrentUser = Annotated[User, Depends(get_current_user)]
        self.dep_aliases = dict(aliases or {})
        for node in self.tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                m = re.search(r"Depends\(([\w.]+)", ast.unparse(node.value))
                if m and "Annotated" in ast.unparse(node.value):
                    self.dep_aliases[node.targets[0].id] = m.group(1)

    # ----- route discovery -------------------------------------------------
    def _router_dependencies(self) -> dict[str, list[str]]:
        """Map router variable name -> dependency names declared at APIRouter/FastAPI level."""
        deps: dict[str, list[str]] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                ctor = _call_name(node.value).split(".")[-1]
                if ctor not in {"APIRouter", "FastAPI"} and not ctor.endswith("Router"):
                    continue
                names: list[str] = [] if ctor in {"APIRouter", "FastAPI"} else [ctor]
                for kw in node.value.keywords:
                    if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        for elt in kw.value.elts:
                            t = _depends_target(elt)
                            if t:
                                names.append(t)
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        deps[tgt.id] = names
        return deps

    def routes(self) -> Iterable[_Route]:
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                    continue
                method = dec.func.attr.lower()
                if method not in HTTP_METHODS:
                    continue
                router = _call_name(dec.func.value)
                path = ""
                if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                    path = dec.args[0].value
                deps = list(self.router_deps.get(router, []))
                for kw in dec.keywords:
                    if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        deps += [t for t in (_depends_target(e) for e in kw.value.elts) if t]
                    if kw.arg == "path" and isinstance(kw.value, ast.Constant):
                        path = kw.value.value
                    if method == "api_route" and kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        ms = [e.value.lower() for e in kw.value.elts if isinstance(e, ast.Constant)]
                        method = ms[0] if ms else "get"
                yield _Route(node, method, path, deps)

    # ----- per-handler analysis --------------------------------------------
    def _handler_params(self, fn) -> tuple[set[str], list[str], set[str]]:
        """Return (client_controlled_params, auth_dependency_names, caller_params)."""
        args = fn.args
        all_args = args.posonlyargs + args.args + args.kwonlyargs
        defaults = [None] * (len(args.posonlyargs + args.args) - len(args.defaults)) + list(args.defaults)
        defaults += list(args.kw_defaults)
        client, auth_deps, caller = set(), [], set()
        for arg, default in zip(all_args, defaults):
            dep = _depends_target(default)
            ann = ast.unparse(arg.annotation) if arg.annotation is not None else ""
            if dep is None and ann in self.dep_aliases:
                dep = self.dep_aliases[ann]
            if dep is None and "Depends(" in ann:  # Annotated[User, Depends(get_user)]
                m = re.search(r"Depends\(([\w.]+)", ann)
                dep = m.group(1) if m else "<annotated>"
            if dep is None and CALLER_PARAM.search(arg.arg):
                dep = arg.arg  # e.g. current_user: CurrentUser where the alias lives in another package
            if dep is not None:
                if AUTH_DEP_HINTS.search(dep) or AUTH_DEP_HINTS.search(arg.arg):
                    auth_deps.append(dep)
                    caller.add(arg.arg)
                continue
            if arg.arg in {"self", "request", "response", "background_tasks"}:
                continue
            client.add(arg.arg)
        return client, auth_deps, caller

    def _loads(self, fn, client: set[str]):
        """Yield (call_node, model_name, id_names) for DB loads keyed by client input."""
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            last = name.split(".")[-1]
            # session.get(Model, item_id) / await session.get(Model, item_id)
            if last == "get" and len(node.args) >= 2 and isinstance(node.args[0], ast.Name) and node.args[0].id[:1].isupper():
                ids = _names_in(node.args[1]) & client
                if ids:
                    yield node, node.args[0].id, ids
            # .filter(Model.id == x) / .where(Model.id == x) / .filter_by(id=x)
            elif last in {"filter", "where", "filter_by"}:
                ids: set[str] = set()
                model = ""
                for a in node.args:
                    if isinstance(a, ast.Compare):
                        ids |= _names_in(a) & client
                        lhs = a.left
                        if isinstance(lhs, ast.Attribute) and isinstance(lhs.value, ast.Name):
                            model = lhs.value.id
                for k in node.keywords:
                    ids |= _names_in(k.value) & client
                if ids:
                    yield node, model or _guess_model(node), ids

    def _is_scoped(self, fn, load: ast.Call, caller: set[str]) -> bool:
        """True if the load or the handler body ties the object to the caller."""
        # 1. Find the full query chain that contains this call (walk up parents).
        # A scope predicate only counts if its value comes from the caller, not from
        # client input: filter(Item.owner_id == owner_id_from_query) is still an IDOR.
        chain = _enclosing_statement(fn, load)
        for node in ast.walk(chain):
            # repository.get_readable_statement(auth_subject).where(...)
            if isinstance(node, ast.Call) and node is not load and any(
                    _names_in(a) & caller for a in list(node.args) + [k.value for k in node.keywords]):
                return True
            if isinstance(node, ast.Compare) and _attrs_in(node) & self.scope_fields and _names_in(node) & caller:
                return True
            if isinstance(node, ast.Call):
                for k in node.keywords:
                    if k.arg in self.scope_fields and _names_in(k.value) & caller:
                        return True
        # 2. Identity comparison between the loaded object and the caller: `if obj == current_user`
        loaded = {t.id for t in getattr(chain, "targets", []) if isinstance(t, ast.Name)}
        if isinstance(chain, (ast.AnnAssign, ast.AugAssign)) and isinstance(chain.target, ast.Name):
            loaded.add(chain.target.id)
        for node in ast.walk(fn):
            if isinstance(node, ast.Compare) and loaded and (_names_in(node) & loaded) and (_names_in(node) & caller):
                return True
            # role gate that raises: `if not current_user.is_superuser: raise HTTPException(403)`
            if isinstance(node, ast.If) and (_names_in(node.test) & caller) and \
                    _attrs_in(node.test) & ROLE_ATTRS and any(isinstance(b, ast.Raise) for b in node.body):
                return True
        # 3. Explicit authorization call or ownership comparison anywhere in the handler.
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and AUTHZ_CALL_HINTS.search(_call_name(node).split(".")[-1] or ""):
                return True
            if isinstance(node, ast.Compare):
                attrs = _attrs_in(node)
                if attrs & self.scope_fields and (_names_in(node) & caller):
                    return True
        return False

    def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        for route in self.routes():
            fn = route.node
            client, auth_deps, caller = self._handler_params(fn)
            auth_deps = auth_deps + [d for d in route.dependencies if AUTH_DEP_HINTS.search(d)]
            if any(PRIVILEGED_DEP.search(d) for d in auth_deps):
                continue  # admin-only route: reading any object is the intended behavior
            path_params = set(PATH_PARAM.findall(route.path))
            handler_src = ast.get_source_segment(self.source, fn) or ""
            for call, model, ids in self._loads(fn, client):
                if self._is_scoped(fn, call, caller):
                    continue
                id_list = ", ".join(sorted(ids))
                where = "path" if ids & path_params else "request"
                if not auth_deps:
                    rule, cwe, sev = "missing-authentication", "CWE-306", "high" if route.method in WRITE_METHODS else "medium"
                    msg = (f"{route.method.upper()} {route.path or fn.name} loads {model or 'an object'} by {where} "
                           f"parameter '{id_list}' with no authentication dependency.")
                else:
                    rule, cwe, sev = "object-level-authz", "CWE-639", "high" if route.method in WRITE_METHODS else "medium"
                    msg = (f"{route.method.upper()} {route.path or fn.name} loads {model or 'an object'} by {where} "
                           f"parameter '{id_list}' but never scopes it to the caller "
                           "(no owner/tenant filter or ownership check). "
                           f"Possible IDOR/BOLA.")
                findings.append(Finding(
                    rule_id=rule, cwe=cwe, severity=sev, file=str(self.path), line=call.lineno,
                    function=fn.name, route=route.path, method=route.method.upper(), message=msg,
                    evidence=self.lines[call.lineno - 1].strip(), source=handler_src,
                ))
        return findings


def _guess_model(node: ast.Call) -> str:
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and _call_name(n).split(".")[-1] in {"query", "select"} and n.args:
            if isinstance(n.args[0], ast.Name):
                return n.args[0].id
    return ""


def _enclosing_statement(fn: ast.AST, target: ast.AST) -> ast.AST:
    """Return the smallest statement inside ``fn`` that contains ``target``."""
    best = target
    for stmt in ast.walk(fn):
        if isinstance(stmt, ast.stmt) and stmt is not fn:
            if any(n is target for n in ast.walk(stmt)):
                if best is target or _size(stmt) < _size(best):
                    best = stmt
    return best


def _size(node: ast.AST) -> int:
    return sum(1 for _ in ast.walk(node))


def analyze_path(path: str | Path, scope_fields: Iterable[str] | None = None) -> list[Finding]:
    fields = set(scope_fields or DEFAULT_SCOPE_FIELDS)
    root = Path(path)
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*.py")
                                                 if not any(part in {".venv", "venv", "node_modules", "site-packages"} for part in p.parts))
    sources: dict[Path, str] = {}
    aliases: dict[str, str] = {}
    for f in files:
        try:
            sources[f] = f.read_text(encoding="utf-8")
            aliases.update(collect_dependency_aliases(ast.parse(sources[f])))
        except (SyntaxError, UnicodeDecodeError):
            sources.pop(f, None)
    inherited = _inherited_router_deps(sources)
    out: list[Finding] = []
    for f, src in sources.items():
        out += _ModuleAnalyzer(f, src, fields, aliases, inherited.get(f)).analyze()
    return out


def _resolve_module(base: Path, module: str | None, level: int, name: str | None = None) -> Path | None:
    """Resolve ``from <level dots><module> import <name>`` to a file path (relative imports only,
    plus absolute imports that resolve under a parent directory of ``base``)."""
    parts = (module or "").split(".") if module else []
    if level:
        root = base.parent
        for _ in range(level - 1):
            root = root.parent
        cands = [root]
    else:
        cands = list(base.parents)
    for root in cands:
        target = root.joinpath(*parts) if parts else root
        for c in ([target / f"{name}.py", target / name / "__init__.py"] if name else []) + \
                 [target.with_suffix(".py"), target / "__init__.py"]:
            if c.is_file():
                return c
    return None


def _inherited_router_deps(sources: dict[Path, str]) -> dict[Path, dict[str, list[str]]]:
    """Propagate dependencies declared where a router is *included* back to the module that defines it.

    Handles ``parent.include_router(child_mod.router, dependencies=[...])`` and
    ``from .x.endpoints import router as x_router; protected.include_router(x_router)``.
    """
    edges: list[tuple[Path, str, Path, str, list[str]]] = []  # (parent_file, parent_router, child_file, child_sym, deps)
    for f, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        local: dict[str, tuple[Path, str | None]] = {}  # name -> (file, symbol or None for module)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    mod_file = _resolve_module(f, node.module, node.level, a.name)
                    if mod_file is None:
                        continue
                    as_module = mod_file.stem == a.name or mod_file.parent.name == a.name
                    local[a.asname or a.name] = (mod_file, None if as_module else a.name)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "include_router" and node.args):
                continue
            parent = _call_name(node.func.value)
            deps = [t for kw in node.keywords if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple))
                    for t in (_depends_target(e) for e in kw.value.elts) if t]
            arg = node.args[0]
            if isinstance(arg, ast.Name) and arg.id in local:
                child_file, sym = local[arg.id]
                edges.append((f, parent, child_file, sym or "router", deps))
            elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id in local:
                child_file, _ = local[arg.value.id]
                edges.append((f, parent, child_file, arg.attr, deps))

    own = {}
    for f, src in sources.items():
        try:
            own[f] = _ModuleAnalyzer(f, src, set())._router_dependencies()
        except SyntaxError:
            own[f] = {}
    result: dict[Path, dict[str, list[str]]] = {}
    changed = True
    while changed:  # fixpoint over nested include chains
        changed = False
        for pf, pr, cf, cs, deps in edges:
            parent_deps = own.get(pf, {}).get(pr, []) + result.get(pf, {}).get(pr, []) + deps
            cur = result.setdefault(cf, {}).setdefault(cs, [])
            new = [d for d in parent_deps if d not in cur]
            if new:
                cur += new
                changed = True
    return result


def collect_dependency_aliases(tree: ast.Module) -> dict[str, str]:
    """``CurrentUser = Annotated[User, Depends(get_current_user)]`` -> {"CurrentUser": "get_current_user"}"""
    out = {}
    for node in tree.body:
        target, value = None, None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            target, value = node.target.id, node.value
        if target and value is not None:
            text = ast.unparse(value)
            m = re.search(r"(?:Depends|Security)\(([\w.]+)", text)
            if m and "Annotated" in text:
                out[target] = m.group(1)
    return out
