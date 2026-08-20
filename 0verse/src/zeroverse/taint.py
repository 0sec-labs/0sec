"""The taint model — sources, sinks, and the ``par_slice`` argument DSL.

Schema and approach are adapted from CYD Campus ``mole`` (see
docs/DESIGN-NOTES.md, Decision 3), reimplemented engine-agnostically and — unlike
mole — **without** ``eval``. ``par_slice`` expressions are evaluated by a
whitelisted ``ast`` visitor, so loading a config can never execute arbitrary code.

Config files live in ``conf/NNN-*.json`` and are deep-merged in filename order, so
users extend the model by dropping in a ``conf/004-mylib.json`` — no code changes.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --- par_slice DSL ---------------------------------------------------------

_ALLOWED_NODES = (
    ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not,
    ast.USub, ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.Gt, ast.LtE,
    ast.GtE, ast.Name, ast.Load, ast.Constant,
)


def compile_par_slice(expr: str) -> Callable[[int], bool]:
    """Compile a ``par_slice`` expression over the 1-based-ish arg index ``i``
    into a safe predicate. Examples: ``"i == 2"``, ``"True"``, ``"i >= 2"``.

    Raises ValueError on anything outside the whitelisted grammar (no calls,
    attributes, names other than ``i``, etc.).
    """
    try:
        tree = ast.parse(expr.strip(), mode="eval")
    except SyntaxError as e:
        raise ValueError(f"invalid par_slice {expr!r}: {e}") from e

    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise ValueError(f"disallowed par_slice construct {type(node).__name__} in {expr!r}")
        if isinstance(node, ast.Name) and node.id != "i":
            raise ValueError(f"par_slice may only reference 'i', got {node.id!r} in {expr!r}")
        if isinstance(node, ast.Constant) and not isinstance(node.value, (int, bool)):
            raise ValueError(f"par_slice constants must be int/bool, got {node.value!r}")

    code = compile(tree, "<par_slice>", "eval")

    def predicate(i: int) -> bool:
        return bool(eval(code, {"__builtins__": {}}, {"i": i}))

    predicate.__doc__ = f"par_slice: {expr}"
    return predicate


# --- synopsis parsing ------------------------------------------------------

@dataclass
class Synopsis:
    raw: str
    name: str
    arg_count: int          # fixed (named) argument count
    varargs: bool

    @classmethod
    def parse(cls, raw: str) -> Synopsis:
        m = re.search(r"([A-Za-z_]\w*)\s*\((.*)\)\s*$", raw.strip())
        if not m:
            raise ValueError(f"unparsable synopsis: {raw!r}")
        name, params = m.group(1), m.group(2).strip()
        varargs = "..." in params
        if not params or params == "void":
            args: list[str] = []
        else:
            args = [p for p in (x.strip() for x in params.split(",")) if p and p != "..."]
        return cls(raw=raw, name=name, arg_count=len(args), varargs=varargs)


# --- model -----------------------------------------------------------------

@dataclass
class Role:
    enabled: bool
    par_slice: str
    predicate: Callable[[int], bool] = field(repr=False)


@dataclass
class TaintFunction:
    name: str
    library: str
    category: str
    synopsis: Synopsis
    aliases: list[str] = field(default_factory=list)
    source: Role | None = None
    sink: Role | None = None
    fixer: Role | None = None

    @property
    def all_names(self) -> list[str]:
        return [self.name, *self.aliases]


@dataclass
class TaintModel:
    functions: list[TaintFunction] = field(default_factory=list)

    def sources(self) -> list[TaintFunction]:
        return [f for f in self.functions if f.source and f.source.enabled]

    def sinks(self) -> list[TaintFunction]:
        return [f for f in self.functions if f.sink and f.sink.enabled]

    def by_symbol(self, symbol: str) -> TaintFunction | None:
        for f in self.functions:
            if symbol in f.all_names:
                return f
        return None


def _merge(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def _role(blob: dict[str, Any] | None) -> Role | None:
    if not blob:
        return None
    par = blob.get("par_slice", "True")
    return Role(enabled=bool(blob.get("enabled", False)), par_slice=par,
                predicate=compile_par_slice(par))


def _load_conf_file(path: Path) -> dict[str, Any]:
    """Parse a config file. JSON always; YAML when PyYAML is installed (so users
    can drop a ``conf/NNN-*.yaml`` of sources/sinks without a hard dependency)."""
    text = path.read_text()
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # optional; only needed for YAML config
        except ImportError as e:
            raise RuntimeError(
                f"{path.name} is YAML but PyYAML is not installed (pip install pyyaml)"
            ) from e
        return dict(yaml.safe_load(text) or {})
    return dict(json.loads(text))


def load_model(conf_dir: str | Path) -> TaintModel:
    """Load and deep-merge every ``conf/NNN-*.{json,yaml,yml}`` in filename order,
    then build the validated TaintModel (compiling every par_slice up front).
    Sources/sinks are pure data, so a user extends the model by dropping in a file."""
    conf_dir = Path(conf_dir)
    merged: dict[str, Any] = {}
    paths = sorted(
        [*conf_dir.glob("*.json"), *conf_dir.glob("*.yaml"), *conf_dir.glob("*.yml")],
        key=lambda p: p.name,
    )
    for path in paths:
        blob = _load_conf_file(path)
        if "taint_model" in blob:
            _merge(merged, blob["taint_model"])

    model = TaintModel()
    for library, categories in merged.items():
        for category, funcs in categories.items():
            for name, spec in funcs.items():
                roles = spec.get("roles", {})
                model.functions.append(TaintFunction(
                    name=name,
                    library=library,
                    category=category,
                    synopsis=Synopsis.parse(spec["synopsis"]),
                    aliases=list(spec.get("aliases", [])),
                    source=_role(roles.get("source")),
                    sink=_role(roles.get("sink")),
                    fixer=_role(roles.get("fixer")),
                ))
    return model


def tainted_arg_indices(role: Role, synopsis: Synopsis, *, max_varargs: int = 8) -> Iterable[int]:
    """Yield the 0-based argument indices a role's par_slice selects."""
    n = synopsis.arg_count + (max_varargs if synopsis.varargs else 0)
    return [i for i in range(n) if role.predicate(i)]
