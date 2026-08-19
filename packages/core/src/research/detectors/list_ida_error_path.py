#!/usr/bin/env python3
"""
list_ida_error_path.py — M4 Detector: List/IDA Add Without Del/Free in Error Paths

Pattern (Sony class):
  list_add / hlist_add_head / list_add_tail / ida_alloc* followed by
  goto <error_label> where matching list_del / ida_free is NOT reachable
  from the error label through any path (including label fallthrough).

Algorithm (v2 — with label fallthrough):
  1. Extract functions from .c files via brace counting.
  2. For each function, find all add sites and goto statements.
  3. Build a label-to-cleanup map: for each error label, compute the set of
     cleanup calls reachable from that label by tracing forward through the
     function body until a return statement or function end, following
     through cascading label fallthrough.
  4. For each add site, find subsequent gotos to error labels and check
     if the required cleanup is reachable from the target label.
  5. Report: add site, goto site, error label, missing cleanup, severity.

Key fix over v1: C labels are NOT blocks — execution falls through to
subsequent code/labels. We trace forward from the label definition line
to the next `return` or function end, collecting all cleanup calls along
the way (including from labels we fall through into).

Usage:
  python3 list_ida_error_path.py <kernel_source_dir> [--subsystems drivers,fs]
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ── Data model ──────────────────────────────────────────────────────────────

@dataclass
class AddSite:
    """A list_add / ida_alloc call site."""
    func: str
    line: int
    kind: str           # "list_add", "hlist_add_head", "ida_alloc", etc.
    args: str
    node_arg: str       # first argument (the node/ida being added)


@dataclass
class GotoSite:
    """A goto <label>; statement."""
    line: int
    label: str
    func: str


@dataclass
class ErrorLabel:
    """An error-handling label with its reachable cleanup."""
    name: str
    line: int           # where the label is defined
    func: str
    # The set of cleanup calls reachable from this label
    # (traced forward through fallthrough until return/func-end)
    reachable_cleanup: Set[str] = field(default_factory=set)
    # Raw cleanup call names found in reachable region
    reachable_cleanup_list: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """A detected missing-cleanup finding."""
    file: str
    func: str
    add_site: AddSite
    goto_line: int
    goto_label: str
    error_label: ErrorLabel
    missing_cleanup: List[str]
    severity: str


# ── Constants ───────────────────────────────────────────────────────────────

# add operations → expected cleanup operations
ADD_OPS = {
    "list_add":          {"cleanup": ["list_del", "list_del_init"], "kind": "list"},
    "list_add_tail":     {"cleanup": ["list_del", "list_del_init"], "kind": "list"},
    "list_add_rcu":      {"cleanup": ["list_del_rcu"],              "kind": "list"},
    "hlist_add_head":    {"cleanup": ["hlist_del", "hlist_del_init"],"kind": "hlist"},
    "hlist_add_before":  {"cleanup": ["hlist_del", "hlist_del_init"],"kind": "hlist"},
    "hlist_add_behind":  {"cleanup": ["hlist_del", "hlist_del_init"],"kind": "hlist"},
    "hlist_add_head_rcu":{"cleanup": ["hlist_del_rcu"],              "kind": "hlist"},
    "ida_alloc":         {"cleanup": ["ida_free"],                   "kind": "ida"},
    "ida_alloc_range":   {"cleanup": ["ida_free"],                   "kind": "ida"},
    "ida_alloc_min":     {"cleanup": ["ida_free"],                   "kind": "ida"},
    "ida_alloc_max":     {"cleanup": ["ida_free"],                   "kind": "ida"},
    "ida_simple_get":    {"cleanup": ["ida_simple_remove"],          "kind": "ida"},
}

ADD_RE = re.compile(
    r'\b(' + '|'.join(re.escape(op) for op in ADD_OPS) + r')\s*\(',
)

CLEANUP_OPS = {
    "list_del", "list_del_init", "list_del_rcu",
    "hlist_del", "hlist_del_init", "hlist_del_rcu",
    "ida_free", "ida_simple_remove",
}
CLEANUP_RE = re.compile(
    r'\b(' + '|'.join(re.escape(op) for op in CLEANUP_OPS) + r')\s*\(',
)

GOTO_RE = re.compile(r'\bgoto\s+(\w+)\s*;')
LABEL_RE = re.compile(r'^(\w+)\s*:\s*$', re.MULTILINE)
RETURN_RE = re.compile(r'\breturn\b')

ERROR_LABEL_PATTERNS = [
    r'^err', r'^error', r'^fail', r'^out_', r'^cleanup',
    r'^free', r'^release', r'^unlock', r'^undo',
]

# Wrapper-function detection patterns
WRAPPER_CLEANUP_PATTERNS = {
    "list":  [r'\b(\w*remove\w*)\s*\(', r'\b(\w*del\w*)\s*\(',
              r'\b(\w*cleanup\w*)\s*\(', r'\b(\w*unlink\w*)\s*\('],
    "hlist": [r'\b(\w*remove\w*)\s*\(', r'\b(\w*del\w*)\s*\(',
              r'\b(\w*cleanup\w*)\s*\(', r'\b(\w*unlink\w*)\s*\('],
    "ida":   [r'\b(\w*release\w*)\s*\(', r'\b(\w*free\w*)\s*\(',
              r'\b(\w*cleanup\w*)\s*\('],
}


# ── Core parsing ────────────────────────────────────────────────────────────

def strip_comments(text: str) -> str:
    """Remove C comments (both // and /* */) from text."""
    text = re.sub(r'//[^\n]*', '', text)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    return text


def extract_functions(filepath: str) -> List[Dict]:
    """Extract function name, start/end line, and body from a C source file.

    Uses brace-counting from function signature to closing brace.
    Returns list of {name, start_line, end_line, brace_start, brace_end, body}."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return []

    functions = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i].strip()

        # Skip preprocessor, blank lines, comment starts
        if (not line or line.startswith('#') or line.startswith('/*')
                or line.startswith('*') or line.startswith('//')):
            i += 1
            continue

        # Look for function definition: type name(args)
        m = re.match(
            r'^(?:static\s+)?(?:inline\s+)?(?:__\w+\s+)*(?:const\s+)?'
            r'(?:struct\s+)?(?:enum\s+)?(?:union\s+)?'
            r'[\w\s*]+?\s+'                                    # return type
            r'(\w+)\s*'                                        # function name
            r'\([^)]*\)',                                      # parameter list
            line,
        )
        if m:
            func_name = m.group(1)
            # Skip keywords that look like functions
            if func_name in ('if', 'while', 'for', 'switch', 'return', 'sizeof'):
                i += 1
                continue

            # Find opening brace
            brace_line = i
            while brace_line < n and '{' not in lines[brace_line]:
                brace_line += 1
            if brace_line >= n:
                i += 1
                continue

            # Count braces
            brace_count = 0
            j = brace_line
            found_open = False
            while j < n:
                for ch in lines[j]:
                    if ch == '{':
                        brace_count += 1
                        found_open = True
                    elif ch == '}':
                        brace_count -= 1
                        if brace_count == 0 and found_open:
                            body = ''.join(lines[brace_line:j + 1])
                            functions.append({
                                'name': func_name,
                                'start_line': i + 1,         # 1-based
                                'end_line': j + 1,
                                'brace_start': brace_line + 1,
                                'brace_end': j + 1,
                                'body': body,
                            })
                            i = j + 1
                            break
                else:
                    j += 1
                    continue
                break
            else:
                i += 1
                continue
        i += 1

    return functions


def find_add_sites(func: Dict) -> List[AddSite]:
    """Find all list_add / ida_alloc etc. sites in a function body."""
    sites = []
    body = func['body']
    base_line = func['brace_start'] - 1  # body starts at brace_start, 0-based

    for m in ADD_RE.finditer(body):
        op = m.group(1)
        start = m.start()

        line_offset = body[:start].count('\n')
        actual_line = base_line + line_offset + 1

        # Extract arguments between parens
        paren_start = m.end() - 1
        depth = 0
        arg_end = paren_start
        for k in range(paren_start, len(body)):
            if body[k] == '(':
                depth += 1
            elif body[k] == ')':
                depth -= 1
                if depth == 0:
                    arg_end = k
                    break
        args_text = body[paren_start + 1:arg_end].strip()
        first_arg = extract_first_arg(args_text)

        sites.append(AddSite(
            func=func['name'],
            line=actual_line,
            kind=op,
            args=args_text,
            node_arg=first_arg,
        ))

    return sites


def extract_first_arg(args_text: str) -> str:
    """Extract first comma-separated argument, handling nested parens."""
    depth = 0
    for i, ch in enumerate(args_text):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            return args_text[:i].strip()
    return args_text.strip()


def find_goto_sites(func: Dict) -> List[GotoSite]:
    """Find all goto <label>; statements in a function body."""
    sites = []
    body = func['body']
    base_line = func['brace_start'] - 1
    body_clean = strip_comments(body)

    for m in GOTO_RE.finditer(body_clean):
        label = m.group(1)
        line_offset = body_clean[:m.start()].count('\n')
        actual_line = base_line + line_offset + 1
        sites.append(GotoSite(line=actual_line, label=label, func=func['name']))

    return sites


def is_error_label(name: str) -> bool:
    """Heuristic: does this label name suggest error handling?"""
    for pat in ERROR_LABEL_PATTERNS:
        if re.match(pat, name):
            return True
    return False


def find_reachable_cleanup(
    func: Dict,
    label_line_1based: int,
    all_cleanup_calls: List[Tuple[int, str]],
    return_lines: Set[int],
) -> Tuple[Set[str], List[str]]:
    """Trace forward from a label definition to find all cleanup calls
    reachable by fallthrough (until next return or function end).

    Returns (set of cleanup function names, list of cleanup function names).

    Key insight: C labels don't create blocks. Code falls through.
    We trace from the label line to the next return statement or the
    end of the function, collecting all cleanup calls encountered.
    This naturally handles cascading labels like:
        out_destroy:
            destroy_workqueue(wq);
        out_cleanup:
            list_del(&node);
            return;
    """
    body = func['body']
    base_line = func['brace_start'] - 1  # 0-based
    body_lines = body.split('\n')
    func_start_0based = base_line
    func_end_0based = func['brace_end']  # 1-based → 0-based

    # Convert label line to 0-based offset into body_lines
    label_offset = label_line_1based - base_line - 1

    cleanup_set = set()
    cleanup_list = []

    # Walk forward from the label line
    for off in range(label_offset, len(body_lines)):
        abs_line = base_line + off + 1  # 1-based

        # Stop at return (but note: return might be inside a conditional
        # that doesn't always execute. We treat it as a stop to be
        # conservative — if the return is conditional, the real path may
        # continue to more cleanup.)
        line_clean = strip_comments(body_lines[off])
        if re.search(r'\breturn\b', line_clean):
            # Check if the return is guarded by if() — if so, it might
            # not be the only path; continue looking
            # Simple heuristic: if "return" appears alone or preceded by
            # simple statement end, assume it's unconditional
            if not _is_conditional_return(line_clean):
                # But only stop if this return is at a label level
                # (not inside a nested if block that we can't trace)
                break

        # Collect cleanup calls on this line
        for cm in CLEANUP_RE.finditer(line_clean):
            call = cm.group(1)
            cleanup_set.add(call)
            cleanup_list.append(call)

    return cleanup_set, cleanup_list


def _is_conditional_return(line: str) -> bool:
    """Crude heuristic: is this return inside a conditional?"""
    # If the line starts with 'if' or is deeply indented, it might be conditional
    stripped = line.strip()
    if stripped.startswith('if') or stripped.startswith('else'):
        return True
    # If the line has 'return' but is indented more than the function body,
    # it's likely conditional
    return False


def find_error_labels(func: Dict) -> List[ErrorLabel]:
    """Find all error-handling labels and compute reachable cleanup for each.

    Uses forward tracing from each label to handle fallthrough correctly."""
    labels = []
    body = func['body']
    base_line = func['brace_start'] - 1
    body_clean = strip_comments(body)
    body_lines = body.split('\n')

    # First pass: find all label definitions with their line numbers
    label_defs = []  # (name, line_1based)
    for m in LABEL_RE.finditer(body):
        label_name = m.group(1)
        if not is_error_label(label_name):
            continue
        line_offset = body[:m.start()].count('\n')
        label_line = base_line + line_offset + 1
        label_defs.append((label_name, label_line))

    if not label_defs:
        return labels

    # Sort labels by line number (ascending)
    label_defs.sort(key=lambda x: x[1])

    # Build cleanup for each label by tracing forward
    for idx, (name, line) in enumerate(label_defs):
        # Determine trace end: next label definition's line, or function end
        if idx + 1 < len(label_defs):
            next_label_line = label_defs[idx + 1][1]
            # But we DON'T stop at the next label — we keep going because
            # execution may fall through. Instead we trace all the way to
            # function end / return.
            # The next label just gives us a hint about region boundaries.

        cleanup_set, cleanup_list = _trace_cleanup_forward(
            func, line, label_defs,
        )

        labels.append(ErrorLabel(
            name=name,
            line=line,
            func=func['name'],
            reachable_cleanup=cleanup_set,
            reachable_cleanup_list=cleanup_list,
        ))

    return labels


def _trace_cleanup_forward(
    func: Dict,
    start_line_1based: int,
    all_labels: List[Tuple[str, int]],
) -> Tuple[Set[str], List[str]]:
    """Trace forward from start_line_1based, collecting all cleanup calls
    until we hit an unconditional return or function end.

    We also trace through cascading labels (fallthrough).
    Returns (set of cleanup names, list of cleanup names)."""
    body = func['body']
    base_line = func['brace_start'] - 1  # 0-based
    body_lines = body.split('\n')
    func_end_1based = func['brace_end']

    start_offset = start_line_1based - base_line - 1

    cleanup_set = set()
    cleanup_list = []

    # Determine which lines contain unconditional returns
    unconditional_returns = _find_unconditional_returns(func)

    for off in range(start_offset, len(body_lines)):
        abs_line = base_line + off + 1

        # Stop at unconditional return
        if abs_line in unconditional_returns:
            break

        # Stop at function end
        if abs_line >= func_end_1based:
            break

        line_clean = strip_comments(body_lines[off])

        # Collect cleanup calls
        for cm in CLEANUP_RE.finditer(line_clean):
            call = cm.group(1)
            cleanup_set.add(call)
            cleanup_list.append(call)

    return cleanup_set, cleanup_list


def _find_unconditional_returns(func: Dict) -> Set[int]:
    """Find lines with unconditional return statements.

    Heuristic: a return not inside if/else/for/while/switch is unconditional.
    We approximate this by checking if the line contains only 'return' plus
    optional value and semicolon, and is at the same nesting level as labels
    (i.e., not inside a deeper block).

    Returns set of 1-based line numbers."""
    body = func['body']
    base_line = func['brace_start'] - 1
    body_lines = body.split('\n')

    unconditional = set()

    # Track brace depth per line
    depth = 0

    for off, line in enumerate(body_lines):
        abs_line = base_line + off + 1
        # Count braces (crude but effective for this purpose)
        for ch in line:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1

        line_clean = strip_comments(line).strip()

        # A return is unconditional if:
        # - The line matches `return ...;` pattern
        # - It's at the top level of the function body (brace depth <= 1)
        if re.match(r'^return\b.*;\s*$', line_clean) and depth <= 1:
            unconditional.add(abs_line)

    return unconditional


def analyze_function(filepath: str, func: Dict) -> List[Finding]:
    """Analyze a single function for missing list/IDA cleanup in error paths."""
    findings = []

    add_sites = find_add_sites(func)
    if not add_sites:
        return findings

    goto_sites = find_goto_sites(func)
    error_labels = find_error_labels(func)
    label_map = {el.name: el for el in error_labels}

    for add in add_sites:
        for goto in goto_sites:
            if goto.line <= add.line:
                continue  # goto before add: irrelevant

            if goto.label not in label_map:
                continue  # not a recognized error label

            error_label = label_map[goto.label]

            # Determine expected cleanup for this add operation
            expected_cleanup = set(ADD_OPS[add.kind]["cleanup"])
            add_kind = ADD_OPS[add.kind]["kind"]

            # Check if expected cleanup is reachable from the error label
            missing = expected_cleanup - error_label.reachable_cleanup
            if not missing:
                continue

            # Check for wrapper function calls in the reachable region
            still_missing = []
            for op in missing:
                if not _wrapper_cleanup_present(func, add, error_label, add_kind, op):
                    still_missing.append(op)

            if not still_missing:
                continue

            # Severity
            if any('list_del' in m or 'hlist_del' in m for m in still_missing):
                severity = "HIGH"
            elif any('ida' in m.lower() for m in still_missing):
                severity = "MEDIUM"
            else:
                severity = "LOW"

            findings.append(Finding(
                file=filepath,
                func=func['name'],
                add_site=add,
                goto_line=goto.line,
                goto_label=goto.label,
                error_label=error_label,
                missing_cleanup=still_missing,
                severity=severity,
            ))

    return findings


def _wrapper_cleanup_present(
    func: Dict,
    add: AddSite,
    error_label: ErrorLabel,
    add_kind: str,
    missing_op: str,
) -> bool:
    """Check if a wrapper function in the reachable cleanup region likely
    performs the missing cleanup operation.

    Uses two heuristics:
    1. Function call names matching cleanup patterns (remove, del, free, etc.)
    2. The add's node_arg's base struct variable appearing in the region
       alongside a function call (suggesting wrapper like sony_remove_dev_list(sc))
    """
    body = func['body']
    base_line = func['brace_start'] - 1
    body_lines = body.split('\n')

    # Get the reachable region text
    start_off = error_label.line - base_line - 1
    end_off = len(body_lines)

    # Find unconditional return to bound the region
    unconditional_returns = _find_unconditional_returns(func)
    for off in range(start_off, len(body_lines)):
        if base_line + off + 1 in unconditional_returns:
            end_off = off
            break

    region_lines = body_lines[start_off:end_off + 1]
    region_text = '\n'.join(region_lines)
    region_clean = strip_comments(region_text)

    # Heuristic 1: wrapper function names
    patterns = WRAPPER_CLEANUP_PATTERNS.get(add_kind, [])
    for pat in patterns:
        if re.search(pat, region_clean):
            return True

    # Heuristic 2: struct variable appears with function call pattern
    # Extract base variable name from node_arg
    # "&sc->list_node" → "sc"
    # "&peer_device->peer_devices" → "peer_device"
    if add.node_arg:
        node_base = re.sub(r'^&?\s*', '', add.node_arg)
        # Remove member access: keep the struct variable name
        node_base = re.sub(r'->.*$', '', node_base)
        node_base = re.sub(r'\..*$', '', node_base)
        if node_base and len(node_base) > 1:
            # Check if this variable appears in function calls in the region
            # Pattern: function_name(node_base) or function_name(..., node_base, ...)
            call_with_var = re.compile(
                r'\w+\s*\([^)]*' + re.escape(node_base) + r'[^)]*\)'
            )
            if call_with_var.search(region_clean):
                return True

    # Also check: if the wrapper function is the EXACT same name that appears
    # in the remove path (e.g. sony_remove → sony_remove_dev_list). We look for
    # any function call that has "remove" or "release" AND the same base struct.
    if add.node_arg:
        node_base = re.sub(r'^&?\s*', '', add.node_arg)
        node_base = re.sub(r'->.*$', '', node_base)
        node_base = re.sub(r'\..*$', '', node_base)
        if node_base and len(node_base) > 1:
            # Structured cleanup functions often take the struct pointer
            cleanup_call = re.compile(
                r'\b(\w*(?:remove|release|cleanup|free|del)\w*)\s*\('
                r'[^)]*' + re.escape(node_base) + r'[^)]*\)'
            )
            if cleanup_call.search(region_clean):
                return True

    return False


# ── Main scanner ────────────────────────────────────────────────────────────

def scan_directory(root_dir: str, subsystems: Optional[List[str]] = None) -> List[Finding]:
    """Scan kernel source tree for list/IDA error-path leaks."""
    all_findings = []

    scan_dirs = []
    if subsystems:
        for sub in subsystems:
            path = os.path.join(root_dir, sub.strip())
            if os.path.isdir(path):
                scan_dirs.append(path)
    else:
        for d in ['drivers', 'fs']:
            path = os.path.join(root_dir, d)
            if os.path.isdir(path):
                scan_dirs.append(path)

    c_files = []
    for scan_dir in scan_dirs:
        for dirpath, _, filenames in os.walk(scan_dir):
            for fn in filenames:
                if fn.endswith('.c'):
                    c_files.append(os.path.join(dirpath, fn))

    total = len(c_files)
    for idx, filepath in enumerate(c_files):
        if idx % 500 == 0 and total > 0:
            print(f"  Scanning {idx}/{total} files...", file=sys.stderr)

        functions = extract_functions(filepath)
        for func in functions:
            try:
                findings = analyze_function(filepath, func)
                all_findings.extend(findings)
            except Exception as e:
                print(f"  WARN: error analyzing {filepath}:{func['name']}: {e}",
                      file=sys.stderr)

    return all_findings


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate: same add site + goto label = one finding."""
    seen = set()
    result = []
    for f in findings:
        key = (f.file, f.func, f.add_site.line, f.add_site.kind, f.goto_label)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def findings_to_json(findings: List[Finding]) -> List[Dict]:
    """Convert findings to JSON-serializable dicts."""
    output = []
    for f in findings:
        output.append({
            "file": f.file,
            "function": f.func,
            "severity": f.severity,
            "add_operation": f.add_site.kind,
            "add_line": f.add_site.line,
            "add_args": f.add_site.args,
            "goto_line": f.goto_line,
            "goto_label": f.goto_label,
            "error_label_line": f.error_label.line,
            "error_label_reachable_cleanup": f.error_label.reachable_cleanup_list,
            "missing_cleanup": f.missing_cleanup,
        })
    return output


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="M4 Detector: Find list/IDA add without del/free in error paths"
    )
    parser.add_argument("kernel_dir", help="Path to kernel source tree root")
    parser.add_argument(
        "--subsystems", "-s", default="drivers,fs",
        help="Comma-separated subsystems to scan (default: drivers,fs)",
    )
    parser.add_argument("--output", "-o", help="Output JSON file (default: stdout)")
    parser.add_argument(
        "--min-severity", default="MEDIUM",
        choices=["LOW", "MEDIUM", "HIGH"],
        help="Minimum severity to report (default: MEDIUM)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output as JSON (default: human-readable)",
    )
    args = parser.parse_args()

    kernel_dir = args.kernel_dir
    if not os.path.isdir(kernel_dir):
        print(f"Error: {kernel_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    subsystems = [s.strip() for s in args.subsystems.split(",") if s.strip()]

    print(f"M4 Detector v2: Scanning {kernel_dir} subsystems: {subsystems}",
          file=sys.stderr)

    findings = scan_directory(kernel_dir, subsystems)
    findings = deduplicate_findings(findings)

    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    min_sev = severity_order[args.min_severity]
    findings = [f for f in findings if severity_order[f.severity] >= min_sev]
    findings.sort(key=lambda f: (-severity_order[f.severity], f.file, f.add_site.line))

    if args.json:
        result = {
            "detector": "M4_list_ida_error_path_v2",
            "kernel_dir": kernel_dir,
            "subsystems": subsystems,
            "total_findings": len(findings),
            "findings": findings_to_json(findings),
        }
        json_output = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(json_output)
            print(f"Wrote {len(findings)} findings to {args.output}", file=sys.stderr)
        else:
            print(json_output)
    else:
        if args.output:
            with open(args.output, 'w') as f:
                _write_human_readable(findings, f)
            print(f"Wrote {len(findings)} findings to {args.output}", file=sys.stderr)
        else:
            _write_human_readable(findings, sys.stdout)

    high = sum(1 for f in findings if f.severity == "HIGH")
    med = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")
    print(f"\nSummary: {len(findings)} findings ({high} HIGH, {med} MEDIUM, {low} LOW)",
          file=sys.stderr)


def _write_human_readable(findings: List[Finding], out):
    """Write findings in human-readable format."""
    sev_colors = {"HIGH": "!!!", "MEDIUM": "!! ", "LOW": "!  "}

    for f in findings:
        out.write(f"\n{'='*72}\n")
        out.write(f"{sev_colors[f.severity]} [{f.severity}] {f.file}:{f.add_site.line}\n")
        out.write(f"    Function: {f.func}()\n")
        out.write(f"    Add:      {f.add_site.kind}({f.add_site.args})\n")
        out.write(f"    Goto:     line {f.goto_line} → {f.goto_label}\n")
        out.write(f"    Label:    {f.goto_label}: at line {f.error_label.line}\n")
        out.write(f"    Has:      {f.error_label.reachable_cleanup_list or '(none)'}\n")
        out.write(f"    Missing:  {', '.join(f.missing_cleanup)}\n")


if __name__ == "__main__":
    main()
