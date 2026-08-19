#!/usr/bin/env python3
"""Scrape syzbot fixed-bugs list and label exploitability heuristically.

Outputs JSONL (one JSON object per line) to stdout or a file.
Prints summary stats to stderr.

Usage:
    python scrape_syzbot.py --pages 5
    python scrape_syzbot.py --pages 3 --output bugs.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter

try:
    import requests

    def _get(url: str, timeout: int = 30) -> str:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "0sec-scraper/0.1"})
        resp.raise_for_status()
        return resp.text

except ImportError:
    import urllib.request

    def _get(url: str, timeout: int = 30) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": "0sec-scraper/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")


BASE = "https://syzkaller.appspot.com"
FIXED_URL = BASE + "/upstream/fixed"

# ── Crash-type classification ────────────────────────────────────────────────

CRASH_PATTERNS: list[tuple[str, str]] = [
    # (regex, canonical crash_type)
    (r"KASAN:\s*slab-use-after-free",    "kasan-uaf"),
    (r"KASAN:\s*use-after-free",         "kasan-uaf"),
    (r"KASAN:\s*slab-out-of-bounds",     "kasan-heap-oob"),
    (r"KASAN:\s*out-of-bounds",          "kasan-heap-oob"),
    (r"KASAN:\s*stack-out-of-bounds",    "kasan-stack-oob"),
    (r"KASAN:\s*global-out-of-bounds",   "kasan-global-oob"),
    (r"KASAN:\s*null-ptr-deref",         "null-deref"),
    (r"KASAN",                           "kasan-other"),
    (r"KMSAN",                           "kmsan"),
    (r"KCSAN",                           "kcsan"),
    (r"KFENCE",                          "kfence"),
    (r"UBSAN",                           "ubsan"),
    (r"BUG:\s*unable to handle.*null",   "null-deref"),
    (r"general protection fault",        "gpf"),
    (r"stack-out-of-bounds",             "kasan-stack-oob"),
    (r"null-ptr-deref|null pointer",     "null-deref"),
    (r"WARNING",                         "warning"),
    (r"lockdep|lock.held",               "lockdep"),
    (r"RCU",                             "rcu"),
    (r"deadlock",                        "deadlock"),
    (r"memory leak",                     "memory-leak"),
    (r"INFO:\s*task hung",               "task-hung"),
    (r"soft lockup",                     "soft-lockup"),
    (r"kernel BUG",                      "kernel-bug"),
]

ACCESS_RE = re.compile(r"\b(Read|Write)\b", re.IGNORECASE)


def classify_crash(title: str) -> tuple[str, str | None]:
    """Return (crash_type, access_type|None)."""
    for pattern, ctype in CRASH_PATTERNS:
        if re.search(pattern, title, re.IGNORECASE):
            access = None
            m = ACCESS_RE.search(title)
            if m:
                access = m.group(1).lower()
            return ctype, access
    return "other", None


# ── Exploitability labelling ─────────────────────────────────────────────────

EXPLOITABLE_TYPES = {
    ("kasan-uaf", "write"),
    ("kasan-heap-oob", "write"),
    ("kasan-stack-oob", "write"),
    ("kasan-stack-oob", None),  # stack OOB is exploitable either way
}

LIKELY_EXPLOITABLE_TYPES = {
    ("kasan-uaf", "read"),
    ("kasan-uaf", None),       # UAF without clear direction is still risky
    ("kasan-heap-oob", "read"),
    ("kasan-heap-oob", None),
    ("kasan-stack-oob", "read"),
    ("kasan-global-oob", "write"),
    ("kasan-global-oob", "read"),
    ("kasan-global-oob", None),
    ("gpf", None),
    ("gpf", "write"),
    ("gpf", "read"),
}

LOW_EXPLOITABILITY_TYPES = {
    "null-deref", "ubsan", "warning", "lockdep", "rcu", "deadlock",
    "memory-leak", "task-hung", "soft-lockup", "kcsan", "kmsan",
}


def label_exploitability(crash_type: str, access_type: str | None) -> str:
    if (crash_type, access_type) in EXPLOITABLE_TYPES:
        return "exploitable"
    if (crash_type, access_type) in LIKELY_EXPLOITABLE_TYPES:
        return "likely_exploitable"
    if crash_type in LOW_EXPLOITABILITY_TYPES:
        return "low_exploitability"
    return "unknown"


# ── HTML parsing (regex-based, no beautifulsoup) ────────────────────────────

# Each bug row in the syzbot table looks roughly like:
#   <td class="title"><a href="/bug?extid=XXXX">Title here</a></td>
#   ... <td>Repro</td> ... <td>Fix commit</td> ...

BUG_ROW_RE = re.compile(
    r'<tr[^>]*>(.+?)</tr>',
    re.DOTALL,
)

TITLE_LINK_RE = re.compile(
    r'<td[^>]*class="title"[^>]*>\s*<a\s+href="(/bug\?[^"]+)"[^>]*>([^<]+)</a>',
    re.DOTALL,
)

# Also match title cells without a class, since syzbot tables vary
TITLE_LINK_ALT_RE = re.compile(
    r'<td[^>]*>\s*<a\s+href="(/bug\?[^"]+)"[^>]*>([^<]+)</a>',
    re.DOTALL,
)

TD_RE = re.compile(r'<td[^>]*>(.*?)</td>', re.DOTALL)

REPRO_C_RE = re.compile(r'href="(/text\?[^"]*tag=ReproC[^"]*)"', re.DOTALL)
REPRO_SYZBOT_RE = re.compile(r'href="(/text\?[^"]*tag=ReproSyz[^"]*)"', re.DOTALL)

COMMIT_RE = re.compile(r'[0-9a-f]{8,40}')

# Subsystem from the bug page
SUBSYS_RE = re.compile(r'Subsystem[^<]*</td>\s*<td[^>]*>([^<]+)', re.DOTALL)

# Pagination: next page link
NEXT_PAGE_RE = re.compile(r'<a\s+href="([^"]*)"[^>]*>\s*Next\s*</a>', re.IGNORECASE)


def parse_bug_list_page(html: str) -> tuple[list[dict], str | None]:
    """Parse a fixed-bugs listing page. Returns (bugs, next_page_url|None)."""
    bugs: list[dict] = []

    rows = BUG_ROW_RE.findall(html)
    for row_html in rows:
        # Try to find the title link
        m = TITLE_LINK_RE.search(row_html)
        if not m:
            m = TITLE_LINK_ALT_RE.search(row_html)
        if not m:
            continue

        bug_path = m.group(1)
        title = m.group(2).strip()

        # Skip header rows
        if title.lower() in ("title", "bug"):
            continue

        bug_url = BASE + bug_path

        # Extract all <td> cells
        cells = TD_RE.findall(row_html)

        # Look for C repro link in the row
        has_repro_c = bool(REPRO_C_RE.search(row_html))
        repro_c_url = None
        rm = REPRO_C_RE.search(row_html)
        if rm:
            repro_c_url = BASE + rm.group(1)

        # Check for "C" text in cells (some pages just show "C" instead of a link)
        if not has_repro_c:
            for cell in cells:
                cell_text = re.sub(r'<[^>]+>', '', cell).strip()
                if cell_text == "C":
                    has_repro_c = True
                    break

        # Fix commit: look for a hash in cells
        fix_commit = None
        for cell in cells:
            cell_text = re.sub(r'<[^>]+>', '', cell).strip()
            cm = COMMIT_RE.search(cell_text)
            if cm and len(cm.group(0)) >= 8:
                # Avoid matching the extid in the bug URL
                if "extid" not in cell_text.lower():
                    fix_commit = cm.group(0)
                    break

        # Subsystem: often in a cell
        subsystem = None
        for cell in cells:
            cell_text = re.sub(r'<[^>]+>', '', cell).strip()
            # Subsystem cells tend to be short strings without hashes
            if cell_text and not COMMIT_RE.match(cell_text) and cell_text != title:
                if "/" in cell_text or cell_text[0].islower():
                    if len(cell_text) < 60:
                        subsystem = cell_text
                        break

        crash_type, access_type = classify_crash(title)
        exploitability = label_exploitability(crash_type, access_type)

        bugs.append({
            "title": title,
            "url": bug_url,
            "crash_type": crash_type,
            "access_type": access_type,
            "has_reproducer": has_repro_c,
            "reproducer_url": repro_c_url,
            "fix_commit": fix_commit,
            "subsystem": subsystem,
            "exploitability": exploitability,
        })

    # Find next page
    next_url = None
    nm = NEXT_PAGE_RE.search(html)
    if nm:
        href = nm.group(1).replace("&amp;", "&")
        if href.startswith("/"):
            next_url = BASE + href
        elif href.startswith("http"):
            next_url = href
        else:
            next_url = FIXED_URL + "?" + href if "?" not in href else FIXED_URL.rsplit("/", 1)[0] + "/" + href

    return bugs, next_url


def fetch_reproducer_url(bug_url: str) -> str | None:
    """Visit a bug page and extract the C reproducer URL."""
    try:
        html = _get(bug_url)
        m = REPRO_C_RE.search(html)
        if m:
            return BASE + m.group(1)
    except Exception as exc:
        print(f"[warn] failed to fetch {bug_url}: {exc}", file=sys.stderr)
    return None


def fetch_bug_details(bug_url: str) -> dict:
    """Visit a bug page and extract extra details (reproducer, subsystem)."""
    details: dict = {}
    try:
        html = _get(bug_url)
        m = REPRO_C_RE.search(html)
        if m:
            details["reproducer_url"] = BASE + m.group(1)
            details["has_reproducer"] = True
        sm = SUBSYS_RE.search(html)
        if sm:
            details["subsystem"] = sm.group(1).strip()
    except Exception as exc:
        print(f"[warn] failed to fetch bug details {bug_url}: {exc}", file=sys.stderr)
    return details


def scrape(num_pages: int, fetch_details: bool = False) -> list[dict]:
    """Scrape the syzbot fixed bugs list."""
    all_bugs: list[dict] = []
    url: str | None = FIXED_URL

    for page_num in range(num_pages):
        if url is None:
            print(f"[info] no more pages after page {page_num}", file=sys.stderr)
            break

        print(f"[info] fetching page {page_num + 1}/{num_pages}: {url}", file=sys.stderr)
        try:
            html = _get(url)
        except Exception as exc:
            print(f"[error] failed to fetch page {page_num + 1}: {exc}", file=sys.stderr)
            break

        bugs, next_url = parse_bug_list_page(html)
        print(f"[info] page {page_num + 1}: found {len(bugs)} bugs", file=sys.stderr)

        # For bugs with reproducers that we didn't get a URL for, or
        # bugs without subsystem info, optionally fetch the bug page
        if fetch_details:
            for i, bug in enumerate(bugs):
                if bug["has_reproducer"] and not bug["reproducer_url"]:
                    print(f"[info]   fetching details for bug {i + 1}/{len(bugs)}", file=sys.stderr)
                    details = fetch_bug_details(bug["url"])
                    bug.update({k: v for k, v in details.items() if v is not None})
                    time.sleep(0.5)

        all_bugs.extend(bugs)
        url = next_url
        if page_num < num_pages - 1 and url is not None:
            time.sleep(0.5)

    return all_bugs


def print_summary(bugs: list[dict]) -> None:
    """Print summary stats to stderr."""
    total = len(bugs)
    exploit_counts: Counter[str] = Counter()
    crash_counts: Counter[str] = Counter()
    repro_yes = 0
    repro_no = 0

    for bug in bugs:
        exploit_counts[bug["exploitability"]] += 1
        crash_counts[bug["crash_type"]] += 1
        if bug["has_reproducer"]:
            repro_yes += 1
        else:
            repro_no += 1

    print("\n" + "=" * 60, file=sys.stderr)
    print(f"  syzbot scrape summary: {total} bugs", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    print("\n  By exploitability:", file=sys.stderr)
    for label in ["exploitable", "likely_exploitable", "low_exploitability", "unknown"]:
        count = exploit_counts.get(label, 0)
        pct = (count / total * 100) if total else 0
        print(f"    {label:<22s} {count:5d}  ({pct:5.1f}%)", file=sys.stderr)

    print("\n  By crash type (top 15):", file=sys.stderr)
    for ctype, count in crash_counts.most_common(15):
        pct = (count / total * 100) if total else 0
        print(f"    {ctype:<24s} {count:5d}  ({pct:5.1f}%)", file=sys.stderr)

    print(f"\n  Reproducers: {repro_yes} with C repro, {repro_no} without", file=sys.stderr)
    print("=" * 60 + "\n", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scrape syzbot fixed bugs and label exploitability."
    )
    parser.add_argument(
        "--pages", type=int, default=3,
        help="Number of listing pages to scrape (default: 3)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--fetch-details", action="store_true", default=False,
        help="Fetch individual bug pages for reproducer URLs and subsystem info (slower)",
    )
    args = parser.parse_args()

    bugs = scrape(args.pages, fetch_details=args.fetch_details)

    # Write JSONL output
    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        for bug in bugs:
            out.write(json.dumps(bug, ensure_ascii=False) + "\n")
    finally:
        if args.output:
            out.close()

    print_summary(bugs)

    if args.output:
        print(f"[info] wrote {len(bugs)} records to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
