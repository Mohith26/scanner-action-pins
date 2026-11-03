"""Summarize data/refs.csv into results.md."""
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CLASSES = ["full_sha", "version_tag", "branch", "short_sha", "other"]


def load(path=ROOT / "data" / "refs.csv"):
    with open(path) as f:
        return [r for r in csv.DictReader(f) if r["class"] != "fetch_error"]


def summarize(rows):
    out = {}
    by_action = defaultdict(list)
    for r in rows:
        by_action[r["action"]].append(r)
    for action, rs in by_action.items():
        repos = defaultdict(set)
        for r in rs:
            repos[r["repo"]].add(r["class"])
        counts = Counter(r["class"] for r in rs)
        out[action] = {
            "uses_lines": len(rs),
            "repos": len(repos),
            "lines_by_class": {c: counts.get(c, 0) for c in CLASSES},
            "repos_all_full_sha": sum(1 for cs in repos.values() if cs == {"full_sha"}),
            "repos_any_branch": sum(1 for cs in repos.values() if "branch" in cs),
        }
    return out


def pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "n/a"


def main():
    rows = load()
    s = summarize(rows)
    totals = json.loads((ROOT / "data" / "search_totals.json").read_text())
    lines = ["| action | code-search hits | repos sampled | `uses:` lines | full SHA | version tag | branch (master/main) | other | repos fully SHA-pinned |",
             "|---|---|---|---|---|---|---|---|---|"]
    for action, d in s.items():
        n = d["uses_lines"]
        c = d["lines_by_class"]
        lines.append(
            f"| {action} | {totals[action]['search_total']} | {d['repos']} | {n} | {pct(c['full_sha'], n)} | "
            f"{pct(c['version_tag'], n)} | {pct(c['branch'], n)} | {pct(c['short_sha'] + c['other'], n)} | "
            f"{pct(d['repos_all_full_sha'], d['repos'])} |")
    md = "\n".join(lines) + "\n"
    (ROOT / "results.md").write_text(md)
    (ROOT / "data" / "summary.json").write_text(json.dumps(s, indent=2) + "\n")
    print(md)


if __name__ == "__main__":
    main()
