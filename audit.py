"""Sample public GitHub workflows that use the security-scanner actions hit in
the March 2026 TeamPCP campaign and classify how each one references the action.

Usage: GITHUB_TOKEN=... python3 audit.py
Writes data/refs.csv (one row per `uses:` line) and data/summary.json.

GitHub code search returns at most 1000 results per query, ranked by its own
relevance, so this is a sample, not a census.
"""
import csv
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ACTIONS = [
    "aquasecurity/trivy-action",
    "aquasecurity/setup-trivy",
    "Checkmarx/kics-github-action",
]
ROOT = Path(__file__).resolve().parent
TOKEN = os.environ.get("GITHUB_TOKEN", "")


def get(url, accept="application/vnd.github+json"):
    req = urllib.request.Request(url, headers={"Accept": accept, "Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", "replace")


def search(action):
    """All (repo, path, blob_sha_url) hits for the action, up to GitHub's 1000 cap."""
    q = f'"{action}@" path:.github/workflows'
    hits = []
    for page in range(1, 11):
        url = "https://api.github.com/search/code?" + urllib.parse.urlencode(
            {"q": q, "per_page": 100, "page": page})
        for attempt in range(5):
            try:
                data = json.loads(get(url))
                break
            except urllib.error.HTTPError as e:
                if e.code in (403, 429):
                    time.sleep(65)
                    continue
                raise
        items = data.get("items", [])
        for it in items:
            commit = urllib.parse.parse_qs(urllib.parse.urlparse(it["url"]).query)["ref"][0]
            hits.append((it["repository"]["full_name"], it["path"], commit))
        print(action, "page", page, len(items), "total", data.get("total_count"), file=sys.stderr)
        if len(items) < 100:
            break
        time.sleep(7)  # code search allows 10 requests per minute
    return data.get("total_count"), hits


def classify(ref):
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return "full_sha"
    if re.fullmatch(r"[0-9a-f]{7,39}", ref):
        return "short_sha"
    if re.fullmatch(r"v?\d+(\.\d+){0,2}", ref):
        return "version_tag"
    if ref in ("master", "main"):
        return "branch"
    return "other"


def refs_in(repo, path, commit, action):
    raw = f"https://raw.githubusercontent.com/{repo}/{commit}/{urllib.parse.quote(path)}"
    try:
        text = get(raw, accept="text/plain")
    except Exception as e:  # file gone or unreadable
        return [(repo, path, action, "", "fetch_error", str(e)[:60])]
    pat = re.compile(r"uses:\s*['\"]?" + re.escape(action) + r"@([^\s'\"#]+)", re.I)
    rows = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue  # commented-out step
        m = pat.search(line)
        if m:
            ref = m.group(1)
            rows.append((repo, path, action, ref, classify(ref), ""))
    return rows


def main():
    (ROOT / "data").mkdir(exist_ok=True)
    totals, rows = {}, []
    for action in ACTIONS:
        total, hits = search(action)
        totals[action] = {"search_total": total, "sampled_files": len(hits)}
        with ThreadPoolExecutor(8) as pool:
            for r in pool.map(lambda h: refs_in(*h, action), hits):
                rows.extend(r)
    with open(ROOT / "data" / "refs.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["repo", "path", "action", "ref", "class", "note"])
        w.writerows(rows)
    (ROOT / "data" / "search_totals.json").write_text(json.dumps(totals, indent=2) + "\n")
    print(json.dumps(totals, indent=2))


if __name__ == "__main__":
    main()
