import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import audit  # noqa: E402
from summarize import summarize  # noqa: E402


def test_classify():
    assert audit.classify("a" * 40) == "full_sha"
    assert audit.classify("915b19b") == "short_sha"
    assert audit.classify("0.28.0") == "version_tag"
    assert audit.classify("v0.2.1") == "version_tag"
    assert audit.classify("v1") == "version_tag"
    assert audit.classify("master") == "branch"
    assert audit.classify("main") == "branch"
    assert audit.classify("${{ env.TRIVY_VERSION }}") == "other"


def test_refs_in_parses_uses_lines(monkeypatch):
    workflow = """
jobs:
  scan:
    steps:
      - uses: actions/checkout@v4
      - name: Trivy
        uses: aquasecurity/trivy-action@0.28.0
      - uses: "aquasecurity/trivy-action@915b19bbe73b92a6cf82a1bc12b087c9a19a5fe2" # 0.28.0
      # - uses: aquasecurity/trivy-action@master
      - uses: aquasecurity/trivy-action@master
"""
    monkeypatch.setattr(audit, "get", lambda url, accept=None: workflow)
    rows = audit.refs_in("o/r", ".github/workflows/x.yml", "abc", "aquasecurity/trivy-action")
    assert [(r[3], r[4]) for r in rows] == [
        ("0.28.0", "version_tag"),
        ("915b19bbe73b92a6cf82a1bc12b087c9a19a5fe2", "full_sha"),
        ("master", "branch"),
    ]


def test_summarize_counts_repos_fully_pinned():
    rows = [
        {"repo": "a/a", "action": "x", "class": "full_sha"},
        {"repo": "a/a", "action": "x", "class": "full_sha"},
        {"repo": "b/b", "action": "x", "class": "full_sha"},
        {"repo": "b/b", "action": "x", "class": "branch"},
        {"repo": "c/c", "action": "x", "class": "version_tag"},
    ]
    s = summarize(rows)["x"]
    assert s["uses_lines"] == 5
    assert s["repos"] == 3
    assert s["repos_all_full_sha"] == 1
    assert s["repos_any_branch"] == 1
