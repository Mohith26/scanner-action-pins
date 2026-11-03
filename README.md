# scanner-action-pins

In March 2026 the TeamPCP campaign got credential-stealing code into Trivy and KICS through, among other things, their GitHub Actions ([Oligo's write-up](https://www.oligo.security/blog/teampcp-campaign-the-evolution-of-modern-supply-chain-attacks)). A workflow that references an action by tag or branch runs whatever that ref points to at the time; only a full commit SHA is fixed. I wanted to know how public workflows reference these scanner actions today, so I sampled them with GitHub code search and classified every `uses:` line.

## Result (sampled Nov 3, 2026)

| action | code-search hits | repos sampled | `uses:` lines | full SHA | version tag | branch (master/main) | other | repos fully SHA-pinned |
|---|---|---|---|---|---|---|---|---|
| aquasecurity/trivy-action | 52480 | 749 | 1338 | 25.0% | 30.1% | 44.8% | 0.1% | 23.1% |
| aquasecurity/setup-trivy | 1312 | 660 | 1089 | 63.1% | 36.2% | 0.7% | 0.0% | 62.1% |
| Checkmarx/kics-github-action | 346 | 331 | 347 | 36.9% | 51.9% | 11.2% | 0.0% | 38.4% |

- For `trivy-action`, the most common reference is a branch: 600 of 1338 lines use `@master` or `@main`, and 372 of the 749 sampled repos have at least one such line. Only 173 repos (23%) pin every use to a full SHA.
- `setup-trivy` is much better pinned (63% of lines are full SHAs), and almost nobody tracks a branch.
- KICS sits in between, with version tags as the most common style.

## How it works

- `audit.py` runs `"<action>@" path:.github/workflows` through the code search API for each action, takes up to the first 1000 files (the API's cap), fetches each file at the commit the search index has, and extracts every non-commented `uses: <action>@<ref>` line.
- Refs are classified as a full 40-character SHA, a short SHA, a version tag (`0.28.0`, `v0.36.0`, `v1`), a branch (`master`/`main`), or other.
- `summarize.py` turns `data/refs.csv` into the table above.

```
GITHUB_TOKEN=<any token> python3 audit.py
python3 summarize.py
python3 -m pytest -q tests
```

Only the standard library is needed (plus pytest for the tests). The raw rows from my run are in `data/refs.csv`.

## Limits

- This is a sample, not a census. Code search ranks results its own way and stops at 1000, so for `trivy-action` (52k hits) I saw under 2% of files. Search also skips forks.
- The search index can lag the default branch, so a few files may be older than what the repo has now.
- A version tag is better than a branch but still movable by whoever controls the action's repo. I didn't check which specific tags or commits were affected by the compromise; this only measures how references are written.
- Many of these repos may not hold valuable secrets, so this says nothing about actual exposure.
