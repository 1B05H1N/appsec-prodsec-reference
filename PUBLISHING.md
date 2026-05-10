# Publishing to GitHub (clean history, tags, commits)

These are **local git** patterns. You must run them in your clone with your own remote and credentials. This document is not legal advice about employment contracts or export rules for your materials.

## Goals addressed here

- A **single-lineage** or **squashed** public history instead of messy local experiments
- **Tags** for releases
- Commits without **Co-authored-by** trailers (omit them entirely)
- **No** automated co-author attribution from tools unless you add it

## Option A - Orphan branch (simplest scrub)

Replaces branch history with one commit (loses prior hashes).

```bash
cd /path/to/repo
git checkout --orphan publish-main
git add -A
git status   # verify no secrets, no unintended .env
git commit -m "Initial public release: curated reference materials"
git branch -M main
git remote add origin https://github.com/YOU/REPO.git   # if not set
git push -u -f origin main
```

## Option B - Squash merge on a new remote

Keep a private repo with full history; create a fresh public repo and push only a squash commit (manual copy or `git read-tree`).

## Tags

```bash
git tag -a v1.0.0 -m "First public release"
git push origin v1.0.0
```

Use [Semantic Versioning](https://semver.org/) only if it fits; otherwise dated tags like `2026.05.10` are fine for docs-only repos.

## Commit messages

Write imperative subject lines, e.g. `Add career outlook and resume guide`. Avoid trailers you do not want public.

## Co-authors

Do **not** add lines like `Co-authored-by: name <email>` unless you intend shared attribution. GitHub reads that trailer.

## Before every push

- Search for API keys, internal hostnames, ticket IDs, and employer-confidential wording.
- Confirm `LICENSE` and `README` disclaimers match what you want to stand behind publicly.

## Two repositories

Repeat the workflow separately for `appsec-prodsec-reference` and `software-approval-reference` so a mistake in one does not contaminate the other.
