# zimbra_tag_delta.py

Detect and rank changes between the **nearest ≤ base tag** and a **capped target** (nearest ≤ ceiling tag, or a branch tip) across Zimbra repos. Goal: spot untagged fixes that will likely roll into the next patch without diffing against unstable `master`.

## What it does

For each repo:

1. **Base tag** = highest tag ≤ `--version` (same major.minor).
2. **Target** = highest tag ≤ `--ceiling-tag` (same major.minor).  
   If no such tag exists:
   - `--ceiling-mode skip` → skip repo.
   - `--ceiling-mode branch` → compare to the first matching branch in `--branches` (defaults to `origin/release/{line}`, `origin/support/{line}`, `origin/hotfix/{line}`).
3. **Diff**: list commits and touched files between base → target.
4. **Rank**: score commits by simple security heuristics (keywords in subject, suspicious file paths, code file types).

Outputs:
- `tag_delta_summary_<line>_<ts>.csv` – one line per repo (counts + SHAs).
- `tag_delta_manifest_<line>_<ts>.csv` – exact refs/SHAs (for reproducibility).
- `tag_delta_details_<line>_<ts>.json` – per-commit details (files, score).
- `tag_delta_report_<line>_<ts>.md` – human-friendly rollup with top suspects.

> **Note:** “Suspicious” is a heuristic, not a verdict. Use it to triage what to read first.

## Installation / Requirements

- Python **3.6+** (works on OL8’s 3.6.8).
- Git in PATH.
- Local clones present (e.g., produced by your `build_zimbra.sh`). The script will run `git fetch --tags` to refresh refs.

## Common usage

```bash
# 1) Make a repo list (build leaves repos around)
ls -d zm* > repos.txt

# 2) Compare 10.0.15 → capped at 10.0.17 (prefer tags; else release/support/hotfix)
./zimbra_tag_delta.py   --version 10.0.15   --ceiling-tag 10.0.17   --ceiling-mode branch   --repos-file repos.txt   --workdir .   --format md

# 3) Debug mode (prints tag choices and commit subjects per repo)
./zimbra_tag_delta.py ... --debug
```

### Picking the right knobs

- `--version` (required): base “you’re running” version.  
  Base tag becomes nearest ≤ this. Example: if repo has tags `10.0.13, 10.0.15` and you pass `10.0.14`, base=**10.0.13**.

- `--ceiling-tag`: upper bound you care about (often one patch above).  
  Target becomes nearest ≤ this. If the repo is already at that same tag, there’s no diff.

- `--ceiling-mode`:
  - `skip`: if no tag ≤ ceiling exists after the base, we **skip** (don’t look at branches). Use this when you want *only* tagged deltas.
  - `branch`: if no suitable tag exists, compare to the **release/support/hotfix** branch tip. Use this when tags lag but fixes live on release branches.

- `--branches`: branch fallback order when `--ceiling-mode branch` (default excludes `main/master` to avoid dev partials). You can override:
  ```bash
  --branches "origin/release/{line}" "origin/support/{line}" "origin/hotfix/{line}"
  ```

- `--debug`: prints per-repo reasoning (all tags found, base/target selected, commit list). Great for sanity checks.

## Interpreting scores

Each commit gets a score:

- +3 if subject mentions security-ish terms (e.g., `CVE-`, `security`, `XSS`, `CSRF`, `RCE`, `auth`, `cookie`, `token`, `TLS`, etc.)
- +2 for **file paths** that touch auth/session/parsers/proxy/MTA/Jetty/SSL/etc.
- +1 if any changed file looks like code (`.java`, `.jsp`, `.js`, `.c`…)
- Tiny extra bump if any “interesting” file was touched.

Use the **“Top suspects”** column in the Markdown to jump to likely security-relevant commits first.

## Examples

### Example A — Only tagged deltas
> Show what changed between the build you have and what’s tagged up to 10.0.17. Skip repos without new tags.

```bash
./zimbra_tag_delta.py   --version 10.0.15   --ceiling-tag 10.0.17   --ceiling-mode skip   --repos-file repos.txt   --workdir .   --format md
```

### Example B — Include branch-only changes
> If tags lag in some repos, include commits on `origin/release/{line}`.

```bash
./zimbra_tag_delta.py   --version 10.0.15   --ceiling-tag 10.0.17   --ceiling-mode branch   --repos-file repos.txt   --workdir .   --format md
```

### Example C — Troubleshoot a repo
```bash
./zimbra_tag_delta.py ... --debug
# Look for:
#   All tags (...)         ← what exists in that repo
#   Base tag (<= 10.0.15): ← nearest ≤ base
#   Target tag (<= 10.0.17): ← nearest ≤ ceiling OR branch fallback line
#   FOUND: N commits ...    ← verify there’s a range
```

## What your sample output shows

- `zm-build`: 10.0.13 → 10.0.16, one commit (“add zmacl…”), flagged as suspicious because it touches lots of installer/runtime bits (IMAP, SSL, proxy, etc.).
- `zm-core-utils`: 10.0.9 → 10.0.16, one commit (“add zmacl”) with a big score thanks to many `src/bin/*` and MTA/IMAP/TLS utilities.
- `zm-jython`: 10.0.0 → 10.0.16, one commit (“add zmacl”), smaller but still notable.

That means: those repos have **newer work** between your base and ceiling—even if some other repos didn’t.

## Tips & guardrails

- If a repo shows **no tag ≤ ceiling newer than base** and you used `--ceiling-mode skip`, you’ll see nothing for that repo—that’s expected.
- To avoid pulling in unstable work, leave `main/master` out of `--branches`.
- If you want **only** tag-to-tag diffs, keep `--ceiling-mode skip`. If you want a stronger signal (even when tags lag), use `branch`.

## Troubleshooting

- **No output anywhere**: run with `--debug` and verify the base/target tag lines. Often the base and target resolve to the same tag (e.g., repo hasn’t moved).
- **Python 3.6 error about `text=`**: you’re using this script already; it uses `universal_newlines=True`.
- **Weird missing repos**: make sure `repos.txt` matches folder names in `--workdir`.
