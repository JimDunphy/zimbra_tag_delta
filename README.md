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

## Options

### `--version <major.minor.patch>` *(required)*
Base version you are currently running (or evaluating). For each repo, the script selects the **nearest tag at or below** this version in the same major.minor line.
- If the exact tag does **not** exist in a repo, the script automatically picks the **nearest lower** tag (e.g., `--version 10.0.15` will use `10.0.13` if `10.0.15` is missing but `10.0.13` exists).
- This mirrors how Zimbra’s build logic falls back to earlier tags when a repo skips versions.

**Example**
```bash
--version 10.0.15
```

---

### `--ceiling-tag <major.minor.patch>`
Upper bound for the comparison. For each repo, the script selects the **nearest tag at or below** this ceiling within the same major.minor line.
- This prevents pulling in work beyond the ceiling (e.g., unrelated development for the next train).

**Example**
```bash
--ceiling-tag 10.0.17
```

If omitted, the effective default ceiling is **one patch above** `--version`.

---

### `--ceiling-mode {skip|branch}` *(required)*
What to do if a repo has **no tag at or below** the specified `--ceiling-tag` that is newer than the base:
- **`skip`** *(recommended for most users)* – Only compare **tag-to-tag**. If the repo has no newer tag within the ceiling, it is skipped. Choose this when you only want published, reproducible tag deltas.
- **`branch`** – If no suitable tag exists, compare the base tag against the **release/support/hotfix branch tip** for that line (by default: `origin/release/{line}`, `origin/support/{line}`, `origin/hotfix/{line}`). This can reveal **untagged fixes** already merged to release branches. Avoid including `main/master` unless you know you want dev work.

**Examples**
```bash
# Only published tags (safest / most common)
--ceiling-mode skip

# Include untagged work on release branches when tags lag
--ceiling-mode branch
```

> Tip: In `branch` mode, pass `--branches` explicitly if your org uses custom branch names.

---

### `--workdir <path>`
Directory that already contains the Git clones named in `--repos-file`. The script **does not clone** repos; it operates on what’s present locally (and runs `git fetch --tags` to refresh). This keeps the tool fast and predictable and pairs well with your `build_zimbra.sh` workflow.

**Example**
```bash
--workdir /srv/zimbra-repos
```

---

### `--repos-file <file>`
Plain text file with **one repo name per line** (must match subdirectory names under `--workdir`). Lines starting with `#` are ignored.

**Example**
```text
zm-mailbox
zm-web-client
zm-core-utils
```
```bash
--repos-file repos.txt
```

---

### `--branches <patterns...>`
Branch fallback patterns used **only** when `--ceiling-mode branch` is set. Patterns may include `{line}` which expands to the `major.minor` line from `--version` (e.g., `10.0`).

**Default**
```text
origin/release/{line}
origin/support/{line}
origin/hotfix/{line}
```
> `main`/`master` are intentionally excluded by default to avoid unstable development heads. Add them only if you know you want to include those changes.

**Example**
```bash
--branches "origin/release/{line}" "origin/support/{line}" "origin/hotfix/{line}"
```

---

### `--format {csv|md}`
Also emit a Markdown rollup (`.md`) alongside CSV/JSON. CSV/JSON are always written; Markdown is optional.
```bash
--format md
```

---

### `--out <path>`
Output directory for the generated files (`tag_delta_summary_*.csv`, `tag_delta_manifest_*.csv`, `tag_delta_details_*.json`, and optional `tag_delta_report_*.md`). Defaults to `./tag_delta_out`.

```bash
--out ./reports/tag_delta
```

---

### `--debug`
Verbose processing. Prints, per repo: all tags found, selected base/target, and the first ~40 commit subjects between them. Useful to verify selection logic. Core processing and files are generated **with or without** `--debug`.

```bash
--debug
```

---

### `-V`, `--tool-version`
Print the tool’s version string and exit.

```bash
- V
```

## Typical Use Patterns

| Goal | Suggested Flags |
|------|------------------|
| **Only published tag-to-tag deltas (most users)** | `--version 10.0.15 --ceiling-tag 10.0.17 --ceiling-mode skip --repos-file repos.txt --workdir . --format md` |
| **Include untagged fixes on release branches** | `--version 10.0.15 --ceiling-tag 10.0.17 --ceiling-mode branch --branches "origin/release/{line}" "origin/support/{line}" "origin/hotfix/{line}" --repos-file repos.txt --workdir . --format md` |
| **Troubleshoot a specific repo’s selection** | Add `--debug` to either of the above to see per-repo decisions and commit list. |

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
