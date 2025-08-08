#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import argparse, json, os, re, subprocess, sys
from datetime import datetime
from pathlib import Path

TOOL_VERSION = "1.2.1"

# Default branch candidates (keep master/main out unless you pass them)
DEFAULT_BRANCHES = [
    "origin/release/{line}",
    "origin/support/{line}",
    "origin/hotfix/{line}",
]

# Heuristics
SECURITY_SUBJECT_RE = re.compile(
    r"(CVE-|security|vuln|sanitize|escape|validate|xss|csrf|xxe|rce|ssrf|sqli|auth|"
    r"login|session|cookie|token|password|privilege|dos|overflow|jetty|proxy|nginx|tls|ssl)",
    re.IGNORECASE,
)
SECURITY_FILE_RE = re.compile(
    r"(auth|login|session|cookie|csrf|xss|escape|sanitize|imap|smtp|lmtp|sieve|parser|upload|"
    r"attachment|mime|proxy|jetty|nginx|ssl|tls|crypto|sasl|clamav|spamassassin|jackson|netty|guava|log4j|openssl)",
    re.IGNORECASE,
)
CODE_EXT_RE = re.compile(r"\.(java|jsp|js|ts|c|cc|cpp|go|rb|py|xml|groovy|scala|kt)$", re.IGNORECASE)

MAX_COMMITS_ANALYZED = 800
NUMS_RE = re.compile(r"\d+")

# ---------------- subprocess helper (Py3.6 safe) ----------------
def run(cmd, cwd=None):
    p = subprocess.run(
        cmd, cwd=cwd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True, check=False
    )
    return (p.stdout or "").strip(), (p.stderr or "").strip(), p.returncode

# ---------------- version/tag helpers ----------------
def parse_version_tuple(vstr):
    m = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)\s*$", vstr)
    if not m:
        raise ValueError("must be major.minor.patch (e.g., 10.0.16)")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

def line_of(tup):
    return "{}.{}".format(tup[0], tup[1])

def tag_nums_for_line(tag, major, minor):
    nums = [int(n) for n in NUMS_RE.findall(tag)]
    if len(nums) < 2: return None
    if nums[0] != major or nums[1] != minor: return None
    while len(nums) < 3: nums.append(0)
    return tuple(nums[:3])

def nearest_le_tag(tags, major, minor, ceiling_tuple):
    best = None; best_nums = None
    for t in tags:
        nums = tag_nums_for_line(t, major, minor)
        if not nums: continue
        if nums <= ceiling_tuple:
            if best_nums is None or nums > best_nums:
                best, best_nums = t, nums
    return best, best_nums

def list_tags(repo_dir):
    out, _, _ = run(["git", "tag", "--list"], cwd=repo_dir)
    tags = [t.strip() for t in out.splitlines() if t.strip()]
    def key(t):
        n = [int(x) for x in NUMS_RE.findall(t)]
        return tuple(n)
    return sorted(tags, key=key)

def ref_exists(repo_dir, ref):
    _, _, rc = run(["git", "rev-parse", "--verify", "--quiet", ref], cwd=repo_dir)
    return rc == 0

def pick_branch(repo_dir, patterns, version_line):
    for pat in patterns:
        ref = pat.format(line=version_line)
        if ref_exists(repo_dir, ref): return ref
    return None

# ---------------- git ops ----------------
def fetch_refs(repo_dir, verbose=False):
    run(["git", "fetch", "--all", "--prune"], cwd=repo_dir)
    run(["git", "fetch", "--tags", "--force"], cwd=repo_dir)
    if verbose: print("  [fetched tags/branches]")

def rev_parse(repo_dir, ref):
    out, _, _ = run(["git", "rev-parse", ref], cwd=repo_dir)
    return out.strip()

def commits_between(repo_dir, base_ref, target_ref):
    out, _, _ = run(["git", "log", "--no-merges", "--pretty=%h\t%s", base_ref+".."+target_ref, "--"], cwd=repo_dir)
    return [ln for ln in out.splitlines() if ln.strip()]

def files_touched(repo_dir, full_sha):
    out, _, _ = run(["git", "show", "--name-only", "--pretty=format:", full_sha], cwd=repo_dir)
    return [f for f in out.splitlines() if f.strip()]

def commit_score(subject, files):
    score = 0
    if SECURITY_SUBJECT_RE.search(subject): score += 3
    hit_file = False
    for f in files:
        if SECURITY_FILE_RE.search(f): score += 2; hit_file = True
        if CODE_EXT_RE.search(f): score += 1
    if hit_file and score < 3: score += 1
    return score

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser(description="Zimbra tag delta: nearest ≤ base tag → capped target (tag ≤ ceiling or branch).")
    ap.add_argument("--version", required=True, help="Base version (major.minor.patch), e.g., 10.0.15")
    ap.add_argument("--ceiling-tag", help="Ceiling (major.minor.patch). Default: base+1 patch")
    ap.add_argument("--ceiling-mode", choices=["skip","branch"], required=True,
                    help="If no tag ≤ ceiling exists after base: skip or fall back to branch tip")
    ap.add_argument("--repos-file", required=True, help="File with repo names (one per line)")
    ap.add_argument("--workdir", default=".", help="Directory holding repos (default: .)")
    ap.add_argument("--branches", nargs="*", default=DEFAULT_BRANCHES,
                    help="Branch fallback patterns; {line} placeholder allowed")
    ap.add_argument("--out", default="./tag_delta_out", help="Output directory (default: ./tag_delta_out)")
    ap.add_argument("--format", choices=["csv","md"], default="md", help="Also write a Markdown rollup (default md)")
    ap.add_argument("--debug", action="store_true", help="Verbose per-repo reasoning & commit list")
    ap.add_argument("-V","--tool-version", action="store_true", help="Print tool version and exit")
    args = ap.parse_args()

    if args.tool_version:
        print("zimbra_tag_delta.py", TOOL_VERSION); sys.exit(0)

    try:
        base_tuple = parse_version_tuple(args.version)
    except ValueError as e:
        print("Error parsing --version:", e, file=sys.stderr); sys.exit(2)

    if args.ceiling_tag:
        try:
            ceil_tuple = parse_version_tuple(args.ceiling_tag)
        except ValueError as e:
            print("Error parsing --ceiling-tag:", e, file=sys.stderr); sys.exit(2)
    else:
        ceil_tuple = (base_tuple[0], base_tuple[1], base_tuple[2] + 1)

    version_line = line_of(base_tuple)

    # load repos
    with open(args.repos_file, "r", encoding="utf-8") as f:
        repos = [ln.strip().split("/")[-1] for ln in f if ln.strip() and not ln.strip().startswith("#")]
    # de-dupe preserve order
    seen=set(); repos = [r for r in repos if not (r in seen or seen.add(r))]

    outdir = Path(args.out); outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    line_tag = version_line

    summary_rows = []
    manifest_rows = []
    details = {}

    changed_repos = 0
    analyzed_repos = 0

    for repo in repos:
        repo_dir = Path(args.workdir) / repo
        if args.debug: print("\n=== {} ===".format(repo))
        if not repo_dir.exists():
            if args.debug: print("SKIP: not cloned at {}".format(repo_dir))
            continue

        analyzed_repos += 1
        fetch_refs(repo_dir, verbose=args.debug)

        tags = list_tags(repo_dir)
        if args.debug: print("All tags ({}): {}".format(len(tags), ", ".join(tags)))

        base_tag, base_nums = nearest_le_tag(tags, base_tuple[0], base_tuple[1], base_tuple)
        if args.debug: print("Base tag (<= {}.{}.{}): {}".format(*base_tuple, base_tag))
        if not base_tag:
            if args.debug: print("SKIP: no base tag for line {}".format(version_line))
            continue

        target_ref = None
        target_is_tag = False

        tgt_tag, tgt_nums = nearest_le_tag(tags, base_tuple[0], base_tuple[1], ceil_tuple)
        if tgt_tag:
            target_ref = tgt_tag; target_is_tag = True
            if args.debug: print("Target tag (<= {}.{}.{}): {}".format(*ceil_tuple, target_ref))
        else:
            if args.ceiling_mode == "branch":
                b = pick_branch(repo_dir, args.branches, version_line)
                if b:
                    target_ref = b; target_is_tag = False
                    if args.debug: print("Target branch fallback:", target_ref)
            if not target_ref:
                if args.debug: print("SKIP: no target tag ≤ ceiling and ceiling-mode=skip")
                continue

        base_sha = rev_parse(repo_dir, base_tag)
        target_sha = rev_parse(repo_dir, target_ref)
        if base_sha == target_sha:
            if args.debug: print("SKIP: base == target ({} == {})".format(base_tag, target_ref))
            continue

        commits = commits_between(repo_dir, base_tag, target_ref)
        if args.debug:
            if commits:
                print("FOUND: {} commits between {}..{}".format(len(commits), base_tag, target_ref))
                for ln in commits[:40]: print("  "+ln)
                if len(commits) > 40: print("  ... ({} more)".format(len(commits)-40))
            else:
                print("No commits between {}..{}".format(base_tag, target_ref))

        suspicious_count = 0
        scored = []
        for ln in commits[:MAX_COMMITS_ANALYZED]:
            try:
                short, subject = ln.split("\t", 1)
            except ValueError:
                short, subject = ln, ""
            full_sha = rev_parse(repo_dir, short) or short
            files = files_touched(repo_dir, full_sha)
            sc = commit_score(subject, files)
            if sc > 0: suspicious_count += 1
            scored.append({"sha": full_sha, "short": short, "subject": subject, "score": sc, "files": files[:200]})

        top3 = sorted(scored, key=lambda x: x["score"], reverse=True)[:3]

        summary_rows.append({
            "repo": repo, "base_tag": base_tag, "base_sha": base_sha,
            "target_ref": target_ref, "target_sha": target_sha,
            "commit_count": len(commits), "suspicious_commits": suspicious_count,
            "top": [{"short": t["short"], "score": t["score"], "subject": t["subject"]} for t in top3],
        })
        manifest_rows.append({
            "repo": repo, "base_ref": base_tag, "base_sha": base_sha,
            "target_ref": target_ref, "target_sha": target_sha,
        })
        details[repo] = {
            "base": {"tag": base_tag, "sha": base_sha},
            "target": {"ref": target_ref, "sha": target_sha, "is_tag": target_is_tag},
            "commits_analyzed": len(scored),
            "suspicious_commits": suspicious_count,
            "commits": scored,
        }

        changed_repos += 1
        # ALWAYS print a concise line when not in --debug (so it never looks like “immediate return”)
        if not args.debug:
            print("[{}] {} → {} | commits: {} | suspicious: {}".format(
                repo, base_tag, target_ref, len(commits), suspicious_count
            ))

    # Sort & write outputs even if nothing changed
    summary_rows.sort(key=lambda r: (r["suspicious_commits"], r["commit_count"]), reverse=True)

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    summary_csv = outdir / ("tag_delta_summary_{}_{}.csv".format(line_of(base_tuple), ts))
    manifest_csv = outdir / ("tag_delta_manifest_{}_{}.csv".format(line_of(base_tuple), ts))
    details_json = outdir / ("tag_delta_details_{}_{}.json".format(line_of(base_tuple), ts))
    md_path = outdir / ("tag_delta_report_{}_{}.md".format(line_of(base_tuple), ts)) if args.format == "md" else None

    with summary_csv.open("w", encoding="utf-8") as f:
        f.write("repo,base_tag,base_sha,target_ref,target_sha,commit_count,suspicious_commits\n")
        for r in summary_rows:
            f.write("{repo},{base_tag},{base_sha},{target_ref},{target_sha},{commit_count},{suspicious_commits}\n".format(**r))

    with manifest_csv.open("w", encoding="utf-8") as f:
        f.write("repo,base_ref,base_sha,target_ref,target_sha\n")
        for r in manifest_rows:
            f.write("{repo},{base_ref},{base_sha},{target_ref},{target_sha}\n".format(**r))

    with details_json.open("w", encoding="utf-8") as f:
        json.dump(details, f, indent=2)

    if md_path:
        with md_path.open("w", encoding="utf-8") as f:
            f.write("# Zimbra Tag Delta — {} — {}\n\n".format(line_tag, ts))
            f.write("| Repo | Base → Target | Commits | Suspicious | Top suspects |\n|---|---|---:|---:|---|\n")
            for r in summary_rows:
                tops = r.get("top", [])
                top_txt = "<br/>".join("`{}` [{}] {}".format(t["short"], t["score"], t["subject"]) for t in tops) if tops else ""
                f.write("| `{}` | `{} → {}` | {} | {} | {} |\n".format(
                    r["repo"], r["base_tag"], r["target_ref"], r["commit_count"], r["suspicious_commits"], top_txt
                ))
            f.write("\n<sub>See CSV/JSON for exact SHAs and per-commit file lists.</sub>\n")

    # Always print a final summary
    print("\nAnalyzed repos: {} | Repos with changes: {}".format(analyzed_repos, changed_repos))
    print("Wrote:\n  {}\n  {}\n  {}".format(summary_csv, manifest_csv, details_json))
    if md_path: print("  {}".format(md_path))

if __name__ == "__main__":
    main()

