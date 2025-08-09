#!/usr/bin/env perl
use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use POSIX qw(strftime);
use File::Spec;
use File::Path qw(make_path);
use JSON::PP;
use Cwd qw(abs_path);

# ---------------- Config / Heuristics ----------------
my $TOOL_VERSION = "1.2.1-perl";

my @DEFAULT_BRANCHES = (
  "origin/release/{line}",
  "origin/support/{line}",
  "origin/hotfix/{line}",
);

my $SECURITY_SUBJECT_RE = qr/(CVE-|security|vuln|sanitize|escape|validate|xss|csrf|xxe|rce|ssrf|sqli|auth|login|session|cookie|token|password|privilege|dos|overflow|jetty|proxy|nginx|tls|ssl)/i;
my $SECURITY_FILE_RE    = qr/(auth|login|session|cookie|csrf|xss|escape|sanitize|imap|smtp|lmtp|sieve|parser|upload|attachment|mime|proxy|jetty|nginx|ssl|tls|crypto|sasl|clamav|spamassassin|jackson|netty|guava|log4j|openssl)/i;
my $CODE_EXT_RE         = qr/\.(java|jsp|js|ts|c|cc|cpp|go|rb|py|xml|groovy|scala|kt)$/i;

my $MAX_COMMITS_ANALYZED = 800;

# ---------------- CLI ----------------
my ($version, $ceiling_tag, $ceiling_mode, $repos_file, $workdir, @branches, $outdir, $format, $debug, $print_tool_version);
$workdir = ".";
$outdir  = "./tag_delta_out";
$format  = "md";

GetOptions(
  "version=s"      => \$version,
  "ceiling-tag=s"  => \$ceiling_tag,
  "ceiling-mode=s" => \$ceiling_mode,  # skip | branch
  "repos-file=s"   => \$repos_file,
  "workdir=s"      => \$workdir,
  "branches=s@"    => \@branches,      # allow multiple
  "out=s"          => \$outdir,
  "format=s"       => \$format,        # csv | md
  "debug"          => \$debug,
  "tool-version|V" => \$print_tool_version,
) or die "Error parsing options. Try --help\n";

if ($print_tool_version) {
  print "zimbra_tag_delta.pl $TOOL_VERSION\n";
  exit 0;
}

sub usage {
  print <<"USAGE";
Usage:
  $0 --version <X.Y.Z> --ceiling-mode {skip|branch} --repos-file repos.txt [options]

Required:
  --version X.Y.Z          Base version (e.g., 10.0.15)
  --ceiling-mode MODE      'skip' (tag-to-tag only) or 'branch' (fallback to release branch tip)

Common:
  --ceiling-tag X.Y.Z      Upper bound tag (default: base + 1 patch)
  --repos-file FILE        List of repo dirs under --workdir (one per line)
  --workdir DIR            Root dir that already contains the repos (default: .)
  --branches PATTERN...    Branch fallback patterns (default: release/support/hotfix line)
  --out DIR                Output dir (default: ./tag_delta_out)
  --format md|csv          Also write Markdown rollup if 'md' (CSV/JSON always written)
  --debug                  Verbose per-repo reasoning
  -V, --tool-version       Print tool version and exit
USAGE
  exit 2;
}

usage() unless defined $version && defined $ceiling_mode && defined $repos_file;
die "--ceiling-mode must be 'skip' or 'branch'\n" unless $ceiling_mode eq 'skip' || $ceiling_mode eq 'branch';

@branches = @DEFAULT_BRANCHES unless @branches && @branches > 0;

# ---------------- Helpers ----------------
sub parse_version_tuple {
  my ($vstr) = @_;
  die "--version/--ceiling-tag must be major.minor.patch (e.g., 10.0.16)\n"
    unless $vstr =~ /^\s*(\d+)\.(\d+)\.(\d+)\s*$/;
  return ($1+0, $2+0, $3+0);
}

my ($base_major, $base_minor, $base_patch) = parse_version_tuple($version);
my ($ceil_major, $ceil_minor, $ceil_patch) =
  defined $ceiling_tag ? parse_version_tuple($ceiling_tag) : ($base_major, $base_minor, $base_patch + 1);

my $version_line = "$base_major.$base_minor";

sub run_git {
  my ($repo_dir, @cmd) = @_;
  my $old = Cwd::getcwd();
  chdir $repo_dir or return ("", "chdir failed", 1);
  my $cmd_str = join(" ", @cmd);
  my $out = qx{$cmd_str 2>&1};
  my $rc = $? >> 8;
  chdir $old;
  my $err = ($rc != 0) ? $out : "";
  $out = ($rc == 0) ? $out : "";
  chomp $out;
  return ($out, $err, $rc);
}

sub fetch_refs {
  my ($repo_dir) = @_;
  run_git($repo_dir, "git fetch --all --prune >/dev/null");
  run_git($repo_dir, "git fetch --tags --force >/dev/null");
  print "  [fetched tags/branches]\n" if $debug;
}

sub list_tags {
  my ($repo_dir) = @_;
  my ($out, $err, $rc) = run_git($repo_dir, "git tag --list");
  return [] if $rc != 0;
  my @tags = grep { $_ ne "" } split /\n/, $out;

  # Numeric-ish sort by extracting numbers
  my @sorted = sort {
    my @an = ($a =~ /(\d+)/g);
    my @bn = ($b =~ /(\d+)/g);
    my $i = 0;
    while ($i <= $#an || $i <= $#bn) {
      my $av = $i <= $#an ? $an[$i] : -1;
      my $bv = $i <= $#bn ? $bn[$i] : -1;
      return $av <=> $bv if $av != $bv;
      $i++;
    }
    return lc($a) cmp lc($b);
  } @tags;

  return \@sorted;
}

sub tag_nums_for_line {
  my ($tag, $maj, $min) = @_;
  my @nums = ($tag =~ /(\d+)/g);
  return undef if @nums < 2;
  return undef if $nums[0] != $maj || $nums[1] != $min;
  push @nums, 0 while @nums < 3;
  return [ @nums[0..2] ];
}

sub le_tuple {
  my ($a, $b) = @_; # arrays [maj,min,patch]
  return 1 if ($a->[0] < $b->[0]) || ($a->[0] == $b->[0] && $a->[1] <  $b->[1]) ||
              ($a->[0] == $b->[0] && $a->[1] == $b->[1] && $a->[2] <= $b->[2]);
  return 0;
}

sub tuple_cmp {
  my ($a, $b) = @_;
  return ($a->[0] <=> $b->[0]) || ($a->[1] <=> $b->[1]) || ($a->[2] <=> $b->[2]);
}

sub nearest_le_tag {
  my ($tags, $maj, $min, $ceil_tuple) = @_;
  my $best; my $best_nums;
  foreach my $t (@$tags) {
    my $nums = tag_nums_for_line($t, $maj, $min) or next;
    if (le_tuple($nums, $ceil_tuple)) {
      if (!defined $best_nums || tuple_cmp($nums, $best_nums) > 0) {
        $best = $t; $best_nums = $nums;
      }
    }
  }
  return ($best, $best_nums);
}

sub ref_exists {
  my ($repo_dir, $ref) = @_;
  my ($out, $err, $rc) = run_git($repo_dir, "git rev-parse --verify --quiet $ref");
  return $rc == 0;
}

sub pick_branch {
  my ($repo_dir, $patterns, $line) = @_;
  foreach my $pat (@$patterns) {
    my $ref = $pat; $ref =~ s/\{line\}/$line/g;
    return $ref if ref_exists($repo_dir, $ref);
  }
  return undef;
}

sub rev_parse {
  my ($repo_dir, $ref) = @_;
  my ($out, $err, $rc) = run_git($repo_dir, "git rev-parse $ref");
  return $rc == 0 ? $out : "";
}

sub commits_between {
  my ($repo_dir, $base_ref, $target_ref) = @_;
  my $cmd = "git log --no-merges --pretty=format:%H%x00%s $base_ref..$target_ref --";
  my ($out, $err, $rc) = run_git($repo_dir, $cmd);
  return [] if $rc != 0;
  my @lines = grep { $_ ne "" } split /\n/, $out;
  return \@lines;
}

sub files_touched {
  my ($repo_dir, $sha) = @_;
  my ($out, $err, $rc) = run_git($repo_dir, "git show --name-only --pretty=format: $sha");
  return [] if $rc != 0;
  my @files = grep { $_ ne "" } split /\n/, $out;
  return \@files;
}

sub commit_score {
  my ($subject, $files) = @_;
  my $score = 0;
  $score += 3 if $subject =~ $SECURITY_SUBJECT_RE;
  my $hit_file = 0;
  foreach my $f (@$files) {
    if ($f =~ $SECURITY_FILE_RE) { $score += 2; $hit_file = 1; }
    if ($f =~ $CODE_EXT_RE)      { $score += 1; }
  }
  $score += 1 if $hit_file && $score < 3;
  return $score;
}

# ---------------- Load repos ----------------
open my $RF, "<", $repos_file or die "Cannot open --repos-file $repos_file: $!\n";
my @repos;
my %seen;
while (my $ln = <$RF>) {
  chomp $ln;
  next if $ln =~ /^\s*$/ || $ln =~ /^\s*#/;
  $ln =~ s/.*\///; # keep last path part
  next if $seen{$ln}++;
  push @repos, $ln;
}
close $RF;

# ---------------- Outputs ----------------
make_path($outdir);
my $ts = strftime("%Y%m%dT%H%M%SZ", gmtime());
my $line_tag = "$base_major.$base_minor";

my $summary_csv  = File::Spec->catfile($outdir, "tag_delta_summary_${line_tag}_$ts.csv");
my $manifest_csv = File::Spec->catfile($outdir, "tag_delta_manifest_${line_tag}_$ts.csv");
my $details_json = File::Spec->catfile($outdir, "tag_delta_details_${line_tag}_$ts.json");
my $md_path      = $format eq 'md' ? File::Spec->catfile($outdir, "tag_delta_report_${line_tag}_$ts.md") : undef;

open my $SUM, ">", $summary_csv or die "Write $summary_csv: $!";
print $SUM "repo,base_tag,base_sha,target_ref,target_sha,commit_count,suspicious_commits\n";

open my $MAN, ">", $manifest_csv or die "Write $manifest_csv: $!";
print $MAN "repo,base_ref,base_sha,target_ref,target_sha\n";

my %details;
my @summary_rows; # for MD sorting
my $analyzed_repos = 0;
my $changed_repos  = 0;

# ---------------- Main loop ----------------
foreach my $repo (@repos) {
  my $repo_dir = File::Spec->catdir($workdir, $repo);
  print "\n=== $repo ===\n" if $debug;
  unless (-d $repo_dir) {
    print "SKIP: not cloned at $repo_dir\n" if $debug;
    next;
  }

  $analyzed_repos++;
  fetch_refs($repo_dir) if $debug; # always fetch, but print only in debug
  run_git($repo_dir, "git fetch --tags --force >/dev/null"); # ensure tags even if not debug

  my $tags = list_tags($repo_dir);
  print "All tags (@$tags)\n" if $debug && @$tags;

  my ($base_tag, $base_nums) = nearest_le_tag($tags, $base_major, $base_minor, [$base_major,$base_minor,$base_patch]);
  print "Base tag (<= $base_major.$base_minor.$base_patch): " . (defined $base_tag ? $base_tag : "(none)") . "\n" if $debug;
  next unless defined $base_tag;

  my $target_ref;
  my $target_is_tag = 0;
  my ($tgt_tag, $tgt_nums) = nearest_le_tag($tags, $base_major, $base_minor, [$ceil_major,$ceil_minor,$ceil_patch]);
  if (defined $tgt_tag) {
    $target_ref = $tgt_tag; $target_is_tag = 1;
    print "Target tag (<= $ceil_major.$ceil_minor.$ceil_patch): $target_ref\n" if $debug;
  } else {
    if ($ceiling_mode eq 'branch') {
      my $picked = pick_branch($repo_dir, \@branches, $version_line);
      if ($picked) {
        $target_ref = $picked; $target_is_tag = 0;
        print "Target branch fallback: $target_ref\n" if $debug;
      }
    }
    unless ($target_ref) {
      print "SKIP: no target tag ≤ ceiling and ceiling-mode=skip\n" if $debug;
      next;
    }
  }

  my $base_sha   = rev_parse($repo_dir, $base_tag);
  my $target_sha = rev_parse($repo_dir, $target_ref);

  if ($base_sha eq $target_sha) {
    print "SKIP: base == target ($base_tag == $target_ref)\n" if $debug;
    next;
  }

  my $commits = commits_between($repo_dir, $base_tag, $target_ref);
  if ($debug) {
    if (@$commits) {
      print "FOUND: " . scalar(@$commits) . " commits between $base_tag..$target_ref\n";
      my $show = 0;
      foreach my $ln (@$commits) {
        print "  $ln\n";
        last if (++$show >= 40);
      }
      print "  ... (" . (scalar(@$commits) - 40) . " more)\n" if @$commits > 40;
    } else {
      print "No commits between $base_tag..$target_ref\n";
    }
  }

  my $suspicious_count = 0;
  my @scored;
  my $count = 0;
  foreach my $ln (@$commits) {
    last if ++$count > $MAX_COMMITS_ANALYZED;
    my ($full_sha, $subject) = split /\0/, $ln, 2;   # NUL-delimited
    $subject = "" unless defined $subject;
    my $short = substr($full_sha, 0, 9);             # derive short from full
    my $files = files_touched($repo_dir, $full_sha);
    my $score = commit_score($subject, $files);
    $suspicious_count++ if $score > 0;
    push @scored, {
      sha     => $full_sha,
      short   => $short,
      subject => $subject,
      score   => $score,
      files   => [ @$files[0..($#$files < 199 ? $#$files : 199)] ],
    };
  }

  # top 3
  my @top = sort { $b->{score} <=> $a->{score} } @scored;
  splice(@top, 3) if @top > 3;

  # Write row aggregates
  print $SUM join(",", map { _csv($_) } ($repo,$base_tag,$base_sha,$target_ref,$target_sha, scalar(@$commits), $suspicious_count))."\n";
  print $MAN join(",", map { _csv($_) } ($repo,$base_tag,$base_sha,$target_ref,$target_sha))."\n";

  $details{$repo} = {
    base => { tag => $base_tag, sha => $base_sha },
    target => { ref => $target_ref, sha => $target_sha, is_tag => $target_is_tag ? JSON::PP::true : JSON::PP::false },
    commits_analyzed => scalar(@scored),
    suspicious_commits => $suspicious_count,
    commits => \@scored,
  };

  push @summary_rows, {
    repo => $repo, base_tag => $base_tag, base_sha => $base_sha,
    target_ref => $target_ref, target_sha => $target_sha,
    commit_count => scalar(@$commits),
    suspicious_commits => $suspicious_count,
    top => [ map { { short => $_->{short}, score => $_->{score}, subject => $_->{subject} } } @top ],
  };

  $changed_repos++;

  # concise line when not debug
  if (!$debug) {
    print "[$repo] $base_tag → $target_ref | commits: ".scalar(@$commits)." | suspicious: $suspicious_count\n";
  }
}

close $SUM;
close $MAN;

# Sort for MD
@summary_rows = sort {
  ($b->{suspicious_commits} <=> $a->{suspicious_commits}) || ($b->{commit_count} <=> $a->{commit_count})
} @summary_rows;

# details JSON
open my $DJ, ">", $details_json or die "Write $details_json: $!";
print $DJ JSON::PP->new->ascii->pretty->canonical->encode(\%details);
close $DJ;

# markdown
if (defined $md_path && $format eq 'md') {
  open my $MD, ">", $md_path or die "Write $md_path: $!";
  print $MD "# Zimbra Tag Delta — $version_line — $ts\n\n";
  print $MD "| Repo | Base → Target | Commits | Suspicious | Top suspects |\n|---|---|---:|---:|---|\n";
  foreach my $r (@summary_rows) {
    my $top_txt = "";
    if (@{$r->{top}}) {
      my @lines = map { sprintf("`%s` [%d] %s", $_->{short}, $_->{score}, _md_escape($_->{subject})) } @{$r->{top}};
      $top_txt = join("<br/>", @lines);
    }
    printf $MD "| `%s` | `%s → %s` | %d | %d | %s |\n",
      $r->{repo}, $r->{base_tag}, $r->{target_ref}, $r->{commit_count}, $r->{suspicious_commits}, $top_txt;
  }
  print $MD "\n<sub>See CSV/JSON for exact SHAs and per-commit file lists.</sub>\n";
  close $MD;
}

# summary to stdout
print "\nAnalyzed repos: $analyzed_repos | Repos with changes: $changed_repos\n";
print "Wrote:\n  $summary_csv\n  $manifest_csv\n  $details_json\n";
print "  $md_path\n" if defined $md_path;

exit 0;

# ---------------- utils ----------------
sub _csv {
  my ($v) = @_;
  $v = "" unless defined $v;
  if ($v =~ /[",\n]/) {
    $v =~ s/"/""/g;
    return "\"$v\"";
  }
  return $v;
}

sub _md_escape {
  my ($s) = @_;
  $s = "" unless defined $s;
  $s =~ s/\|/\\|/g;
  return $s;
}

