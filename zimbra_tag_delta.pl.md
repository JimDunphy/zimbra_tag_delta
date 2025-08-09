# Zimbra Tag Delta Script Documentation

**Author:** GPT-5
**Date:** 2025-08-09

This document serves as a clean, documented reference for the `zimbra_tag_delta` script, which identifies changes between two Git tags across multiple Zimbra repositories.

## Overview

The script compares the contents of multiple Git repositories between a base tag (determined from the `--version` parameter) and a ceiling tag (specified with `--ceiling-tag`). It is useful for:

* Identifying commits between specific versions.
* Checking what changed before a release.
* Avoiding developer branches unless explicitly requested.

## Key Features

* **Automatic nearest tag selection:** If the specified version does not exist, it finds the nearest tag less than or equal to it.
* **Flexible ceiling handling:** Control how missing ceiling tags are treated.
* **Debug mode:** Verbose output for troubleshooting.
* **Output formats:** JSON, CSV, and summary modes.

## Options

### `--version`

Specifies the version to use for the base tag. If it doesn’t exist, the nearest lower tag is used.

### `--ceiling-tag`

Specifies the upper tag limit for comparisons.

### `--ceiling-mode`

Determines behavior when the ceiling tag does not exist in a repository:

* **`skip`**: Repository is skipped if ceiling tag is missing.
* **`branch`**: Uses the repository’s branch tip instead of skipping.

### `--repos-file`

A text file listing the repositories to check.

### `--workdir`

The directory containing the repositories. Repositories must already be cloned.

### `--debug`

Enables detailed output for troubleshooting.

## Example Usage

```bash
./zimbra_tag_delta.py \
  --version 10.0.15 \
  --ceiling-tag 10.0.17 \
  --ceiling-mode skip \
  --repos-file repos.txt \
  --workdir /path/to/repos \
  --debug
```

## Notes

* For most use cases, `--ceiling-mode skip` is recommended to avoid including developer-only changes.
* Ensure repositories are cloned before running the script.
* Debug mode is essential when verifying behavior.

## Author’s Note

This version of the script was reviewed and documented by GPT-5 on 2025-08-09, with inline comments added for clarity in the codebase.

