# Tests

Offline tests for [`generate.sh`](../generate.sh). They need no network and run in about two seconds.

```sh
sh tests/run.sh
```

## What is tested

`run.sh` runs the real, unmodified `generate.sh` with every installed awk (gawk, mawk, busybox awk) and checks:

- **Output.** The lists generated from `fixtures/` must be byte-identical to `expected/`, and a second run must produce no change.
- **Retry pass.** A feed that is an error page in the first pass and fine in the second must be recovered. The test config overrides `sleep` to swap in the good file.
- **Failure scenarios.** Each of these must make the run fail, leave the existing lists untouched and leave no temporary files behind:
  - a feed is missing
  - a feed is empty
  - a feed is an HTML page instead of data
  - a feed is below its minimum
  - DShield changed its format
  - two kinds of invalid whitelist entry
  - an entry is wider than allowed
  - a list is out of bounds
  - three kinds of invalid config: a feed tier no list uses, a list tier with no feeds, a non-numeric list bound
  - a list changed too much

## How it works

`generate.sh` reads an optional settings file named by `BLOCKLIST_CONFIG`. [`config.sh`](config.sh) uses it to:

- point the script at the fixture feeds through `FEEDS_DIR` (offline mode)
- set small minimums and list bounds that fit the fixtures
- turn off the retry delay

Each failure scenario adds a line or two to that config, for example `MIN_PREFIX_LEN=11`.

The fixtures in [`fixtures/`](fixtures) imitate each real feed format: Spamhaus CIDRs with `;` comments, DShield's tab-separated rows, ThreatFox CSV, plain IP lists and IPsum's IP/count pairs. Together they cover:

- unaligned, nested, adjacent and duplicate entries
- every reserved range
- invalid octets and prefix lengths
- addresses inside comment lines
- a range around a whitelisted IP

## Changing the generator

- **Refactoring.** The tests must keep passing unchanged.
- **Intended changes to the output.** Regenerate the expected files and review the diff before committing:

  ```sh
  sh tests/run.sh --update
  git diff tests/expected
  ```

  Every changed line in that diff should be explained by your change.

- **New behaviour.** Add the input that exercises it to a fixture. For a new way to fail, add an `expect_failure` line to `run.sh`.

## Trying out a new feed

Offline mode is also handy for checking a feed before adding it to `FEEDS`:

1. Download the feed once.
2. Write a small settings file that sets `FEEDS_DIR`, `FEEDS` and `OUTDIR`.
3. Run `BLOCKLIST_CONFIG=myconfig.sh sh generate.sh`.

The per-feed range counts it prints help you choose a sensible `min_ranges`.

## RouterOS self-test

[`routeros-selftest.rsc`](routeros-selftest.rsc) tests the two RouterOS scripts from the main README on a real router. Run it with `/import file-name=routeros-selftest.rsc`.

It reads the source of your installed `blocklist-dl` and `blocklist-diff` scripts and redirects them to a scratch address-list and scratch file. It refuses to run if any reference to `prod_blocklist` is left. It then checks:

- the normal update: keep, remove, add, CIDR entries, a first octet that continues into the next block
- a rerun and a first run
- truncated, corrupt, empty and missing files, and an unknown format version
- a rejected entry, an entry wider than /10, and a list change above the limit
- a failed download, and a real download with certificate verification

Every case also checks that the logging rule is back in its previous state.
