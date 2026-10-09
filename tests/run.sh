#!/bin/sh
# Test suite for generate.sh.
#
# Runs the real script in offline mode against the fixture feeds in
# tests/fixtures, once per available awk (gawk, mawk, busybox awk), and
# checks the output byte-for-byte against tests/expected. Then runs a set
# of failure scenarios, each of which must abort without touching the
# existing lists.
#
# Usage: sh tests/run.sh            run all tests
#        sh tests/run.sh --update   rewrite tests/expected (review the diff!)

set -u
export LC_ALL=C

TESTS_DIR=$(cd "$(dirname "$0")" && pwd)
export TESTS_DIR
GEN="$(dirname "$TESTS_DIR")/generate.sh"
EXPECTED="$TESTS_DIR/expected"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
ok()     { pass=$((pass + 1)); printf '  ok    %s\n' "$*"; }
not_ok() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$*"; }

# Put an `awk` for the given implementation first on PATH.
# Returns non-zero if that implementation is not installed.
use_awk() {
    dir="$TMP/bin-$1"
    rm -rf "$dir"
    mkdir "$dir"
    case "$1" in
        gawk|mawk)
            path=$(command -v "$1") || return 1
            ln -s "$path" "$dir/awk"
            ;;
        busybox)
            busybox awk 'BEGIN {}' 2>/dev/null || return 1
            printf '#!/bin/sh\nexec busybox awk "$@"\n' > "$dir/awk"
            chmod +x "$dir/awk"
            ;;
    esac
    AWK_PATH="$dir:$PATH"
}

# run_gen <outdir> [config line...]
# Runs generate.sh with the fixture config plus the given extra config
# lines, writing lists to <outdir> and the log to <outdir>.log.
run_gen() {
    out="$1"; shift
    mkdir -p "$out"
    {
        # shellcheck disable=SC2016  # expanded when generate.sh sources it
        echo '. "$TESTS_DIR/config.sh"'
        echo "OUTDIR=\"$out\""
        for line in "$@"; do echo "$line"; done
    } > "$out.cfg"
    BLOCKLIST_CONFIG="$out.cfg" GITHUB_ACTIONS="" GITHUB_STEP_SUMMARY="" \
        PATH="$AWK_PATH" timeout 60 sh "$GEN" > "$out.log" 2>&1
}

# expect_failure <name> <expected log message> [config line...]
# The run must fail, log the message, leave the previous lists (a copy of
# the expected output) untouched and leave no staging dir behind.
expect_failure() {
    name="$1"; msg="$2"; shift 2
    out="$TMP/$awk_name-$(echo "$name" | tr -c 'a-z0-9\n' '-')"
    mkdir -p "$out"
    cp "$EXPECTED"/* "$out/"
    if [ -n "${PREVIOUS_TXT:-}" ]; then
        printf '%s\n' "$PREVIOUS_TXT" > "$out/blocklist.txt"
    fi
    cp -R "$out" "$out.before"
    if run_gen "$out" "$@"; then
        not_ok "$name: expected failure, got success"
    elif ! grep -qF -- "$msg" "$out.log"; then
        not_ok "$name: log lacks '$msg'"
        sed 's/^/        /' "$out.log"
    elif ! diff -r "$out.before" "$out" > /dev/null; then
        not_ok "$name: existing lists were modified"
    elif [ -n "$(find "$out" -name ".generate.*")" ]; then
        not_ok "$name: staging dir left behind"
    else
        ok "$name"
    fi
}

if [ "${1:-}" = "--update" ]; then
    use_awk gawk || use_awk mawk || { echo "no awk found" >&2; exit 1; }
    if ! run_gen "$TMP/expected"; then
        cat "$TMP/expected.log"
        echo "generate.sh failed; $EXPECTED left unchanged." >&2
        exit 1
    fi
    rm -rf "$EXPECTED"
    cp -R "$TMP/expected" "$EXPECTED"
    echo "Updated $EXPECTED -- review the diff before committing."
    exit 0
fi

# Fixture variants for the failure scenarios.
mkdir "$TMP/no-cins" "$TMP/html-cins" "$TMP/dshield-drift" "$TMP/empty-cins"
cp "$TESTS_DIR"/fixtures/* "$TMP/no-cins/"
rm "$TMP/no-cins/cins"
cp "$TESTS_DIR"/fixtures/* "$TMP/html-cins/"
printf '<!DOCTYPE html>\n<html><body>Checking your browser...</body></html>\n' > "$TMP/html-cins/cins"
cp "$TESTS_DIR"/fixtures/* "$TMP/empty-cins/"
: > "$TMP/empty-cins/cins"
cp "$TESTS_DIR"/fixtures/* "$TMP/dshield-drift/"
# Netmask column moved: column 3 is no longer a prefix length.
awk -F '\t' 'BEGIN { OFS = "\t" } /^[0-9]/ { $3 = "x" } { print }' \
    "$TESTS_DIR/fixtures/dshield" > "$TMP/dshield-drift/dshield"

ran=0
for awk_name in gawk mawk busybox; do
    if ! use_awk "$awk_name"; then
        echo "== $awk_name: not installed, skipped"
        continue
    fi
    ran=$((ran + 1))
    echo "== $awk_name"

    out="$TMP/$awk_name-golden"
    if ! run_gen "$out"; then
        not_ok "golden: generate.sh failed"
        sed 's/^/        /' "$out.log"
    elif ! diff -r "$EXPECTED" "$out" > "$out.diff"; then
        not_ok "golden: output differs from tests/expected"
        head -n 20 "$out.diff" | sed 's/^/        /'
    else
        ok "golden: output matches tests/expected"
    fi

    if run_gen "$out" && grep -q '(0% change)' "$out.log" &&
        diff -r "$EXPECTED" "$out" > /dev/null; then
        ok "rerun: identical output, 0% change"
    else
        not_ok "rerun: second run differs or failed"
    fi

    # The feed is an error page in the first pass and fixed by the time of
    # the second; the sourced config overrides `sleep` to make the swap.
    out="$TMP/$awk_name-retry"
    rm -rf "$out.feeds"
    cp -R "$TMP/html-cins" "$out.feeds"
    if run_gen "$out" "FEEDS_DIR=\"$out.feeds\"" \
            "sleep() { cp \"\$TESTS_DIR/fixtures/cins\" \"$out.feeds/cins\"; }" &&
        grep -q 'Retrying cins' "$out.log" &&
        diff -r "$EXPECTED" "$out" > /dev/null; then
        ok "retry pass: recovers a feed that was bad in the first pass"
    else
        not_ok "retry pass: did not recover"
        sed 's/^/        /' "$out.log"
    fi

    expect_failure "missing feed" "Fixture CINS: download failed" \
        "FEEDS_DIR=\"$TMP/no-cins\""
    expect_failure "empty feed" "Fixture CINS: download failed: empty response" \
        "FEEDS_DIR=\"$TMP/empty-cins\""
    expect_failure "HTML instead of feed" "Fixture CINS: only 0 ranges (minimum 3)" \
        "FEEDS_DIR=\"$TMP/html-cins\""
    expect_failure "feed below minimum" "Fixture DROP: only 9 ranges (minimum 50)" \
        "FEEDS=\$(printf '%s\n' \"\$FEEDS\" | sed 's/^s|drop|5|/s|drop|50|/')"
    expect_failure "DShield format drift" "Fixture DShield: unexpected format" \
        "FEEDS_DIR=\"$TMP/dshield-drift\""
    expect_failure "invalid whitelist prefix" "prefix length must be 16..32" \
        'WHITELIST="1.2.3.5/40"'
    expect_failure "whitelist with host bits" "host bits set" \
        'WHITELIST="52.113.194.132/24"'
    expect_failure "entry too wide" "entry 45.0.0.0/10 is wider than /11" \
        'MIN_PREFIX_LEN=11'
    expect_failure "list above bounds" "outside the expected 10..20" \
        "LISTS=\$(printf '%s\n' \"\$LISTS\" | sed 's/|100\$/|20/')"
    expect_failure "feed tier not in any list" "has tier 'x', which no list uses" \
        "FEEDS=\$(printf '%s\n' \"\$FEEDS\" | sed 's/^xl|/x|/')"
    expect_failure "list tier without feeds" "tier 'xxl' is used by a list but has no feeds" \
        "LISTS=\$(printf '%s\n%s\n' \"\$LISTS\" 'blocklist_x|blocklist_ga_x|s xxl|10|100')"
    expect_failure "non-numeric list bound" "list 'blocklist' needs numeric bounds" \
        "LISTS=\$(printf '%s\n' \"\$LISTS\" | sed 's/^blocklist|blocklist_ga|s|10|100/blocklist|blocklist_ga|s|10|1k/')"
    PREVIOUS_TXT="1.1.1.1"
    expect_failure "change above limit" "changed by" ""
    PREVIOUS_TXT=""
done

echo
echo "$pass passed, $fail failed ($ran awk implementation(s))"
[ "$ran" -gt 0 ] && [ "$fail" -eq 0 ]
