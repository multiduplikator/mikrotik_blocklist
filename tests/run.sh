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
# Block size the fixture config uses for the .json lists.
JSON_TEST_BLOCK=$(sed -n 's/^JSON_BLOCK=//p' "$TESTS_DIR/config.sh")
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

# decode_json <file.json> <block size>
# Prints the entries of a .json list, one per line, reading it the way the
# RouterOS script does: fixed-size blocks, each parsed on its own.
decode_json() {
    awk -v B="$2" '
    { s = s $0 }
    END {
        for (off = 1; off <= length(s); off += B) {
            c = substr(s, off, B)
            depth = 0; key = ""
            while (match(c, /"[^"]*"|[{}:,]|[0-9]+/)) {
                t = substr(c, RSTART, RLENGTH); c = substr(c, RSTART + RLENGTH)
                if (t == "{") {
                    depth++; K[depth] = key
                    # the router keeps only one copy of a group: never split one
                    if (depth == 3 && (K[2] "." K[3]) in G) { print "group split"; exit 1 }
                    if (depth == 3) G[K[2] "." K[3]] = 1
                }
                else if (t == "}") depth--
                else if (t ~ /^"/) key = substr(t, 2, length(t) - 2)
                else if (t ~ /^[0-9]+$/ && depth == 3 && K[2] != "#") print K[2] "." K[3] "." key
            }
            if (depth != 0) { print "unbalanced block"; exit 1 }
        }
    }' "$1"
}

# The JSON checker from generate.sh, run on its own against crafted files.
sed -n "/^JSON_CHECK_AWK='\$/,/^'\$/p" "$GEN" | sed '1d;$d' > "$TMP/check.awk"
printf '1.2.3.4\n1.2.5.6\n1.7.0.1\n5.6.7.8\n' > "$TMP/check.txt"

# check_case <name> <expected message, or "" for a valid file> <block>...
# Blocks are padded to 100 bytes; the last one is not padded.
check_case() {
    # POSIX sh has no local variables: use names no caller relies on.
    cc_name="$1"; cc_msg="$2"; shift 2
    cc_file="$TMP/check-$awk_name.json"
    : > "$cc_file"
    while [ "$#" -gt 1 ]; do printf '%-100s' "$1" >> "$cc_file"; shift; done
    printf '%s' "$1" >> "$cc_file"
    cc_out=$(PATH="$AWK_PATH" awk -v block=100 -f "$TMP/check.awk" "$TMP/check.txt" "$cc_file")
    cc_rc=$?
    if [ -z "$cc_msg" ]; then
        if [ "$cc_rc" -eq 0 ]; then ok "json check accepts: $cc_name"; else not_ok "json check rejected $cc_name: $cc_out"; fi
    elif [ "$cc_rc" -ne 0 ] && printf '%s' "$cc_out" | grep -qF -- "$cc_msg"; then
        ok "json check rejects: $cc_name"
    else
        not_ok "json check: $cc_name: expected '$cc_msg', got rc=$cc_rc '$cc_out'"
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

    json_ok=1
    for list in blocklist blocklist_l blocklist_xl; do
        if [ -f "$out/$list.json" ] && [ -f "$out/$list.txt" ]; then
            decode_json "$out/$list.json" "$JSON_TEST_BLOCK" | sort > "$out.$list.decoded"
            sort "$out/$list.txt" > "$out.$list.sorted"
            cmp -s "$out.$list.decoded" "$out.$list.sorted" || json_ok=0
        else
            json_ok=0
        fi
    done
    if [ "$json_ok" = 1 ]; then
        ok "json: every list decodes block by block to exactly its .txt"
    else
        not_ok "json: decoded entries differ from the .txt lists"
    fi

    H='{"#":{"format":1,"entries":4}'
    check_case "valid, one block" "" \
        "$H"',"1":{"2":{"3.4":1,"5.6":1},"7":{"0.1":1}},"5":{"6":{"7.8":1}}}'
    check_case "valid, first octet continued in the next block" "" \
        "$H"',"1":{"2":{"3.4":1,"5.6":1}}}' '{"1":{"7":{"0.1":1}},"5":{"6":{"7.8":1}}}'
    check_case "two objects in one block" "data after the object" \
        "$H"',"1":{"2":{"3.4":1,"5.6":1},"7":{"0.1":1}}}{"5":{"6":{"7.8":1}}}'
    check_case "junk after the object" "data after the object" \
        "$H"',"1":{"2":{"3.4":1,"5.6":1},"7":{"0.1":1}},"5":{"6":{"7.8":1}}}xyz'
    check_case "first octet repeated in a block" "first octet 1 repeated" \
        "$H"',"1":{"2":{"3.4":1,"5.6":1}},"5":{"6":{"7.8":1}},"1":{"7":{"0.1":1}}}'
    check_case "group split across blocks" "group 1.2 appears in two places" \
        "$H"',"1":{"2":{"3.4":1}}}' '{"1":{"2":{"5.6":1},"7":{"0.1":1}},"5":{"6":{"7.8":1}}}'
    check_case "header count wrong" "header says 5 entries" \
        '{"#":{"format":1,"entries":5},"1":{"2":{"3.4":1,"5.6":1},"7":{"0.1":1}},"5":{"6":{"7.8":1}}}'
    check_case "entry not in the list" "entry 1.2.3.9 is not in the list" \
        "$H"',"1":{"2":{"3.9":1,"5.6":1},"7":{"0.1":1}},"5":{"6":{"7.8":1}}}'
    check_case "value other than 1" "has a value other than 1" \
        "$H"',"1":{"2":{"3.4":2,"5.6":1},"7":{"0.1":1}},"5":{"6":{"7.8":1}}}'
    check_case "header missing" "does not start an object" \
        '"1":{"2":{"3.4":1,"5.6":1},"7":{"0.1":1}},"5":{"6":{"7.8":1}}}'
    check_case "truncated block" "block 1" \
        "$H"',"1":{"2":{"3.4":1,"5.6":1},"7":{"0.1":1}},"5":{"6":{"7.8":1'
    check_case "header in second block" "misplaced header" \
        '{"1":{"2":{"3.4":1,"5.6":1},"7":{"0.1":1}}}' "$H"',"5":{"6":{"7.8":1}}}'

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
    expect_failure "json group larger than a block" "does not fit into a 60-byte block" \
        'JSON_BLOCK=60'
done

echo
echo "$pass passed, $fail failed ($ran awk implementation(s))"
[ "$ran" -gt 0 ] && [ "$fail" -eq 0 ]
