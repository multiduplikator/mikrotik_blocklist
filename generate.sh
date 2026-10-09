#!/bin/sh
# Blocklist aggregator
#
# Downloads public threat feeds, extracts IPv4 addresses and CIDRs, drops
# reserved address space, merges overlapping ranges and writes three
# cumulative tiers (standard, large, xl) as plain text and as two RouterOS
# script flavours.
#
# Failure policy is all-or-nothing: if any feed cannot be downloaded (after
# retries) or yields fewer ranges than its configured minimum, the script
# exits non-zero, so the last good lists stay in place.
#
# Based on multiduplikator's README script, extended via the Davie3 fork.
#
# Requires: curl, sort, and a POSIX awk. The awk programs use only integer
#   arithmetic (multiply, divide, modulo) -- no GNU extensions -- and are
#   tested with gawk, mawk and busybox awk.

set -eu
export LC_ALL=C

# ============================================================
# CONFIG
# ============================================================

UA="multiduplikator/mikrotik_blocklist regenerator (github.com/multiduplikator/mikrotik_blocklist)"

CURL_CONNECT_TIMEOUT=30
CURL_MAX_TIME=120           # per attempt
CURL_RETRIES=3
CURL_RETRY_DELAY=5          # fixed pause between attempts
CURL_RETRY_MAX_TIME=300     # no new attempt starts after this many seconds
RETRY_PASS_DELAY=60         # pause before a second pass over failed feeds

# Output sanity checks. A run that violates any of them aborts before the
# existing lists are touched.
MAX_DELTA_PCT=30            # max change in entries vs the current lists
MIN_PREFIX_LEN=10           # no entry may be wider than this (e.g. a /8)

# Block size of the .json lists. RouterOS reads files in chunks of at most
# 32768 bytes (/file read), so every block must be one complete JSON object
# of at most this size.
JSON_BLOCK=32768

# Never block these, even if a feed lists them or a range containing them.
# Space-separated IPs or CIDRs (/16 to /32). Wider ranges are cut into the
# smallest set of CIDR blocks that leaves these addresses out.
WHITELIST="52.113.194.132 35.186.224.25"    # Microsoft Teams

# ============================================================
# LISTS
# ============================================================
# Format: <list>|<ga_list>|<tiers>|<min_entries>|<max_entries>
#
# list:    base name of the .txt and .rsc outputs
# ga_list: base name of the global-array .rsc output
# tiers:   space-separated feed tiers included in this list. Every tier
#          named here needs at least one feed, and every feed tier must be
#          used by at least one list.

LISTS=$(cat <<'EOF'
blocklist|blocklist_ga|s|8000|60000
blocklist_l|blocklist_ga_l|s l|15000|80000
blocklist_xl|blocklist_ga_xl|s l xl|40000|150000
EOF
)

# ============================================================
# FEEDS
# ============================================================
# Format: <tier>|<id>|<min_ranges>|<display_name>|<url>
#
# tier: which lists include the feed (see LISTS above):
#   s   -> Standard (also in Large and XL)
#   l   -> Large (also in XL)
#   xl  -> XL only
#
# id: short unique name, [a-z0-9_]. Feeds that need format-specific
#   preprocessing are dispatched on it in preprocess() below.
#
# min_ranges: the feed fails (and with it the run) if it yields fewer
#   usable ranges than this. Set to roughly 10-20% of the normal count so
#   that dead, truncated or HTML-error-page downloads are caught.

FEEDS=$(cat <<'EOF'
s|spamhaus_drop|500|Spamhaus DROP|https://www.spamhaus.org/drop/drop.txt
s|threatfox|500|ThreatFox|https://threatfox.abuse.ch/export/csv/ip-port/recent/
s|blocklist_de|5000|Blocklist.de|https://lists.blocklist.de/lists/all.txt
s|dshield|15|DShield|https://www.dshield.org/block.txt
s|et_compromised|100|ET Compromised IPs|https://rules.emergingthreats.net/blockrules/compromised-ips.txt
s|firehol_l1|1000|FireHOL L1|https://iplists.firehol.org/files/firehol_level1.netset
s|ipsum_l3|3000|IPsum L3|https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt
l|cinsarmy|3000|CINS Army|https://cinsscore.com/list/ci-badguys.txt
xl|ipsum_l1|20000|IPsum L1|https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt
EOF
)

# Where the lists are written. Empty means next to this script.
OUTDIR=""

# Offline mode: read each feed from $FEEDS_DIR/<id> instead of downloading.
FEEDS_DIR=""

# An optional shell file that overrides any setting above. The test suite
# uses it to run against fixture feeds; regular runs do not need it.
if [ -n "${BLOCKLIST_CONFIG:-}" ]; then
    # shellcheck source=/dev/null
    . "$BLOCKLIST_CONFIG"
fi

# ============================================================
# HELPERS
# ============================================================

log() { printf '%s\n' "$*"; }

# In GitHub Actions, emit workflow commands so problems show up as
# annotations on the run page.
warn() {
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        printf '::warning::%s\n' "$*" >&2
    else
        printf 'WARNING: %s\n' "$*" >&2
    fi
}
err() {
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        printf '::error::%s\n' "$*" >&2
    else
        printf 'ERROR: %s\n' "$*" >&2
    fi
}
die() { err "$*"; exit 1; }

summary() {
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"
    fi
}

# Iterate over FEEDS without a pipe, so loops run in the current shell
# (variables persist and background jobs can be waited for).
feeds() {
    printf '%s\n' "$FEEDS"
}

validate_config() {
    list_tiers=" " names=" "
    while IFS='|' read -r list ga_list tiers min max; do
        [ -n "$list" ] || continue
        for n in "$list" "$ga_list"; do
            case "$n" in
                ''|*[!A-Za-z0-9_]*) die "config: invalid list name '$n'" ;;
            esac
            case "$names" in
                *" $n "*) die "config: duplicate list name '$n'" ;;
            esac
            names="$names$n "
        done
        [ -n "$tiers" ] || die "config: list '$list' has no tiers"
        for t in $tiers; do
            case "$list_tiers" in
                *" $t "*) ;;
                *) list_tiers="$list_tiers$t " ;;
            esac
        done
        case "$min$max" in
            *[!0-9]*) min="" ;;
        esac
        if [ -z "$min" ] || [ -z "$max" ] || [ "$min" -gt "$max" ]; then
            die "config: list '$list' needs numeric bounds with min <= max"
        fi
    done <<EOF
$LISTS
EOF

    feed_tiers=" " ALL_IDS=""
    while IFS='|' read -r tier id min name url; do
        [ -n "$tier" ] || continue
        case "$id" in
            ''|*[!a-z0-9_]*) die "config: invalid feed id '$id'" ;;
        esac
        case " $ALL_IDS " in
            *" $id "*) die "config: duplicate feed id '$id'" ;;
        esac
        ALL_IDS="$ALL_IDS $id"
        case "$list_tiers" in
            *" $tier "*) ;;
            *) die "config: feed '$id' has tier '$tier', which no list uses" ;;
        esac
        feed_tiers="$feed_tiers$tier "
        case "$min" in
            ''|*[!0-9]*|0) die "config: feed '$id' needs a min_ranges >= 1" ;;
        esac
        if [ -z "$name" ] || [ -z "$url" ]; then
            die "config: feed '$id' is incomplete"
        fi
    done <<EOF
$(feeds)
EOF
    for t in $list_tiers; do
        case "$feed_tiers" in
            *" $t "*) ;;
            *) die "config: tier '$t' is used by a list but has no feeds" ;;
        esac
    done

    printf '%s\n' "$WHITELIST" > "$WORK/whitelist.in"
    awk "$WHITELIST_AWK" "$WORK/whitelist.in" > "$WORK/whitelist.unsorted" \
        || die "config: invalid WHITELIST"
    sort -n "$WORK/whitelist.unsorted" > "$WORK/whitelist" || die "whitelist: sort failed"
}

# Download one feed to $RAW/<id>. The file only appears once the transfer
# has completed successfully and is non-empty, so a partial or empty
# download can never be mistaken for a good one. Runs as a background job;
# curl runs as its own child so that it can be stopped on TERM.
fetch_feed() {
    id="$1"; name="$2"; url="$3"
    dest="$RAW/$id"
    rm -f "$dest"
    if [ -n "$FEEDS_DIR" ]; then
        cp "$FEEDS_DIR/$id" "$dest.part" 2> "$dest.err" &
    else
        curl --silent --show-error --fail --location \
            --proto =https --proto-redir =https --compressed \
            --connect-timeout "$CURL_CONNECT_TIMEOUT" \
            --max-time "$CURL_MAX_TIME" \
            --retry "$CURL_RETRIES" \
            --retry-delay "$CURL_RETRY_DELAY" \
            --retry-max-time "$CURL_RETRY_MAX_TIME" \
            --retry-connrefused --retry-all-errors \
            --user-agent "$UA" \
            --output "$dest.part" "$url" 2> "$dest.err" &
    fi
    child=$!
    trap 'kill "$child" 2>/dev/null; exit 143' TERM
    if ! wait "$child"; then
        # Last line of curl's (or cp's) error output is the actionable reason.
        warn "$name: download failed: $(tail -n 1 "$dest.err")"
        rm -f "$dest.part"
    elif [ ! -s "$dest.part" ]; then
        warn "$name: download failed: empty response"
        rm -f "$dest.part"
    else
        mv "$dest.part" "$dest"
        log "  + $name"
    fi
    rm -f "$dest.err"
}

# Download the given feeds (by id) in parallel.
fetch_feeds() {
    while IFS='|' read -r tier id min name url; do
        case " $* " in
            *" $id "*) ;;
            *) continue ;;
        esac
        fetch_feed "$id" "$name" "$url" &
        JOBS="$JOBS $!"
    done <<EOF
$(feeds)
EOF
    wait
    JOBS=""
}

# Turn one downloaded feed into $RANGES/<id>.<tier>. Sets FEED_COUNT and,
# if the feed is unusable, FEED_STATUS (and returns non-zero).
check_feed() {
    tier="$1"; id="$2"; min="$3"
    FEED_COUNT=0
    FEED_STATUS=""
    rm -f "$RANGES/$id.$tier"
    if [ ! -s "$RAW/$id" ]; then
        FEED_STATUS="download failed"
    elif ! preprocess "$id" "$RAW/$id" "$FEED/$id"; then
        FEED_STATUS="unexpected format"
    elif ! awk "$EXTRACT_AWK" "$FEED/$id" > "$RANGES/$id.$tier"; then
        FEED_STATUS="extraction failed"
    else
        FEED_COUNT=$(($(wc -l < "$RANGES/$id.$tier")))
        if [ "$FEED_COUNT" -lt "$min" ]; then
            FEED_STATUS="only $FEED_COUNT ranges (minimum $min)"
        fi
    fi
    if [ -n "$FEED_STATUS" ]; then
        rm -f "$RANGES/$id.$tier"
        return 1
    fi
}

# Check the given feeds (by id). Records each result in $STATUS/<id> and
# sets FAILED_IDS to the feeds that are unusable.
check_feeds() {
    FAILED_IDS=""
    while IFS='|' read -r tier id min name url; do
        case " $* " in
            *" $id "*) ;;
            *) continue ;;
        esac
        if check_feed "$tier" "$id" "$min"; then
            log "  $name: $FEED_COUNT ranges"
        else
            warn "$name: $FEED_STATUS"
            FAILED_IDS="$FAILED_IDS $id"
        fi
        printf '%s|%s\n' "$FEED_COUNT" "$FEED_STATUS" > "$STATUS/$id"
    done <<EOF
$(feeds)
EOF
}

# Convert a raw feed into something the generic extractor understands.
# Returns non-zero if the feed's format looks wrong.
preprocess() {
    id="$1"; src="$2"; dst="$3"
    case "$id" in
        dshield)
            # DShield ships "startIP<TAB>endIP<TAB>netmask<TAB>..." per row;
            # the extractor would see only the two edge IPs, so convert to
            # CIDR. Column 3 must be a valid prefix length -- otherwise an
            # empty $3 would emit "ip/", read as a /32 (silent ~99% loss).
            awk '/^[0-9]/ && $3 ~ /^[0-9]+$/ && $3+0 >= 1 && $3+0 <= 32 { print $1 "/" $3 }' \
                "$src" > "$dst"
            rows=$(grep -c '^[0-9]' "$src" || true)
            kept=$(($(wc -l < "$dst")))
            # A healthy file converts ~1:1. Fewer than half surviving means
            # the column layout changed.
            if [ "$kept" -lt "$(( (${rows:-0} + 1) / 2 ))" ]; then
                warn "DShield: only $kept of $rows rows converted (format change?)"
                return 1
            fi
            ;;
        *)
            cp "$src" "$dst"
            ;;
    esac
}

# Extract "start end" integer ranges from free-form text, one per line.
# Comment lines (# or ;) are skipped and reserved space is dropped.
#
# Reserved-range filter magic numbers:
#   16777215                    = 1.0.0.0 - 1                    -> 0.0.0.0/8
#   167772160..184549375        = 10.0.0.0/8
#   1681915904..1686110207      = 100.64.0.0/10   (CGNAT, RFC 6598)
#   2130706432..2147483647      = 127.0.0.0/8
#   2851995648..2852061183      = 169.254.0.0/16  (link-local, RFC 3927)
#   2886729728..2887778303      = 172.16.0.0/12
#   3232235520..3232301055      = 192.168.0.0/16
#   >= 3758096384               = 224.0.0.0/3 (multicast + reserved)
# shellcheck disable=SC2016  # awk program, not shell
EXTRACT_AWK='
BEGIN {
    # P[len] = number of addresses in a /len block (2^(32-len)).
    pw = 1
    for (i = 32; i >= 0; i--) { P[i] = pw; pw = pw * 2 }
}
/^[ \t]*[#;]/ { next }
{
    line = $0
    while (match(line, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?/)) {
        addr = substr(line, RSTART, RLENGTH)
        line = substr(line, RSTART + RLENGTH)

        n = split(addr, parts, "/")
        split(parts[1], o, ".")
        if (o[1]>255||o[2]>255||o[3]>255||o[4]>255) continue
        pfx = (n==2) ? parts[2]+0 : 32
        if (pfx<0||pfx>32) continue

        s = o[1]*16777216 + o[2]*65536 + o[3]*256 + o[4]
        sz = P[pfx]
        s = s - (s % sz)
        e = s + sz - 1

        if (s <= 16777215) continue
        if (s <= 184549375 && e >= 167772160) continue
        if (s <= 1686110207 && e >= 1681915904) continue
        if (s <= 2147483647 && e >= 2130706432) continue
        if (s <= 2852061183 && e >= 2851995648) continue
        if (s <= 2887778303 && e >= 2886729728) continue
        if (s <= 3232301055 && e >= 3232235520) continue
        if (e >= 3758096384) continue

        print s, e
    }
}
'

# Parse whitelist entries (whitespace-separated) into "start end" ranges. Rejects
# anything that is not a canonical IPv4 address or CIDR between /16 and
# /32, so a typo cannot whitelist a huge range or break the build.
# shellcheck disable=SC2016  # awk program, not shell
WHITELIST_AWK='
function bad(entry, why) {
    print "whitelist entry \"" entry "\": " why > "/dev/stderr"
    status = 1
}
function parse(entry,   n, q, o, len, size, i, s) {
    if (entry !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) return bad(entry, "not an IPv4 address or CIDR")
    n = split(entry, q, "/")
    split(q[1], o, ".")
    len = (n == 2) ? q[2] + 0 : 32
    if (o[1] > 255 || o[2] > 255 || o[3] > 255 || o[4] > 255) return bad(entry, "octet out of range")
    if (len < 16 || len > 32) return bad(entry, "prefix length must be 16..32")
    size = 1
    for (i = len; i < 32; i++) size = size * 2
    s = o[1]*16777216 + o[2]*65536 + o[3]*256 + o[4]
    if (s % size) return bad(entry, "host bits set (not a network address)")
    print s, s + size - 1
}
{ for (f = 1; f <= NF; f++) parse($f) }
END { exit status }
'

# Merge sorted "start end" ranges (overlapping or adjacent ones are
# joined), cut out the whitelisted ranges read from wlfile (sorted "start
# end" lines), and write what is left as the minimal set of CIDR blocks to
# txt, rsc and ga. Exits 3 if any block is wider than /minpfx.
# shellcheck disable=SC2016  # awk program, not shell
BUILD_AWK='
BEGIN {
    # S[b] = number of addresses in a block with b host bits (2^b).
    v = 1
    for (i = 0; i <= 32; i++) { S[i] = v; v = v * 2 }
    printf "" > txt
    print "/ip firewall address-list" > rsc
    print ":global newips [:toarray \"\"]" > ga
    too_wide = 0
    nwl = 0
    while ((getline line < wlfile) > 0) {
        split(line, r, " ")
        nwl++; WS[nwl] = r[1] + 0; WE[nwl] = r[2] + 0
    }
    close(wlfile)
}
function ip(n) {
    return int(n/16777216)%256 "." int(n/65536)%256 "." int(n/256)%256 "." n%256
}
function emit(s, e,   b, sz, addr) {
    while (s <= e) {
        for (b = 0; b < 32; b++) {
            sz = S[b+1]
            if ((s % sz) || s+sz-1 > e) break
        }
        sz = S[b]
        addr = (b == 0) ? ip(s) : ip(s) "/" (32-b)
        if (32-b < minpfx) {
            print "entry " addr " is wider than /" minpfx > "/dev/stderr"
            too_wide++
        }
        print addr > txt
        print "add list=new_blocklist address=\"" addr "\" comment=\"blocklist\"" > rsc
        print ":set newips ($newips,\"" addr "\")" > ga
        s += sz
    }
}
# Emit [s, e] minus every whitelisted range.
function emit_wl(s, e,   i) {
    for (i = 1; i <= nwl && s <= e; i++) {
        if (WE[i] < s || WS[i] > e) continue
        if (WS[i] > s) emit(s, WS[i] - 1)
        s = WE[i] + 1
    }
    if (s <= e) emit(s, e)
}
NR == 1 { cs = $1; ce = $2; next }
$1 <= ce+1 { if ($2 > ce) ce = $2; next }
{ emit_wl(cs, ce); cs = $1; ce = $2 }
END {
    if (NR) emit_wl(cs, ce)
    if (too_wide) exit 3
}
'

# Write a list (sorted .txt input) as fixed-size JSON blocks for RouterOS.
# Every block is exactly `block` bytes (padded with spaces; the last one is
# not padded) and holds one JSON object that maps first octet -> second
# octet -> rest of the address -> 1, e.g.
#   {"#":{"format":1,"entries":3},"1":{"2":{"3.4":1,"3.8/30":1}},"5":{...}}
# The "#" header is only in the first block. A first-octet object may
# continue in the next block; a second-octet group never spans blocks.
# Exits 3 if a single group does not fit into one block.
# shellcheck disable=SC2016  # awk program, not shell
JSON_AWK='
BEGIN {
    SP = " "
    while (length(SP) < block) SP = SP SP
    body = "{\"#\":{\"format\":1,\"entries\":" entries "}"
    memb = 1; o1cur = ""; g = ""; go1 = ""; go2 = ""; npend = 0; bad = 0
}
function close_block(   s) {
    s = body ((o1cur != "") ? "}" : "") "}"
    if (npend) printf "%s%s", pend, substr(SP, 1, block - length(pend)) > out
    pend = s; npend = 1
    body = "{"; memb = 0; o1cur = ""
}
function flush_group(   grp, piece) {
    if (g == "") return
    grp = "\"" go2 "\":{" g "}"
    if (go1 == o1cur) piece = "," grp
    else piece = ((o1cur != "") ? "}" : "") (memb ? "," : "") "\"" go1 "\":{" grp
    if (length(body) + length(piece) + 2 > block) {
        close_block()
        piece = "\"" go1 "\":{" grp
        if (length(body) + length(piece) + 2 > block) {
            print "json: group " go1 "." go2 " does not fit into a " block "-byte block" > "/dev/stderr"
            bad = 1
        }
    }
    body = body piece; o1cur = go1; memb = 1; g = ""
}
{
    i = index($0, "."); o1 = substr($0, 1, i - 1); r = substr($0, i + 1)
    j = index(r, "."); o2 = substr(r, 1, j - 1); rest = substr(r, j + 1)
    if (o1 != go1 || o2 != go2) { flush_group(); go1 = o1; go2 = o2 }
    g = g ((g == "") ? "" : ",") "\"" rest "\":1"
}
END {
    flush_group()
    close_block()
    printf "%s", pend > out
    if (bad) exit 3
}
'

# Check a .json list the way RouterOS reads it: block by block, each block
# exactly one JSON object followed only by padding. Reads the list's .txt
# first, then the .json; every decoded entry must be in the .txt, appear
# once, and the totals must match the header. Rejects anything the router
# would load wrongly: a repeated first octet within a block (later key
# wins), a second-octet group in two blocks (the router keeps only one),
# stray characters, a misplaced header. Prints the reason and exits 1.
# shellcheck disable=SC2016  # awk program, not shell
JSON_CHECK_AWK='
function fail(why) { print why; bad = 1; exit 1 }
FNR == NR { want[$0] = 1; nwant++; next }
{ s = s $0 }
END {
    if (bad) exit 1
    if (length(s) == 0) fail("empty file")
    nblk = 0; count = 0; fmt = ""; ents = ""
    for (off = 1; off <= length(s); off += block) {
        nblk++
        c = substr(s, off, block)
        if (substr(c, 1, 1) != "{") fail("block " nblk " does not start an object")
        np = split(c, P, "\"")
        depth = 0; closed = 0; delete o1seen
        for (k = 1; k <= np; k++) {
            if (k % 2 == 0) {
                if (closed || depth < 1) fail("block " nblk ": text outside the object")
                key = P[k]; nxt = P[k + 1]
                if (substr(nxt, 1, 2) == ":{") {
                    name[depth + 1] = key
                } else if (depth == 3 && name[2] != "#") {
                    if (substr(nxt, 1, 2) != ":1" || substr(nxt, 3, 1) !~ /^[,}]$/) fail("block " nblk ": entry " key " has a value other than 1")
                    e = name[2] "." name[3] "." key
                    if (!(e in want)) fail("block " nblk ": entry " e " is not in the list")
                    if (e in got) fail("block " nblk ": entry " e " appears twice")
                    got[e] = 1; count++
                } else if (depth == 2 && name[2] == "#" && nblk == 1) {
                    v = substr(nxt, 2); sub(/[^0-9].*$/, "", v)
                    if (key == "format") fmt = v
                    else if (key == "entries") ents = v
                    else fail("unknown header field " key)
                } else {
                    fail("block " nblk ": unexpected key " key)
                }
                seg = substr(nxt, 2)
            } else if (k == 1) {
                seg = P[k]
            } else {
                continue    # already handled together with the key before it
            }
            m = length(seg)
            for (i = 1; i <= m; i++) {
                ch = substr(seg, i, 1)
                if (closed) {
                    if (ch != " ") fail("block " nblk ": data after the object")
                } else if (ch == "{") {
                    depth++
                    if (depth == 2) {
                        if (name[2] in o1seen) fail("block " nblk ": first octet " name[2] " repeated")
                        o1seen[name[2]] = 1
                        if (name[2] == "#" && (nblk != 1 || hdrseen++)) fail("misplaced header")
                    }
                    if (depth == 3) {
                        g = name[2] "." name[3]
                        if (g in grp) fail("second-octet group " g " appears in two places")
                        grp[g] = 1
                    }
                    if (depth > 3) fail("block " nblk ": nested too deep")
                } else if (ch == "}") {
                    depth--
                    if (depth < 0) fail("block " nblk ": unbalanced braces")
                    if (depth == 0) closed = 1
                } else if (ch !~ /^[:,0-9]$/) {
                    fail("block " nblk ": unexpected character " ch)
                }
            }
        }
        if (!closed) fail("block " nblk " is not a complete object")
    }
    if (fmt != "1") fail("header missing or format is not 1")
    if (ents != nwant) fail("header says " ents " entries, list has " nwant)
    if (count != nwant) fail("decoded " count " entries, list has " nwant)
}
'

# Build one list into $STAGE from the ranges of the given feed tiers.
build_list() {
    list="$1"; ga_list="$2"; tiers="$3"
    set --
    for f in "$RANGES"/*; do
        case " $tiers " in
            *" ${f##*.} "*) set -- "$@" "$f" ;;
        esac
    done
    [ "$#" -gt 0 ] || die "$list: no ranges for tiers '$tiers'"
    # sort writes to a file rather than into the awk pipe: POSIX sh has no
    # pipefail, so a failing sort would otherwise go unnoticed.
    sort -n "$@" > "$WORK/$list.sorted" || die "$list: sort failed"
    awk -v txt="$STAGE/$list.txt" -v rsc="$STAGE/$list.rsc" \
        -v ga="$STAGE/$ga_list.rsc" -v minpfx="$MIN_PREFIX_LEN" \
        -v wlfile="$WORK/whitelist" \
        "$BUILD_AWK" "$WORK/$list.sorted" || die "$list: build failed"
    awk -v out="$STAGE/$list.json" -v block="$JSON_BLOCK" \
        -v entries="$(($(wc -l < "$STAGE/$list.txt")))" \
        "$JSON_AWK" "$STAGE/$list.txt" || die "$list: json build failed"
}

# Validate one staged list: shape of every line, consistent entry counts
# across the three files, absolute bounds, and change vs the current list.
check_list() {
    list="$1"; ga_list="$2"; min="$3"; max="$4"
    txt="$STAGE/$list.txt"; rsc="$STAGE/$list.rsc"; ga="$STAGE/$ga_list.rsc"

    if grep -Evq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "$txt"; then
        die "$list.txt: unexpected line(s)"
    fi
    if [ "$(head -n 1 "$rsc")" != "/ip firewall address-list" ] ||
        tail -n +2 "$rsc" | grep -Evq '^add list=new_blocklist address="[0-9./]+" comment="blocklist"$'; then
        die "$list.rsc: unexpected line(s)"
    fi
    # shellcheck disable=SC2016  # literal $newips in the pattern
    if [ "$(head -n 1 "$ga")" != ':global newips [:toarray ""]' ] ||
        tail -n +2 "$ga" | grep -Evq '^:set newips \(\$newips,"[0-9./]+"\)$'; then
        die "$ga_list.rsc: unexpected line(s)"
    fi

    n=$(($(wc -l < "$txt")))
    if [ "$(($(wc -l < "$rsc")))" -ne $((n + 1)) ] || [ "$(($(wc -l < "$ga")))" -ne $((n + 1)) ]; then
        die "$list: entry counts differ between .txt and .rsc files"
    fi
    if [ "$n" -lt "$min" ] || [ "$n" -gt "$max" ]; then
        die "$list: $n entries, outside the expected $min..$max"
    fi
    if ! why=$(awk -v block="$JSON_BLOCK" "$JSON_CHECK_AWK" "$txt" "$STAGE/$list.json"); then
        die "$list.json: $why"
    fi

    prev="$OUTDIR/$list.txt"
    if [ -s "$prev" ]; then
        old=$(($(wc -l < "$prev")))
        pct=$(awk -v o="$old" -v n="$n" 'BEGIN { d = (n - o) / o * 100; if (d < 0) d = -d; printf "%d", d + 0.5 }')
        log "  $list: $old -> $n entries (${pct}% change)"
        if [ "$pct" -gt "$MAX_DELTA_PCT" ]; then
            die "$list: changed by ${pct}% (limit ${MAX_DELTA_PCT}%)"
        fi
    else
        log "  $list: $n entries (no previous list)"
    fi
    LIST_ROWS="$LIST_ROWS| $list | $n |
"
}

# ============================================================
# SCRIPT
# ============================================================

# By default, anchor output to the script's own directory, not the
# caller's CWD.
if [ -z "$OUTDIR" ]; then
    OUTDIR="$(cd "$(dirname "$0")" && pwd)"
fi
[ -d "$OUTDIR" ] || die "output directory $OUTDIR does not exist"

WORK=""
STAGE=""
JOBS=""
cleanup() {
    # Stop downloads still running (only after INT/TERM).
    if [ -n "$JOBS" ]; then
        # shellcheck disable=SC2086  # list of PIDs
        kill $JOBS 2>/dev/null || true
        wait
    fi
    if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
    if [ -n "$STAGE" ]; then rm -rf "$STAGE"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

WORK=$(mktemp -d)
RAW="$WORK/raw"
FEED="$WORK/feed"
RANGES="$WORK/ranges"
STATUS="$WORK/status"
mkdir "$RAW" "$FEED" "$RANGES" "$STATUS"
# New lists are staged next to the old ones and only moved into place
# once all of them pass the checks.
STAGE=$(mktemp -d "$OUTDIR/.generate.XXXXXX")

validate_config

# shellcheck disable=SC2086  # ALL_IDS / FAILED_IDS are lists of plain ids
{
log "Downloading feeds..."
fetch_feeds $ALL_IDS
log "Extracting ranges..."
check_feeds $ALL_IDS

# Second pass: anything unusable -- failed, empty, truncated, an error page
# instead of data -- is downloaded and checked once more.
if [ -n "$FAILED_IDS" ]; then
    log "Retrying$FAILED_IDS in ${RETRY_PASS_DELAY}s..."
    sleep "$RETRY_PASS_DELAY"
    fetch_feeds $FAILED_IDS
    check_feeds $FAILED_IDS
fi
}

summary "| Feed | Tier | Ranges | Status |"
summary "|---|---|---:|---|"
failed=""
while IFS='|' read -r tier id min name url; do
    [ -n "$tier" ] || continue
    IFS='|' read -r count status < "$STATUS/$id"
    if [ -n "$status" ]; then
        err "$name: $status"
        failed="$failed${failed:+, }$name"
        summary "| $name | $tier | $count | :x: $status |"
    else
        summary "| $name | $tier | $count | ok |"
    fi
done <<EOF
$(feeds)
EOF
if [ -n "$failed" ]; then
    die "Aborting, lists left unchanged. Failed feed(s): $failed"
fi

log "Building lists..."
while IFS='|' read -r list ga_list tiers min max; do
    [ -n "$list" ] || continue
    build_list "$list" "$ga_list" "$tiers"
done <<EOF
$LISTS
EOF

log "Checking lists..."
LIST_ROWS=""
while IFS='|' read -r list ga_list tiers min max; do
    [ -n "$list" ] || continue
    check_list "$list" "$ga_list" "$min" "$max"
done <<EOF
$LISTS
EOF

# Every check passed: replace the lists. STAGE lives inside OUTDIR, so
# each mv is an atomic rename.
for f in "$STAGE"/*; do
    mv "$f" "$OUTDIR/"
done
summary ""
summary "| List | Entries |"
summary "|---|---:|"
summary "$LIST_ROWS"
log "Done!"
