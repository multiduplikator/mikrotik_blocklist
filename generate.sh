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
CURL_RETRY_DELAY=5          # doubles after each attempt
CURL_RETRY_MAX_TIME=300     # total budget for one feed, including retries
RETRY_PASS_DELAY=60         # pause before a second pass over failed feeds

# ============================================================
# FEEDS
# ============================================================
# Format: <tier>|<id>|<min_ranges>|<display_name>|<url>
#
# tier:
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
    have_s=0 have_l=0 have_xl=0 ids=" "
    while IFS='|' read -r tier id min name url; do
        [ -n "$tier" ] || continue
        case "$tier" in
            s) have_s=1 ;; l) have_l=1 ;; xl) have_xl=1 ;;
            *) die "config: feed '$id' has unknown tier '$tier'" ;;
        esac
        case "$id" in
            ''|*[!a-z0-9_]*) die "config: invalid feed id '$id'" ;;
        esac
        case "$ids" in
            *" $id "*) die "config: duplicate feed id '$id'" ;;
        esac
        ids="$ids$id "
        case "$min" in
            ''|*[!0-9]*|0) die "config: feed '$id' needs a min_ranges >= 1" ;;
        esac
        if [ -z "$name" ] || [ -z "$url" ]; then
            die "config: feed '$id' is incomplete"
        fi
    done <<EOF
$(feeds)
EOF
    [ "$have_s$have_l$have_xl" = 111 ] || die "config: every tier (s, l, xl) needs at least one feed"
}

# Download one feed to $RAW/<id>. The file only appears once the transfer
# has completed successfully, so a partial download can never be mistaken
# for a good one.
fetch_feed() {
    id="$1"; name="$2"; url="$3"
    dest="$RAW/$id"
    if out=$(curl --silent --show-error --fail --location \
            --proto =https --proto-redir =https --compressed \
            --connect-timeout "$CURL_CONNECT_TIMEOUT" \
            --max-time "$CURL_MAX_TIME" \
            --retry "$CURL_RETRIES" \
            --retry-delay "$CURL_RETRY_DELAY" \
            --retry-max-time "$CURL_RETRY_MAX_TIME" \
            --retry-connrefused --retry-all-errors \
            --user-agent "$UA" \
            --output "$dest.part" "$url" 2>&1); then
        mv "$dest.part" "$dest"
        log "  + $name"
    else
        rm -f "$dest.part"
        # Last line of curl's output is the actionable reason.
        warn "$name: download failed: $(printf '%s\n' "$out" | tail -n 1)"
    fi
}

# Fetch, in parallel, every feed that is not downloaded yet.
fetch_missing() {
    while IFS='|' read -r tier id min name url; do
        [ -n "$tier" ] || continue
        [ -s "$RAW/$id" ] || fetch_feed "$id" "$name" "$url" &
    done <<EOF
$(feeds)
EOF
    wait
}

count_missing() {
    n=0
    while IFS='|' read -r tier id min name url; do
        [ -n "$tier" ] || continue
        [ -s "$RAW/$id" ] || n=$((n + 1))
    done <<EOF
$(feeds)
EOF
    echo "$n"
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
# Comment lines (# or ;) are skipped; reserved space and whitelisted
# hosts are dropped.
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
#   879870596                   = 52.113.194.132   (whitelist: Teams)
#   599449625                   = 35.186.224.25    (whitelist: Teams)
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
        if (pfx==32 && s==879870596) continue
        if (pfx==32 && s==599449625) continue

        print s, e
    }
}
'

# ============================================================
# SCRIPT
# ============================================================

# Anchor output to the script's own directory, not the caller's CWD.
OUTDIR="$(cd "$(dirname "$0")" && pwd)"

WORK=""
cleanup() {
    if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

WORK=$(mktemp -d)
RAW="$WORK/raw"
FEED="$WORK/feed"
RANGES="$WORK/ranges"
mkdir "$RAW" "$FEED" "$RANGES"

validate_config

log "Downloading feeds..."
fetch_missing
missing=$(count_missing)
if [ "$missing" -gt 0 ]; then
    log "$missing feed(s) failed; retrying them in ${RETRY_PASS_DELAY}s..."
    sleep "$RETRY_PASS_DELAY"
    fetch_missing
fi

log "Extracting ranges..."
summary "| Feed | Tier | Ranges | Status |"
summary "|---|---|---:|---|"
failed=""
while IFS='|' read -r tier id min name url; do
    [ -n "$tier" ] || continue
    status=""
    count=0
    if [ ! -s "$RAW/$id" ]; then
        status="download failed"
    elif ! preprocess "$id" "$RAW/$id" "$FEED/$id"; then
        status="unexpected format"
    else
        awk "$EXTRACT_AWK" "$FEED/$id" > "$RANGES/$id.$tier"
        count=$(($(wc -l < "$RANGES/$id.$tier")))
        if [ "$count" -lt "$min" ]; then
            status="only $count ranges (minimum $min)"
        fi
    fi
    if [ -n "$status" ]; then
        err "$name: $status"
        failed="$failed${failed:+, }$name"
        summary "| $name | $tier | $count | :x: $status |"
    else
        log "  $name: $count ranges"
        summary "| $name | $tier | $count | ok |"
    fi
done <<EOF
$(feeds)
EOF
if [ -n "$failed" ]; then
    die "Aborting, lists left unchanged. Failed feed(s): $failed"
fi

log "Building lists..."

build_list() {
    base="$1"; shift
    outbase="$OUTDIR/$base"

    sort -n "$@" | awk \
        -v base="$base" \
        -v outbase="$outbase" \
        -v outdir="$OUTDIR" '
    BEGIN {
        v = 1
        for (i=0; i<=32; i++) { P[i]=v; v=v*2 }
        rsc = outbase ".rsc"
        if (base == "blocklist")         ga_suffix = ""
        else if (base == "blocklist_l")  ga_suffix = "_l"
        else if (base == "blocklist_xl") ga_suffix = "_xl"
        else                              ga_suffix = "_" base
        ga = outdir "/blocklist_ga" ga_suffix ".rsc"
        txt = outbase ".txt"
        printf "" > txt
        print "/ip firewall address-list" > rsc
        print ":global newips [:toarray \"\"]" > ga
        count = 0
    }
    function ip(n) {
        return int(n/16777216)%256 "." int(n/65536)%256 "." int(n/256)%256 "." n%256
    }
    function emit(s, e,   b, sz, addr) {
        while (s <= e) {
            for (b=0; b<32; b++) {
                sz = P[b+1]
                if ((s % sz) || s+sz-1 > e) break
            }
            sz = P[b]
            addr = (b==0) ? ip(s) : ip(s) "/" (32-b)
            print addr >> txt
            print "add list=new_blocklist address=\"" addr "\" comment=\"blocklist\"" >> rsc
            print ":set newips ($newips,\"" addr "\")" >> ga
            count++
            s += sz
        }
    }
    NR==1 { cs=$1; ce=$2; next }
    $1 <= ce+1 { if ($2>ce) ce=$2; next }
    { emit(cs,ce); cs=$1; ce=$2 }
    END {
        if(NR) emit(cs,ce)
        print "  " base ": " count " entries" > "/dev/stderr"
    }'
}

# A bare `wait` under `set -e` does NOT abort on a failed background job
# (it returns 0), so a build_list failure would silently ship partial
# files. Capture the exit status explicitly and fail loudly.
build_list "blocklist"     "$RANGES"/*.s &
pid_s=$!
build_list "blocklist_l"   "$RANGES"/*.s "$RANGES"/*.l &
pid_l=$!
build_list "blocklist_xl"  "$RANGES"/*.s "$RANGES"/*.l "$RANGES"/*.xl &
pid_xl=$!
build_fail=0
wait "$pid_s"  || build_fail=1
wait "$pid_l"  || build_fail=1
wait "$pid_xl" || build_fail=1
if [ "$build_fail" -ne 0 ]; then
    echo "  ! build_list failed; aborting to avoid committing partial lists." >&2
    exit 1
fi

echo "Done!"
