#!/bin/sh
# Blocklist aggregator - gawk version
#
# Based on multiduplikator's README script, extended (via the Davie3 fork)
# with:
#   - Spamhaus EDROP, DShield, and ThreatFox added
#   - HTTP retries + polite User-Agent
#   - Soft-fail: tolerates up to MAX_FAILED_FEEDS failed feeds
#   - DShield CIDR preprocess with a format-drift guard
#   - Broader reserved-range filter (CGNAT, link-local, multicast+reserved)
#
# Requires: curl, gawk, sed, grep (all default on ubuntu-latest).

set -eu
export LC_ALL=C

# ============================================================
# CONFIG
# ============================================================

UA="multiduplikator/mikrotik_blocklist regenerator (github.com/multiduplikator/mikrotik_blocklist)"

MAX_FAILED_FEEDS=2

CURL_CONNECT_TIMEOUT=30
CURL_MAX_TIME=180
CURL_RETRIES=3
CURL_RETRY_DELAY=5

# ============================================================
# FEEDS
# ============================================================
# Format: <tier>|<final_filename>|<display_name>|<url>
#
# tier:
#   s   -> Standard (also in Large and XL)
#   l   -> Large only (also in XL)
#   xl  -> XL only
#
# final_filename: name of the file the extractor reads. For feeds that
# need format-specific preprocessing (see PREPROCESS below), the raw
# download goes to <final_filename>.raw and the preprocess step writes
# the transformed data to <final_filename>.

FEEDS=$(cat <<'EOF'
s|spamhaus_drop.out_s|Spamhaus DROP|https://www.spamhaus.org/drop/drop.txt
s|spamhaus_edrop.out_s|Spamhaus EDROP|https://www.spamhaus.org/drop/edrop.txt
s|sslbl.out_s|SSL Blacklist|https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
s|blocklist_de.out_s|Blocklist.de|https://lists.blocklist.de/lists/all.txt
s|feodo.out_s|Feodo Tracker|https://feodotracker.abuse.ch/downloads/ipblocklist.txt
s|threatfox.out_s|ThreatFox|https://threatfox.abuse.ch/export/csv/ip-port/recent/
s|dshield.out_s|DShield|https://www.dshield.org/block.txt
s|firehol_l1.out_s|FireHOL L1|https://iplists.firehol.org/files/firehol_level1.netset
s|ipsum_l3.out_s|IPsum L3|https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt
l|cinsarmy.out_l|CINS Army|https://cinsscore.com/list/ci-badguys.txt
xl|ipsum_l1.out_xl|IPsum L1|https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt
EOF
)

# Feeds whose raw format the generic extractor cannot parse; each of
# these downloads to <name>.raw and is transformed in the PREPROCESS step.
# Names must match a "final_filename" from FEEDS.
PREPROCESS_DSHIELD="dshield.out_s"

# ============================================================
# SCRIPT
# ============================================================

OUTDIR="$(pwd)"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

CACHE="$TMPDIR/.cache"
mkdir -p "$CACHE"

cd "$TMPDIR"

download() {
    url="$1"; output="$2"; name="$3"
    if curl -sfL \
            --connect-timeout "$CURL_CONNECT_TIMEOUT" \
            --max-time "$CURL_MAX_TIME" \
            --retry "$CURL_RETRIES" \
            --retry-delay "$CURL_RETRY_DELAY" \
            --retry-connrefused --retry-all-errors \
            -A "$UA" \
            "$url" -o "$output" 2>/dev/null; then
        if [ -s "$output" ]; then
            echo "  + $name"
        else
            echo "  ! $name (empty)"
            rm -f "$output"
        fi
    else
        echo "  ! $name (failed)"
        rm -f "$output"
    fi
}

echo "Downloading blocklists..."

# Iterate FEEDS in a subshell so background downloads and the trailing
# `wait` share the same shell context (pipe subshell). The outer `echo`
# blocks until this subshell (including the internal wait) completes.
echo "$FEEDS" | {
    while IFS='|' read -r tier output name url; do
        [ -z "$tier" ] && continue
        if [ "$output" = "$PREPROCESS_DSHIELD" ]; then
            dl_target="$output.raw"
        else
            dl_target="$output"
        fi
        download "$url" "$dl_target" "$name" &
    done
    wait
}

# Preprocessing: transform any format the generic extractor can't parse.
# DShield ships "startIP<TAB>endIP<TAB>netmask<TAB>..." per row; the
# extractor would treat startIP and endIP as isolated /32s and miss
# everything in between, so convert to CIDR first.
if [ -s "$PREPROCESS_DSHIELD.raw" ]; then
    # Require column 3 to be a valid CIDR prefix (1-32). Guards against
    # DShield changing its format: without this, an empty $3 would emit
    # "ip/" which the extractor treats as /32, silently shrinking each
    # /24 block to a single host (~99% coverage loss with no error).
    awk '/^[0-9]/ && $3 ~ /^[0-9]+$/ && $3+0 >= 1 && $3+0 <= 32 {print $1"/"$3}' \
        "$PREPROCESS_DSHIELD.raw" > "$PREPROCESS_DSHIELD"
    raw_lines=$(grep -c '^[0-9]' "$PREPROCESS_DSHIELD.raw" 2>/dev/null || echo 0)
    kept_lines=$(wc -l < "$PREPROCESS_DSHIELD" 2>/dev/null || echo 0)
    if [ "$raw_lines" -gt 0 ] && [ "$kept_lines" -lt "$((raw_lines / 2))" ]; then
        echo "  ! DShield preprocess kept $kept_lines/$raw_lines rows (format change?); dropping feed"
        rm -f "$PREPROCESS_DSHIELD"
    fi
    rm -f "$PREPROCESS_DSHIELD.raw"
fi

# Soft-fail: count missing/empty feeds; abort only if too many are down.
# Plain loop (no pipe) so `missing` accumulates in this shell directly.
missing=0
while IFS='|' read -r tier output name url; do
    [ -z "$tier" ] && continue
    if [ ! -s "$output" ]; then
        echo "  ! Skipping missing/empty feed: $output ($name)"
        missing=$((missing + 1))
    fi
done <<EOF
$FEEDS
EOF
if [ "$missing" -gt "$MAX_FAILED_FEEDS" ]; then
    echo "  ! $missing feeds failed (threshold: $MAX_FAILED_FEEDS). Aborting."
    exit 1
fi
echo "Downloads complete ($missing failed, within tolerance)."

echo "Extracting ranges..."

# Reserved-range filter magic numbers (in awk arithmetic form):
#   16777215                    = 1.0.0.0 - 1                    -> 0.0.0.0/8
#   167772160..184549375        = 10.0.0.0/8
#   1681915904..1686110207      = 100.64.0.0/10   (CGNAT, RFC 6598)
#   2130706432..2147483647      = 127.0.0.0/8 (loopback range end padded)
#   2851995648..2852061183      = 169.254.0.0/16  (link-local, RFC 3927)
#   2886729728..2887778303      = 172.16.0.0/12
#   3232235520..3232301055      = 192.168.0.0/16
#   >= 3758096384               = 224.0.0.0/3 (multicast + reserved)
#   879870596                   = 52.113.194.132   (whitelist: Teams)
#   599449625                   = 35.186.224.25    (whitelist: Teams)
gawk '
BEGIN {
    for (i = 0; i <= 32; i++) P[i] = lshift(1, 32-i)
    cache = "'"$CACHE"'/"
}
{
    line = $0
    while (match(line, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?/)) {
        addr = substr(line, RSTART, RLENGTH)
        line = substr(line, RSTART + RLENGTH)

        n = split(addr, p, "/")
        split(p[1], o, ".")
        if (o[1]>255||o[2]>255||o[3]>255||o[4]>255) continue
        pfx = (n==2) ? p[2]+0 : 32
        if (pfx<0||pfx>32) continue

        s = lshift(o[1],24) + lshift(o[2],16) + lshift(o[3],8) + o[4]
        sz = P[pfx]
        s = and(s, compl(sz-1))
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

        print s, e >> (cache FILENAME ".ranges")
    }
}
' ./*.out_*

echo "Building lists..."

build_list() {
    base="$1"; shift
    outbase="$OUTDIR/$base"

    sort -n -S 50% "$@" | gawk \
        -v base="$base" \
        -v outbase="$outbase" \
        -v outdir="$OUTDIR" '
    BEGIN {
        for (i=0; i<=32; i++) P[i] = lshift(1, i)
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
        return and(rshift(n,24),255) "." and(rshift(n,16),255) "." and(rshift(n,8),255) "." and(n,255)
    }
    function emit(s, e,   b, sz, addr) {
        while (s <= e) {
            for (b=0; b<32; b++) {
                sz = P[b+1]
                if (and(s,sz-1) || s+sz-1 > e) break
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

# Guard against empty globs if all feeds in a tier failed.
have_ranges() {
    for p in "$@"; do
        [ -e "$p" ] && return 0
    done
    return 1
}

# Every tier must produce ranges. If any tier is empty, the previous
# committed files would silently persist -- fail loudly instead so CI
# surfaces the outage rather than shipping yesterday's data.
fail=0
if ! have_ranges "$CACHE"/*.out_s.ranges; then
    echo "  ! No standard-tier ranges extracted (all s-tier feeds collapsed?)" >&2
    fail=1
fi
if [ "$fail" -eq 1 ]; then
    echo "  ! Aborting to avoid committing stale lists." >&2
    exit 1
fi

build_list "blocklist"     "$CACHE"/*.out_s.ranges &
build_list "blocklist_l"   "$CACHE"/*.out_s.ranges "$CACHE"/*.out_l.ranges &
build_list "blocklist_xl"  "$CACHE"/*.out_s.ranges "$CACHE"/*.out_l.ranges "$CACHE"/*.out_xl.ranges &
wait

echo "Done!"