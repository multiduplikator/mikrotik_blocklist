# MikroTik Blocklist

An aggregated IP blocklist for MikroTik RouterOS firewalls, compiled from multiple threat intelligence sources.

## Overview

This project provides pre-aggregated blocklists optimized for MikroTik routers. By using CIDR prefix aggregation, we minimize the number of address-list entries while maintaining comprehensive coverage — improving router performance and reducing memory usage.

**Update frequency:** Every 3 hours

## Available Lists

| List | File | Entries | Sources |
|------|------|---------|---------|
| Standard | `blocklist.txt` / `blocklist_ga.rsc` | ~20k | Core threat feeds |
| Large | `blocklist_l.txt` / `blocklist_ga_l.rsc` | ~25k | Core + CINS Army |
| Extra Large | `blocklist_xl.txt` / `blocklist_ga_xl.rsc` | ~68k | All sources including IPsum L1 |

## Sources

| Source | Description | Standard | Large | XL |
|--------|-------------|:--------:|:-----:|:--:|
| [Tor Exit Nodes](https://github.com/SecOps-Institute/Tor-IP-Addresses) | Tor exit node IPs | ✓ | ✓ | ✓ |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | "Don't Route Or Peer" list | ✓ | ✓ | ✓ |
| [SSL Blacklist](https://sslbl.abuse.ch/) | Botnet C&C servers | ✓ | ✓ | ✓ |
| [Blocklist.de](https://lists.blocklist.de/) | Fail2ban reported IPs | ✓ | ✓ | ✓ |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Banking trojan C&C servers | ✓ | ✓ | ✓ |
| [FireHOL Level 1](https://iplists.firehol.org/) | Aggregated threat intelligence | ✓ | ✓ | ✓ |
| [IPsum Level 3](https://github.com/stamparm/ipsum) | High-confidence threat IPs (3+ hits) | ✓ | ✓ | ✓ |
| [CINS Army](https://cinsscore.com/) | Collective Intelligence Network Security | | ✓ | ✓ |
| [IPsum Level 1](https://github.com/stamparm/ipsum) | Broader threat IPs (1+ hits) | | | ✓ |

## Filtered Addresses

The following are automatically excluded:
- Private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback: `127.0.0.0/8`
- Multicast: `224.0.0.0/4`
- Reserved: `240.0.0.0/4` (added to blocklist), `0.0.0.0/8`
- Whitelisted: `52.113.194.132` (Microsoft Teams), `35.186.224.25` (Microsoft Teams)

---

## Blocklist Generation

The blocklist is generated using a sh script for IP extraction, validation, and CIDR aggregation.

### Dependencies

- `sh`
- `sed`
- `grep`
- `gawk`
- `ipgrange` (only for iprange version)
- `curl`
- `git` (for publishing)

### Generator Script (gawk version)

```sh
#!/bin/sh
# Blocklist aggregator - Alpine Linux (gawk version)
# Requires: apk add curl git gawk
set -eu

export LC_ALL=C

WORKDIR="/path/to/blocklist"
OUTDIR="/path/to/mikrotik_blocklist"
CACHE="$WORKDIR/.cache"

cd "$WORKDIR"
rm -rf -- "$CACHE" *.txt *.rsc 2>/dev/null || true
mkdir -p "$CACHE"

download() {
    url="$1"; output="$2"; name="$3"
    if curl -sfL --connect-timeout 30 --max-time 120 "$url" -o "$output" 2>/dev/null; then
        [ -s "$output" ] && echo "  + $name" || { echo "  ! $name (empty)"; exit 1; }
    else
        echo "  ! $name (failed)"; exit 1
    fi
}

echo "Downloading blocklists..."

download "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst" \
         "tor_exits.out_s" "Tor Exit Nodes" &
download "https://www.spamhaus.org/drop/drop.txt" \
         "spamhaus_drop.out_s" "Spamhaus DROP" &
download "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" \
         "sslbl.out_s" "SSL Blacklist" &
download "https://lists.blocklist.de/lists/all.txt" \
         "blocklist_de.out_s" "Blocklist.de" &
download "https://cinsscore.com/list/ci-badguys.txt" \
         "cinsarmy.out_l" "CINS Army" &
download "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
         "feodo.out_s" "Feodo Tracker" &
download "https://iplists.firehol.org/files/firehol_level1.netset" \
         "firehol_l1.out_s" "FireHOL L1" &
download "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt" \
         "ipsum_l1.out_xl" "IPsum L1" &
download "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" \
         "ipsum_l3.out_s" "IPsum L3" &
wait

for f in tor_exits.out_s spamhaus_drop.out_s sslbl.out_s blocklist_de.out_s \
         cinsarmy.out_l feodo.out_s firehol_l1.out_s ipsum_l1.out_xl ipsum_l3.out_s; do
    [ -s "$f" ] || { echo "  ! Missing: $f"; exit 1; }
done

echo "All downloads successful."
echo "Extracting ranges..."

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
        if (s <= 2147483647 && e >= 2130706432) continue
        if (s <= 2887778303 && e >= 2886729728) continue
        if (s <= 3232301055 && e >= 3232235520) continue
        if (e >= 3758096384) continue
        if (pfx==32 && s==879870596) continue
        if (pfx==32 && s==599449625) continue

        print s, e >> (cache FILENAME ".ranges")
    }
}
' *.out_*

echo "  Processed $(ls *.out_* | wc -l) files"

echo "Building lists..."

build_list() {
    base="$1"; shift
    sort -n -S 50% "$@" | gawk -v base="$base" '
    BEGIN {
        for (i=0; i<=32; i++) P[i] = lshift(1, i)
        rsc = base ".rsc"
        ga = (base == "blocklist") ? "blocklist_ga.rsc" : "blocklist_ga_" substr(base, 11) ".rsc"
        txt = base ".txt"
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
        addr = "240.0.0.0/4"
        print addr >> txt
        print "add list=new_blocklist address=\"" addr "\" comment=\"blocklist\"" >> rsc
        print ":set newips ($newips,\"" addr "\")" >> ga
        count++
        print "  " base ": " count " entries" > "/dev/stderr"
    }'
}

build_list "blocklist"    "$CACHE"/*.out_s.ranges &
build_list "blocklist_l"  "$CACHE"/*.out_s.ranges "$CACHE"/*.out_l.ranges &
build_list "blocklist_xl" "$CACHE"/*.ranges &
wait

rm -rf "$CACHE"

cp -- *.rsc *.txt "$OUTDIR/"

cd "$OUTDIR"
git fetch origin
git reset --hard origin/main
git add -A
git commit -m "Autoupdated $(date +%Y-%m-%d)" || echo "No changes to commit"
git push
git gc --auto

echo "Done!"
```

### Generator Script (iprange version)

```sh
#!/bin/sh
# Blocklist aggregator - Alpine Linux (iprange version)
# Requires: apk add curl git gawk iprange
#   To install iprange from edge/testing:
#     echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories
#     apk update
#     apk add iprange
set -eu

export LC_ALL=C

WORKDIR="/path/to/blocklist"
OUTDIR="/path/to/mikrotik_blocklist"
EXCLUDE="$WORKDIR/.exclude"

cd "$WORKDIR"
rm -f -- *.out_* *.txt *.rsc 2>/dev/null || true

# Create exclusion file: reserved ranges + whitelist
cat > "$EXCLUDE" << 'EOF'
0.0.0.0/8
10.0.0.0/8
127.0.0.0/8
172.16.0.0/12
192.168.0.0/16
224.0.0.0/3
52.113.194.132
35.186.224.25
EOF

download() {
    url="$1"; output="$2"; name="$3"
    if curl -sfL --connect-timeout 30 --max-time 120 "$url" -o "$output" 2>/dev/null; then
        [ -s "$output" ] && echo "  + $name" || { echo "  ! $name (empty)"; exit 1; }
    else
        echo "  ! $name (failed)"; exit 1
    fi
}

echo "Downloading blocklists..."

download "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst" \
         "tor_exits.out_s" "Tor Exit Nodes" &
download "https://www.spamhaus.org/drop/drop.txt" \
         "spamhaus_drop.out_s" "Spamhaus DROP" &
download "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" \
         "sslbl.out_s" "SSL Blacklist" &
download "https://lists.blocklist.de/lists/all.txt" \
         "blocklist_de.out_s" "Blocklist.de" &
download "https://cinsscore.com/list/ci-badguys.txt" \
         "cinsarmy.out_l" "CINS Army" &
download "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
         "feodo.out_s" "Feodo Tracker" &
download "https://iplists.firehol.org/files/firehol_level1.netset" \
         "firehol_l1.out_s" "FireHOL L1" &
download "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt" \
         "ipsum_l1.out_xl" "IPsum L1" &
download "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" \
         "ipsum_l3.out_s" "IPsum L3" &
wait

for f in tor_exits.out_s spamhaus_drop.out_s sslbl.out_s blocklist_de.out_s \
         cinsarmy.out_l feodo.out_s firehol_l1.out_s ipsum_l1.out_xl ipsum_l3.out_s; do
    [ -s "$f" ] || { echo "  ! Missing: $f"; exit 1; }
done

echo "All downloads successful."
echo "Building lists..."

build_list() {
    base="$1"; shift

    {
        grep -hoE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' "$@" \
            | iprange - --optimize --except "$EXCLUDE"
        echo "240.0.0.0/4"
    } | gawk -v base="$base" '
    BEGIN {
        rsc = base ".rsc"
        ga = (base == "blocklist") ? "blocklist_ga.rsc" : "blocklist_ga_" substr(base, 11) ".rsc"
        txt = base ".txt"
        print "/ip firewall address-list" > rsc
        print ":global newips [:toarray \"\"]" > ga
    }
    {
        print >> txt
        print "add list=new_blocklist address=\"" $0 "\" comment=\"blocklist\"" >> rsc
        print ":set newips ($newips,\"" $0 "\")" >> ga
        count++
    }
    END { print "  " base ": " count " entries" > "/dev/stderr" }'
}

build_list "blocklist"    *.out_s &
build_list "blocklist_l"  *.out_s *.out_l &
build_list "blocklist_xl" *.out_* &
wait

rm -f "$EXCLUDE"

cp -- *.rsc *.txt "$OUTDIR/"

cd "$OUTDIR"
git fetch origin
git reset --hard origin/main
git add -A
git commit -m "Autoupdated $(date +%Y-%m-%d)" || echo "No changes to commit"
git push
git gc --auto

echo "Done!"
```

---

## RouterOS Implementation

### Firewall Setup

Before using the blocklist, ensure you have appropriate firewall rules. Consider using the `raw` table for best performance. See [MikroTik's Advanced Firewall Guide](https://help.mikrotik.com/docs/display/ROS/Building+Advanced+Firewall) for details.

Example rule (add to your firewall):
```
/ip firewall raw add chain=prerouting src-address-list=prod_blocklist action=drop comment="Drop blocklisted IPs"
```

### Script 1: Download

**Policy:** `ftp, read, write, test`  
**Schedule:** Every 3 hours

```
:log info "blocklist-DL: started"
/tool fetch url="https://raw.githubusercontent.com/multiduplikator/mikrotik_blocklist/main/blocklist_ga_l.rsc" mode=https
:log info "blocklist-DL: finished"
```

### Script 2: Differential Update

**Policy:** `read, write, test`  
**Schedule:** Every 3 hours, 5 minutes after download

This script performs differential updates — only adding new entries and removing stale ones. This approach maintains continuous protection without any gap in coverage.

```
:log info "blocklist-DIFF: === STARTED ==="
:local startTime [/system clock get time]

# Disable logging to prevent flood
/system logging disable 0

# Import new IPs into global array
/import file-name=blocklist_ga_l.rsc
:global newips

:local totalNew [:len $newips]
:if ($totalNew = 0) do={
    /system logging enable 0
    :log error "blocklist-DIFF: Empty import, aborting"
    :error "Empty blocklist import"
}

:log info "blocklist-DIFF: Imported $totalNew entries"

# Process existing entries
/ip firewall address-list

:local prdkeys [find list=prod_blocklist]
:local countKept 0
:local countRemoved 0

:foreach entryId in=$prdkeys do={
    :local addr [get $entryId address]
    :local keyindex [:find $newips $addr]
    
    # Check for nil (not found) - fixes index 0 bug
    :if ([:typeof $keyindex] != "nil") do={
        # EXISTS in new list - keep it, blank out to skip later
        :set ($newips->$keyindex) ""
        :set countKept ($countKept + 1)
    } else={
        # NOT in new list - remove
        remove $entryId
        :set countRemoved ($countRemoved + 1)
    }
}

:log info "blocklist-DIFF: Kept $countKept, removed $countRemoved"

# Add NEW entries (non-empty values remaining in $newips)
:local countAdded 0

:foreach addr in=$newips do={
    :if ($addr != "") do={
        add list=prod_blocklist address=$addr
        :set countAdded ($countAdded + 1)
    }
}

# Cleanup
:set newips

:local endTime [/system clock get time]
:local duration ($endTime - $startTime)

/system logging enable 0

:local finalCount [:len [/ip firewall address-list find list=prod_blocklist]]

:log info "blocklist-DIFF: === COMPLETED ==="
:log info "blocklist-DIFF: Removed=$countRemoved, Added=$countAdded, Total=$finalCount"
:log info "blocklist-DIFF: Duration=$duration"
```

### Important Notes

1. **First Run:** On initial setup, `prod_blocklist` won't exist. The script will simply add all entries.

2. **Index 0 Bug Fix:** Previous versions used `:if ($keyindex > 0)` which incorrectly handled IPs at array index 0. The fix uses `:if ([:typeof $keyindex] != "nil")` to properly detect if an IP was found.

3. **Performance:** Expect 90-150 seconds for ~25k entries on a CCR-1036 or CCR-2004

4. **Logging:** The script disables logging rule 0 during execution to prevent thousands of "address-list entry added/removed" log messages.

---

## License

This project aggregates publicly available threat intelligence feeds. Please respect the terms of use of each source.
