# MikroTik Blocklist

An aggregated IP blocklist for MikroTik RouterOS firewalls, compiled from multiple threat intelligence sources. Tried and tested on ROS 7.24.5 - latest at the time of writing.

## Overview

This project provides pre-aggregated blocklists optimized for MikroTik routers. By using CIDR prefix aggregation, we minimize the number of address-list entries while maintaining comprehensive coverage — improving router performance and reducing memory usage.

**Update frequency:** Every 3 hours (automated via GitHub Actions)

## Available Lists

| List | File | Entries | Sources |
|------|------|---------|---------|
| Standard | `blocklist.txt` / `blocklist_ga.rsc` | ~30k | Core threat feeds |
| Large | `blocklist_l.txt` / `blocklist_ga_l.rsc` | ~40k | Core + CINS Army |
| Extra Large | `blocklist_xl.txt` / `blocklist_ga_xl.rsc` | ~110k | All threat sources including IPsum L1 |

## Sources

| Source | Description | Standard | Large | XL |
|--------|-------------|:--------:|:-----:|:--:|
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Hijacked / criminal netblocks ("Don't Route Or Peer") | ✓ | ✓ | ✓ |
| [Spamhaus EDROP](https://www.spamhaus.org/drop/) | Extended DROP (suballocations) | ✓ | ✓ | ✓ |
| [SSL Blacklist](https://sslbl.abuse.ch/) | IPs hosting known malicious TLS certs | ✓ | ✓ | ✓ |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Banking trojan C&C servers | ✓ | ✓ | ✓ |
| [ThreatFox](https://threatfox.abuse.ch/) | Active malware campaign IOCs (IP:port export) | ✓ | ✓ | ✓ |
| [DShield](https://www.dshield.org/) | SANS ISC top attackers (startIP-endIP-netmask format) | ✓ | ✓ | ✓ |
| [Blocklist.de](https://lists.blocklist.de/) | Fail2ban-reported IPs across participating servers | ✓ | ✓ | ✓ |
| [FireHOL Level 1](https://iplists.firehol.org/) | Aggregated high-confidence threat intelligence | ✓ | ✓ | ✓ |
| [IPsum Level 3](https://github.com/stamparm/ipsum) | High-confidence threat IPs (3+ list hits) | ✓ | ✓ | ✓ |
| [CINS Army](https://cinsscore.com/) | Sentinel IPS community feed | | ✓ | ✓ |
| [IPsum Level 1](https://github.com/stamparm/ipsum) | Broader threat IPs (1+ list hits) | | | ✓ |

## Filtered Addresses

The following are automatically excluded from feed input:

- Private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- CGNAT: `100.64.0.0/10` (RFC 6598)
- Loopback: `127.0.0.0/8`
- Link-local: `169.254.0.0/16` (RFC 3927)
- Multicast + reserved: `224.0.0.0/3` (covers `224.0.0.0/4` multicast and `240.0.0.0/4` IANA-reserved)
- Zero-network: `0.0.0.0/8`
- Whitelisted: `52.113.194.132` (Microsoft Teams), `35.186.224.25` (Microsoft Teams)

---

## Blocklist Generation

The generator lives in [`generate.sh`](generate.sh) and runs under GitHub Actions every 3 hours via [`.github/workflows/update_blocklist.yml`](.github/workflows/update_blocklist.yml). Feed URLs, tier assignments, timeouts, retry counts, and the soft-fail threshold are all hoisted to constants at the top of `generate.sh` — edit there.

**Dependencies:** `sh`, `sed`, `grep`, `gawk`, `curl`. All present by default on `ubuntu-latest` GitHub runners.

**Key behaviors:**

- Per-feed HTTP retries with a polite `User-Agent` (`curl --retry 3 --retry-delay 5 --retry-connrefused --retry-all-errors`).
- Parallel downloads.
- Soft-fail: tolerates up to `MAX_FAILED_FEEDS` (2) missing/empty feeds before aborting.
- **DShield preprocess** — DShield ships `startIP<TAB>endIP<TAB>netmask` per row; the generic regex extractor would treat only the two edge IPs as /32s and miss everything between. A dedicated preprocess step converts to CIDR, with a **format-drift guard** that drops the feed if <50% of rows survive (protects against a silent ~99% coverage loss if DShield changes format).
- **Reserved-range filter** removes RFC 1918/6598/3927 space, loopback, multicast, and IANA-reserved from feed input at extract time (see [Filtered Addresses](#filtered-addresses) above).
- Every tier must produce ranges — if any tier is empty, generation aborts loudly so CI surfaces the outage rather than shipping yesterday's committed files.
- **Delta regression check** in CI fails the run if any tier moves >30% vs the previous commit.

### Credits

The generator script and the GitHub Actions pipeline are based on the work in the [Davie3/mikrotik_blocklist](https://github.com/Davie3/mikrotik_blocklist) fork, which added the Spamhaus EDROP, DShield, and ThreatFox feeds, the DShield CIDR preprocess with format-drift guard, the broader reserved-range filter, and the self-hosted CI pipeline. This repository adopts those changes (with the Tor-exit list omitted, as its upstream feed is no longer maintained) and repoints the generator and router download URLs to this repository.

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
