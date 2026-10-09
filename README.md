# MikroTik Blocklist

An aggregated IP blocklist for MikroTik RouterOS firewalls, compiled from multiple threat intelligence sources. Tried and tested on ROS 7.24.5 - latest at the time of writing.

## Overview

This project provides pre-aggregated blocklists optimized for MikroTik routers. By using CIDR prefix aggregation, we minimize the number of address-list entries while maintaining comprehensive coverage — improving router performance and reducing memory usage.

**Update frequency:** Every 3 hours (automated via GitHub Actions)

## Available Lists

| List | File | Entries | Sources |
|------|------|---------|---------|
| Standard | `blocklist.txt` / `blocklist_ga.rsc` | ~28k | Core threat feeds |
| Large | `blocklist_l.txt` / `blocklist_ga_l.rsc` | ~36k | Core + CINS Army |
| Extra Large | `blocklist_xl.txt` / `blocklist_ga_xl.rsc` | ~100k | All threat sources including IPsum L1 |

## Sources

| Source | Description | Standard | Large | XL |
|--------|-------------|:--------:|:-----:|:--:|
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Hijacked / criminal netblocks ("Don't Route Or Peer") | ✓ | ✓ | ✓ |
| [ThreatFox](https://threatfox.abuse.ch/) | Active malware campaign IOCs (IP:port export) | ✓ | ✓ | ✓ |
| [DShield](https://www.dshield.org/) | SANS ISC top attackers (startIP-endIP-netmask format) | ✓ | ✓ | ✓ |
| [Blocklist.de](https://lists.blocklist.de/) | Fail2ban-reported IPs across participating servers | ✓ | ✓ | ✓ |
| [FireHOL Level 1](https://iplists.firehol.org/) | Aggregated high-confidence threat intelligence | ✓ | ✓ | ✓ |
| [IPsum Level 3](https://github.com/stamparm/ipsum) | High-confidence threat IPs (3+ list hits) | ✓ | ✓ | ✓ |
| [ET Compromised IPs](https://rules.emergingthreats.net/blockrules/) | Proofpoint Emerging Threats list of known compromised hosts | ✓ | ✓ | ✓ |
| [CINS Army](https://cinsscore.com/) | Sentinel IPS community feed | | ✓ | ✓ |
| [IPsum Level 1](https://github.com/stamparm/ipsum) | Broader threat IPs (1+ list hits) | | | ✓ |

Retired feeds: Spamhaus EDROP (merged into DROP upstream), SSL Blacklist (deprecated by abuse.ch on 2025-01-03) and Feodo Tracker (unmaintained since March 2026; abuse.ch's C2 data lives on in ThreatFox).

## Filtered Addresses

The following are never blocked:

- Private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- CGNAT: `100.64.0.0/10` (RFC 6598)
- Loopback: `127.0.0.0/8`
- Link-local: `169.254.0.0/16` (RFC 3927)
- Multicast + reserved: `224.0.0.0/3` (covers `224.0.0.0/4` multicast and `240.0.0.0/4` IANA-reserved)
- Zero-network: `0.0.0.0/8`
- Whitelisted: `52.113.194.132` (Microsoft Teams), `35.186.224.25` (Microsoft Teams). The whitelist is the `WHITELIST` setting in `generate.sh` and takes IPs or CIDRs (/16 to /32). If a feed lists a wider range containing a whitelisted address, the range is split so that only the whitelisted part is left out (e.g. a /24 around one whitelisted IP becomes 8 smaller blocks).

---

## Blocklist Generation

The generator lives in [`generate.sh`](generate.sh) and runs under GitHub Actions every 3 hours via [`.github/workflows/update_blocklist.yml`](.github/workflows/update_blocklist.yml). All settings (feeds, tiers, per-feed minimums, list bounds, whitelist, timeouts, retries) are constants at the top of `generate.sh`.

**Dependencies:** a POSIX `sh`, `curl`, `sort`, and any POSIX `awk`. gawk, mawk and busybox awk are all tested and produce byte-identical output.

**Running locally:** `sh generate.sh` writes the lists next to the script. `sh tests/run.sh` runs the offline test suite.

### How a run works

1. **Download** all feeds in parallel. Each download goes to a temporary file that is only kept if the transfer completes and is not empty, so a truncated feed can never pass as a good one. curl retries failed transfers itself. Any feed that is still unusable after extraction (failed, empty, below its minimum, or an error page instead of data) is downloaded and checked once more in a second pass a minute later.
2. **Extract** IPv4 addresses and CIDRs from each feed. Comment lines are skipped, invalid entries ignored, and [reserved address space](#filtered-addresses) dropped. DShield's `startIP endIP netmask` rows are converted to CIDRs first.
3. **Build** the three lists: overlapping and adjacent ranges are merged, whitelisted addresses are cut out, and the result is written as the smallest set of CIDR blocks in all three file formats.
4. **Check** the new lists, then replace the old ones. Nothing is overwritten until every check below has passed.

### Failure policy: all or nothing

Routers remove any address that disappears from the list, so shipping a list with a feed missing is worse than shipping no update. A run therefore fails, and leaves every list exactly as it was, if:

- any feed still fails to download after retries;
- any feed yields fewer ranges than its configured minimum (catches dead feeds, empty files and HTML error pages served instead of data);
- the DShield file no longer looks like the expected format;
- any list entry is wider than /10 (correct output is never wider than about /12);
- any list is outside its expected size, or changed by more than 30% since the last run;
- any output line has an unexpected shape, or the `.txt` and `.rsc` files disagree.

Errors name the failing feed or list and show up as annotations in the GitHub Actions run, which also gets a per-feed summary table. A failed scheduled run sends GitHub's failure email; routers keep importing the last good lists in the meantime.

### Tests and CI

- `tests/run.sh` runs the real `generate.sh` in offline mode against fixture feeds, with every installed awk (gawk, mawk, busybox). It checks the output byte-for-byte against `tests/expected` and runs a retry-pass recovery check and thirteen failure scenarios, each of which must abort without touching the existing lists. See [`tests/README.md`](tests/README.md) for details, how to update the expected output after an intended change, and how to try out a new feed offline.
- CI lints the scripts with shellcheck and runs the tests before every generation run. It clones only the latest commit, and only commits and pushes on `main`; a manual run on any other branch is a dry run.

### Credits

The generator script and the GitHub Actions pipeline are based on the work in the [Davie3/mikrotik_blocklist](https://github.com/Davie3/mikrotik_blocklist) fork, which added the Spamhaus EDROP (since merged into DROP upstream and removed here), DShield, and ThreatFox feeds, the DShield CIDR preprocess with format-drift guard, the broader reserved-range filter, and the self-hosted CI pipeline. This repository adopts those changes (with the Tor-exit list omitted, as its upstream feed is no longer maintained) and repoints the generator and router download URLs to this repository.

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
