# MikroTik Blocklist

An aggregated IP blocklist for MikroTik RouterOS firewalls, compiled from multiple threat intelligence sources. Tried and tested on ROS 7.24.5 - latest at the time of writing.

## Overview

This project provides pre-aggregated blocklists optimized for MikroTik routers. By using CIDR prefix aggregation, we minimize the number of address-list entries while maintaining comprehensive coverage — improving router performance and reducing memory usage.

**Update frequency:** Every 3 hours (automated via GitHub Actions)

## Available Lists

| List | RouterOS (recommended) | Plain text / legacy | Entries | Sources |
|------|------|------|---------|---------|
| Standard | `blocklist.json` | `blocklist.txt` / `blocklist_ga.rsc` | ~28k | Core threat feeds |
| Large | `blocklist_l.json` | `blocklist_l.txt` / `blocklist_ga_l.rsc` | ~36k | Core + CINS Army |
| Extra Large | `blocklist_xl.json` | `blocklist_xl.txt` / `blocklist_ga_xl.rsc` | ~100k | All threat sources including IPsum L1 |

The `.json` files are made for the [RouterOS scripts](#routeros-implementation) below (RouterOS 7.13+). `blocklist*.rsc` are plain `add` commands, `blocklist_ga*.rsc` feed the [legacy scripts](#important-notes).

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
3. **Build** the three lists: overlapping and adjacent ranges are merged, whitelisted addresses are cut out, and the result is written as the smallest set of CIDR blocks in all four file formats. The `.json` files are packed into 32 KB blocks, each a self-contained JSON object that RouterOS can read and parse in one step.
4. **Check** the new lists, then replace the old ones. Nothing is overwritten until every check below has passed.

### Failure policy: all or nothing

Routers remove any address that disappears from the list, so shipping a list with a feed missing is worse than shipping no update. A run therefore fails, and leaves every list exactly as it was, if:

- any feed still fails to download after retries;
- any feed yields fewer ranges than its configured minimum (catches dead feeds, empty files and HTML error pages served instead of data);
- the DShield file no longer looks like the expected format;
- any list entry is wider than /10 (correct output is never wider than about /12);
- any list is outside its expected size, or changed by more than 30% since the last run;
- any output line has an unexpected shape, the `.txt` and `.rsc` files disagree, or a `.json` block is malformed or its entry count is wrong.

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

Downloads the list as `blocklist_l.json`. Use `blocklist.json` or `blocklist_xl.json` for the other tiers, and use the same file name in Script 2.

```
:local url "https://raw.githubusercontent.com/multiduplikator/mikrotik_blocklist/main/blocklist_l.json"
:local file "blocklist_l.json"

:log info "blocklist-DL: started"
:do {
    # Verify GitHub's certificate. Uses RouterOS's built-in root CAs
    # (7.19+, see Important Notes); on older versions import a CA bundle.
    /tool fetch url=$url dst-path=$file check-certificate=yes-without-crl
} on-error={
    :log error "blocklist-DL: download failed; the update script will reject an incomplete file"
    :error "blocklist download failed"
}
:log info ("blocklist-DL: finished, " . [/file get $file size] . " bytes")
```

### Script 2: Differential Update

**Policy:** `read, write, test`  
**Schedule:** Every 3 hours, 5 minutes after the download  
**Requires:** RouterOS 7 with `:deserialize`. Tested on 7.24.5; older 7.x versions are untested.

The script updates `prod_blocklist` in place. It removes entries that are no longer listed and adds new ones, so the list is active at every moment and RouterOS never holds a second copy of it.

```
:local file "blocklist_l.json"
:local listName "prod_blocklist"
:local block 32768
# Safety limits: abort if the list would grow or shrink by more than
# maxChange percent (raise it once when switching to another tier), and
# never add an entry wider than /minPrefix.
:local maxChange 30
:local minPrefix 10

:log info "blocklist-DIFF: === STARTED ==="
:local startTime [:timestamp]

# ----------------------------------------------------------------------------
# STEP 1: Load and verify the new list. Nothing is changed yet.
# The file is a sequence of 32 KB blocks, each one JSON object:
#   first octet -> second octet -> rest of the address -> 1
# deserialize builds each block's nested keyed array in one call.
# ----------------------------------------------------------------------------
:if ([:len [/file find name=$file]] = 0) do={
    :log error "blocklist-DIFF: $file not found, aborting"
    :error "blocklist file missing"
}
:local size [/file get $file size]
:local bl [:toarray ""]
:local format 0
:local expected -1
:do {
    :for off from=0 to=($size - 1) step=$block do={
        :local r [/file read file=$file offset=$off chunk-size=$block as-value]
        :local data ($r->"data")
        :if ([:typeof $data] = "nothing") do={ :set data $r }
        :foreach o1,g in=[:deserialize from=json options=json.no-string-conversion $data] do={
            :if ($o1 = "#") do={
                :set format ($g->"format")
                :set expected ($g->"entries")
            } else={
                :if ([:typeof ($bl->$o1)] = "nothing") do={
                    :set ($bl->$o1) $g
                } else={
                    # first octet continues from the previous block: merge
                    :local b1 ($bl->$o1)
                    :foreach o2,rs in=$g do={ :set ($b1->$o2) $rs }
                    :set ($bl->$o1) $b1
                }
            }
        }
    }
} on-error={
    :log error "blocklist-DIFF: $file is unreadable or not valid JSON (incomplete download?), aborting"
    :error "blocklist file unreadable"
}
:local total 0
:foreach o1,g in=$bl do={ :foreach o2,rs in=$g do={ :set total ($total + [:len $rs]) } }
:if (($format != 1) || ($total = 0) || ($total != $expected)) do={
    :log error "blocklist-DIFF: $file invalid (format $format, $total of $expected entries), aborting"
    :error "blocklist file invalid"
}
:local current [:len [/ip firewall address-list find list=$listName]]
:if ($current > 0) do={
    :local change ($total - $current)
    :if ($change < 0) do={ :set change (0 - $change) }
    :if (($change * 100) > ($current * $maxChange)) do={
        :log error "blocklist-DIFF: list would change from $current to $total entries (limit $maxChange%), aborting"
        :error "blocklist change too large"
    }
}
:log info "blocklist-DIFF: Loaded $total entries, list has $current"

# ----------------------------------------------------------------------------
# STEP 2: Walk the current list. Entries still listed are kept and ticked
# off in $bl; all others are removed. STEP 3: what is left in $bl is new.
# ----------------------------------------------------------------------------
:local kept 0
:local removed 0
:local added 0
:local failed 0
:local skipped 0

# Silence the info logging rule while the list changes (avoids thousands
# of add/remove messages); its previous state is restored afterwards.
:local logRule [:pick [/system logging find where topics~"info"] 0]
:local logWasOff true
:if ([:typeof $logRule] = "id") do={
    :set logWasOff [/system logging get $logRule disabled]
    /system logging disable $logRule
}

:do {
    /ip firewall address-list
    :foreach id in=[find list=$listName] do={
        :local s [:tostr [get $id address]]
        :local i1 [:find $s "."]
        :local i2 [:find $s "." $i1]
        :local p1 [:pick $s 0 $i1]
        :local p2 [:pick $s ($i1 + 1) $i2]
        :local rest [:pick $s ($i2 + 1) [:len $s]]
        :if ([:typeof ((($bl->$p1)->$p2)->$rest)] != "nothing") do={
            # still listed: keep it, and tick it off in $bl
            :set ((($bl->$p1)->$p2)->$rest)
            :set kept ($kept + 1)
        } else={
            remove $id
            :set removed ($removed + 1)
        }
    }

    :foreach o1,g in=$bl do={
        :foreach o2,rs in=$g do={
            :foreach rest,v in=$rs do={
                :local plen 32
                :local slash [:find $rest "/"]
                :if ([:typeof $slash] != "nil") do={ :set plen [:tonum [:pick $rest ($slash + 1) [:len $rest]]] }
                :if (([:typeof $plen] = "num") && ($plen < $minPrefix)) do={
                    :set skipped ($skipped + 1)
                } else={
                    # one bad entry must not stop the others
                    :do {
                        add list=$listName address=($o1 . "." . $o2 . "." . $rest)
                        :set added ($added + 1)
                    } on-error={ :set failed ($failed + 1) }
                }
            }
        }
    }
} on-error={
    :if (([:typeof $logRule] = "id") && !$logWasOff) do={ /system logging enable $logRule }
    :log error "blocklist-DIFF: failed after removing $removed and adding $added entries"
    :error "blocklist update failed"
}

:if (([:typeof $logRule] = "id") && !$logWasOff) do={ /system logging enable $logRule }
:set bl

:local finalCount [:len [/ip firewall address-list find list=$listName]]
:log info "blocklist-DIFF: === COMPLETED ==="
:log info "blocklist-DIFF: Kept=$kept, Removed=$removed, Added=$added, Total=$finalCount"
:if (($failed + $skipped) > 0) do={
    :log warning "blocklist-DIFF: $failed entries could not be added, $skipped skipped as wider than /$minPrefix"
}
:if ($finalCount != ($total - $failed - $skipped)) do={
    :log warning ("blocklist-DIFF: list has " . $finalCount . " entries, expected " . ($total - $failed - $skipped))
}
:log info ("blocklist-DIFF: Duration=" . ([:timestamp] - $startTime))
```

### Important Notes

1. **First run:** on initial setup, `prod_blocklist` doesn't exist yet. The script simply adds all entries; the size check only applies once the list exists.

2. **Safe failure:** the update aborts before changing anything if the file is missing, unreadable or not valid JSON, if the header's entry count does not match what was loaded, or if the list would change by more than `maxChange` percent. The current list then stays as it is. If a single entry can't be added, the others still are, and the run ends with a warning.

3. **Performance:** measured on a CCR2004-16G-2S+ with RouterOS 7.24.5 and the large list (~36k entries). Updates take about **21–24 s**; one that kept 33,368 entries, removed 3,199 and added 3,004 took 23.5 s. The legacy `.rsc` scripts took 2 min 33 s for a comparable update.

4. **Why JSON blocks:** RouterOS arrays are copied whenever they are modified, so building a 36k-entry array one entry at a time is slow (measured: 26 s by appending, 6.5 min as a keyed array). `:deserialize` builds each block's keyed array natively in one call. The blocks are 32 KB because `/file read` reads at most that much per call.

5. **Logging:** the script silences the `info` logging rule only while the list is being changed, to avoid thousands of "address-list entry added/removed" messages. Afterwards, or if the update fails, the rule is restored to the state it had before.

6. **Security:** Script 1 verifies GitHub's TLS certificate (`check-certificate=yes-without-crl`). RouterOS 7.21+ trusts its built-in root CAs for `fetch` by default (`/certificate/settings print` shows `builtin-trust-store`). On 7.19 and 7.20 enable them with `/certificate/settings/set builtin-trust-anchors=trusted`; on older versions import a CA bundle. As a second line of defence, Script 2 never adds entries wider than `/minPrefix` and refuses list changes larger than `maxChange` percent.

7. **Self-test:** [`tests/routeros-selftest.rsc`](tests/routeros-selftest.rsc) runs your installed scripts against a scratch list and checks the normal update and the failure cases above, without touching `prod_blocklist`.

<details>
<summary>Legacy scripts (<code>blocklist_ga*.rsc</code>)</summary>

The `blocklist_ga*.rsc` files are still published for existing setups. They work on older RouterOS versions but are much slower: the import builds the array one append at a time and every lookup is a linear `:find`.

**Download:**

```
:log info "blocklist-DL: started"
/tool fetch url="https://raw.githubusercontent.com/multiduplikator/mikrotik_blocklist/main/blocklist_ga_l.rsc" mode=https
:log info "blocklist-DL: finished"
```

**Differential update:**

```
:log info "blocklist-DIFF: === STARTED ==="
:local startTime [/system clock get time]

/system logging disable 0

/import file-name=blocklist_ga_l.rsc
:global newips

:local totalNew [:len $newips]
:if ($totalNew = 0) do={
    /system logging enable 0
    :log error "blocklist-DIFF: Empty import, aborting"
    :error "Empty blocklist import"
}

:log info "blocklist-DIFF: Imported $totalNew entries"

/ip firewall address-list

:local prdkeys [find list=prod_blocklist]
:local countKept 0
:local countRemoved 0

:foreach entryId in=$prdkeys do={
    :local addr [get $entryId address]
    :local keyindex [:find $newips $addr]
    :if ([:typeof $keyindex] != "nil") do={
        :set ($newips->$keyindex) ""
        :set countKept ($countKept + 1)
    } else={
        remove $entryId
        :set countRemoved ($countRemoved + 1)
    }
}

:local countAdded 0
:foreach addr in=$newips do={
    :if ($addr != "") do={
        add list=prod_blocklist address=$addr
        :set countAdded ($countAdded + 1)
    }
}

:set newips
:local duration ([/system clock get time] - $startTime)
/system logging enable 0

:local finalCount [:len [/ip firewall address-list find list=prod_blocklist]]
:log info "blocklist-DIFF: === COMPLETED ==="
:log info "blocklist-DIFF: Removed=$countRemoved, Added=$countAdded, Total=$finalCount"
:log info "blocklist-DIFF: Duration=$duration"
```

</details>

---

## License

This project aggregates publicly available threat intelligence feeds. Please respect the terms of use of each source.
