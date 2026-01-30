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

| Source | Description |
|--------|-------------|
| [Tor Exit Nodes](https://github.com/SecOps-Institute/Tor-IP-Addresses) | Tor exit node IPs |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | "Don't Route Or Peer" list |
| [SSL Blacklist](https://sslbl.abuse.ch/) | Botnet C&C servers |
| [Blocklist.de](https://lists.blocklist.de/) | Fail2ban reported IPs |
| [CINS Army](https://cinsscore.com/) | Collective Intelligence Network Security |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Banking trojan C&C servers |
| [FireHOL Level 1](https://iplists.firehol.org/) | Aggregated threat intelligence |
| [IPsum](https://github.com/stamparm/ipsum) | Daily threat intelligence feed |

## Filtered Addresses

The following are automatically excluded:
- Private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback: `127.0.0.0/8`
- Multicast: `224.0.0.0/4`
- Reserved: `240.0.0.0/4` (added to blocklist), `0.0.0.0/8`
- Whitelisted: `52.113.194.132` (Microsoft Teams), `35.186.224.25` (Microsoft Teams)

---

## Blocklist Generation

The blocklist is generated using a bash script with embedded Python for IP extraction, validation, and CIDR aggregation.

### Dependencies

- `bash`
- `curl`
- `python3` (3.3+ with built-in `ipaddress` module)
- `git` (for publishing)

### Generator Script

```bash
#!/bin/bash
set -euo pipefail

WORKDIR="/path/to/working/directory"
OUTDIR="/path/to/output/directory"

cd "$WORKDIR"
rm -f *.out_* *.txt *.rsc 2>/dev/null || true

# Download function - exits on failure
download() {
    local url="$1"
    local output="$2"
    local name="$3"
    
    if curl -sfL --connect-timeout 30 --max-time 120 "$url" -o "$output" 2>/dev/null; then
        if [[ -s "$output" ]]; then
            echo "  ✓ $name"
        else
            echo "  ✗ $name (empty file)"
            exit 1
        fi
    else
        echo "  ✗ $name (download failed)"
        exit 1
    fi
}

echo "Downloading blocklists..."

download "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst" \
         "tor_exits.out_s" "Tor Exit Nodes"

download "https://www.spamhaus.org/drop/drop.txt" \
         "spamhaus_drop.out_s" "Spamhaus DROP"

download "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" \
         "sslbl.out_s" "SSL Blacklist"

download "https://lists.blocklist.de/lists/all.txt" \
         "blocklist_de.out_s" "Blocklist.de"

download "https://cinsscore.com/list/ci-badguys.txt" \
         "cinsarmy.out_l" "CINS Army"

download "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
         "feodo.out_s" "Feodo Tracker"

download "https://iplists.firehol.org/files/firehol_level1.netset" \
         "firehol_l1.out_s" "FireHOL L1"

download "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt" \
         "ipsum_l1.out_xl" "IPsum L1"

download "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" \
         "ipsum_l3.out_s" "IPsum L3"

echo "All downloads successful."

# Python script for extraction, filtering, and aggregation
python3 << 'PYTHON_SCRIPT'
import ipaddress
import re
import glob
import sys

# Regex for IPv4 with optional CIDR (with boundary checking to avoid false positives)
IP_PATTERN = re.compile(
    r'(?:^|[^\d])('
    r'(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
    r'(?:/(?:3[0-2]|[12]?\d))?'
    r')(?:[^\d]|$)'
)

EXCLUDE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('127.0.0.0/8'),
]

WHITELIST_IPS = {
    ipaddress.ip_address('52.113.194.132'),
    ipaddress.ip_address('35.186.224.25'),
}

def should_exclude(network):
    if network.num_addresses == 1:
        if network.network_address in WHITELIST_IPS:
            return True
    for excluded in EXCLUDE_NETWORKS:
        if network.subnet_of(excluded) or network.overlaps(excluded):
            return True
    return False

def extract_networks(files):
    networks = set()
    for filepath in files:
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                for match in IP_PATTERN.findall(content):
                    try:
                        addr = match if '/' in match else f"{match}/32"
                        net = ipaddress.ip_network(addr, strict=False)
                        if not should_exclude(net):
                            networks.add(net)
                    except ValueError:
                        continue
        except FileNotFoundError:
            print(f"ERROR: {filepath} not found", file=sys.stderr)
            sys.exit(1)
    return networks

def aggregate_and_save(files, output_base):
    networks = extract_networks(files)
    
    if not networks:
        print(f"ERROR: No valid IPs found for {output_base}", file=sys.stderr)
        sys.exit(1)
    
    # Collapse overlapping networks using Python's built-in function
    aggregated = list(ipaddress.collapse_addresses(sorted(networks)))
    aggregated.append(ipaddress.ip_network('240.0.0.0/4'))
    aggregated = sorted(set(aggregated))
    
    addresses = []
    for net in aggregated:
        addr = str(net.network_address) if net.prefixlen == 32 else str(net)
        addresses.append(addr)
    
    # Plain text list
    with open(f"{output_base}.txt", 'w') as f:
        f.write('\n'.join(addresses) + '\n')
    
    # Direct import .rsc file
    with open(f"{output_base}.rsc", 'w') as f:
        f.write("/ip firewall address-list\n")
        for addr in addresses:
            f.write(f'add list=new_blocklist address="{addr}" comment="blocklist"\n')
    
    # Array-based .rsc file for differential updates
    if output_base == "blocklist":
        ga_filename = "blocklist_ga.rsc"
    else:
        ga_filename = output_base.replace("blocklist_", "blocklist_ga_") + ".rsc"
    
    with open(ga_filename, 'w') as f:
        f.write(':global newips [:toarray ""]\n')
        for addr in addresses:
            f.write(f':set newips ($newips,"{addr}")\n')
    
    print(f"{output_base}: {len(addresses)} entries")

# Build lists with different source combinations
small_files = glob.glob("*.out_s")
large_files = glob.glob("*.out_s") + glob.glob("*.out_l")
xl_files = glob.glob("*.out_*")

aggregate_and_save(small_files, "blocklist")
aggregate_and_save(large_files, "blocklist_l")
aggregate_and_save(xl_files, "blocklist_xl")
PYTHON_SCRIPT

# Copy and publish
cp blocklist.rsc blocklist_ga.rsc \
   blocklist_l.rsc blocklist_ga_l.rsc \
   blocklist_xl.rsc blocklist_ga_xl.rsc \
   blocklist.txt blocklist_l.txt blocklist_xl.txt \
   "$OUTDIR/"

cd "$OUTDIR"
git add -A
git commit -m "Autoupdated $(date +%Y-%m-%d)" || echo "No changes to commit"
git push

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
