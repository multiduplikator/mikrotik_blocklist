# Self-test for the blocklist RouterOS scripts (RouterOS 7).
#
# Runs your INSTALLED download and update scripts against a scratch
# address-list ("blocklist-selftest") and scratch file instead of
# prod_blocklist / blocklist_l.json, and checks normal and failure
# behaviour. prod_blocklist is never touched: the test refuses to run if
# any reference to it is left after swapping in the scratch names.
#
# Test addresses are from ranges reserved for documentation/testing
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15).
# T13 downloads the real blocklist_l.json once (~500 KB) into the
# scratch file to test the certificate check; it is deleted afterwards.
#
# Usage: upload, then /import file-name=routeros-selftest.rsc
# Set the names below if your scripts are named differently. Takes about
# a minute. Do not run it while the scheduled update is running.

{
:local dlScript "blocklist-dl"
:local diffScript "blocklist-diff"

:local TL "blocklist-selftest"
:local TF "blocklist-selftest.json"
:local pass 0
:local fail 0

# ---------------------------------------------------------------- helpers
:local replace do={
    :local s $1
    :local out ""
    :local i [:find $s $2]
    :while ([:typeof $i] != "nil") do={
        :set out ($out . [:pick $s 0 $i] . $3)
        :set s [:pick $s ($i + [:len $2]) [:len $s]]
        :set i [:find $s $2]
    }
    :return ($out . $s)
}
:local writeFile do={
    /file remove [find name=$1]
    /file add name=$1 contents=$2
    :delay 1s
}
:local setList do={
    /ip firewall address-list remove [find list=$1]
    :foreach a in=$2 do={ /ip firewall address-list add list=$1 address=$a }
}
# true if address-list $1 holds exactly the addresses in array $2
:local listIs do={
    :local ids [/ip firewall address-list find list=$1]
    :if ([:len $ids] != [:len $2]) do={ :return false }
    :foreach a in=$2 do={
        :local found false
        :foreach id in=$ids do={
            :if ([:tostr [/ip firewall address-list get $id address]] = [:tostr $a]) do={ :set found true }
        }
        :if (!$found) do={ :return false }
    }
    :return true
}
:local idOf do={
    :foreach id in=[/ip firewall address-list find list=$1] do={
        :if ([:tostr [/ip firewall address-list get $id address]] = $2) do={ :return $id }
    }
    :return ""
}
# disabled-state of the logging rule the update script silences ("" if none)
:local logState do={
    :local rule [:pick [/system logging find where topics~"info"] 0]
    :if ([:typeof $rule] != "id") do={ :return "" }
    :return [:tostr [/system logging get $rule disabled]]
}
# run script source $1; returns "ok" or "error"
:local run do={
    :local fn [:parse $1]
    :local r "ok"
    :do { $fn } on-error={ :set r "error" }
    :return $r
}
:local check do={
    :if ($1) do={ :put ("  PASS  " . $2) } else={ :put ("  FAIL  " . $2) }
    :return $1
}

# ------------------------------------------------- patch installed scripts
:if (([:len [/system script find name=$diffScript]] = 0) || ([:len [/system script find name=$dlScript]] = 0)) do={
    :error "selftest: scripts $dlScript / $diffScript not found -- set the names at the top"
}
:local diffSrc [/system script get [find name=$diffScript] source]
:local dlSrc [/system script get [find name=$dlScript] source]
:if (([:typeof [:find $diffSrc "\"prod_blocklist\""]] = "nil") || ([:typeof [:find $diffSrc "\"blocklist_l.json\""]] = "nil")) do={
    :error "selftest: $diffScript does not contain \"prod_blocklist\" and \"blocklist_l.json\" -- adjust the test"
}
:local q "\""
# RouterOS does not process \" escapes in arguments to script functions,
# so every string with quotes is built here and passed as a variable.
:local pProd ($q . "prod_blocklist" . $q)
:local pFile ($q . "blocklist_l.json" . $q)
:local pTL ($q . $TL . $q)
:local pTF ($q . $TF . $q)
:local pUrl ("/main/blocklist_l.json" . $q)
:local pUrlBad ("/main/selftest-does-not-exist.json" . $q)
:set diffSrc [$replace $diffSrc $pProd $pTL]
:set diffSrc [$replace $diffSrc $pFile $pTF]
# download with the real URL into the scratch file
:local dlReal [$replace $dlSrc $pFile $pTF]
# download from a URL that does not exist
:local dlBad [$replace $dlReal $pUrl $pUrlBad]
:if (([:typeof [:find $diffSrc "prod_blocklist"]] != "nil") || ([:typeof [:find $diffSrc "blocklist_l.json"]] != "nil") || ([:typeof [:find $dlReal "\"blocklist_l.json\""]] != "nil") || ([:typeof [:find $dlBad "blocklist_l.json"]] != "nil")) do={
    :error "selftest: could not redirect the scripts to scratch names -- aborting, nothing was run"
}
:local logBefore [$logState]

# ------------------------------------------------------------ test data
# Two 32 KB blocks; first octet "198" continues in block 2. 6 entries.
:local pad " "
:while ([:len $pad] < 32768) do={ :set pad ($pad . $pad) }
:local b1 "{\"#\":{\"format\":1,\"entries\":6},\"198\":{\"51\":{\"100.1\":1,\"100.2\":1,\"100.16/28\":1}},\"203\":{\"0\":{\"113.1\":1}}}"
:local b2 "{\"198\":{\"18\":{\"0.1\":1}},\"192\":{\"0\":{\"2.1\":1}}}"
:local valid ($b1 . [:pick $pad 0 (32768 - [:len $b1])] . $b2)
:local want {"198.51.100.1";"198.51.100.2";"198.51.100.16/28";"203.0.113.1";"198.18.0.1";"192.0.2.1"}
:local before {"198.51.100.1";"203.0.113.1";"198.51.100.16/28";"203.0.113.99";"192.0.2.200"}
:local want9 {"198.51.100.1";"198.51.100.2";"198.51.100.16/28";"203.0.113.1";"198.18.0.1"}
:local small {"198.51.100.1";"192.0.2.200"}
:local r
:local ok

:put "== blocklist self-test =="
:do {
    :local probe [:deserialize from=json "{\"a\":{\"b\":{\"c\":1,\"d\":2}}}"]
    :set ((($probe->"a")->"b")->"c")
    :put ("  info  nested :set delete: " . [:len (($probe->"a")->"b")] . " key(s) left (1 = works)")
} on-error={ :put "  info  nested :set delete: not supported" }

# T1: normal update with keep / remove / add, across two blocks
[$writeFile $TF $valid]
[$setList $TL $before]
:local keepId [$idOf $TL "198.51.100.1"]
:set r [$run $diffSrc]
:set ok (($r = "ok") && [$listIs $TL $want] && ([$idOf $TL "198.51.100.1"] = $keepId) && ([$logState] = $logBefore))
:if ([$check $ok "T1 update: 3 kept (same entries), 2 removed, 3 added, CIDR and block continuation"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }

# T2: same file again changes nothing
:set keepId [$idOf $TL "192.0.2.1"]
:set r [$run $diffSrc]
:set ok (($r = "ok") && [$listIs $TL $want] && ([$idOf $TL "192.0.2.1"] = $keepId) && ([$logState] = $logBefore))
:if ([$check $ok "T2 rerun with same file: no change"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }

# T3: first run, list empty: everything added
/ip firewall address-list remove [find list=$TL]
:set r [$run $diffSrc]
:set ok (($r = "ok") && [$listIs $TL $want] && ([$logState] = $logBefore))
:if ([$check $ok "T3 first run (empty list): all 6 added"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }

# T4-T8: bad files must abort with an error and leave the list untouched.
# Each file is built only when needed: variables are limited to ~64 KB.
:foreach name in={"T4 truncated download (header says 6, file has 4)";"T5 corrupt JSON block";"T6 unknown format version";"T7 empty file";"T8 missing file"} do={
    :local content ""
    :local t [:pick $name 0 2]
    :if ($t = "T4") do={ :set content ($b1 . [:pick $pad 0 (32768 - [:len $b1])]) }
    :if ($t = "T5") do={ :set content ($b1 . [:pick $pad 0 (32768 - [:len $b1])] . "{\"198\":{\"18\":{\"0.1\":1}") }
    :if ($t = "T6") do={
        :local fmt1 ($q . "format" . $q . ":1")
        :local fmt2 ($q . "format" . $q . ":2")
        :local f2 [$replace $b1 $fmt1 $fmt2]
        :set content ($f2 . [:pick $pad 0 (32768 - [:len $f2])] . $b2)
    }
    [$setList $TL $before]
    :if ($t = "T8") do={ /file remove [find name=$TF]; :delay 1s } else={ [$writeFile $TF $content] }
    :set r [$run $diffSrc]
    :set ok (($r = "error") && [$listIs $TL $before] && ([$logState] = $logBefore))
    :if ([$check $ok ($name . ": aborted, list untouched")]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }
}

# T9: an entry the router rejects (invalid prefix): the others are
# still added, the run completes, logging restored
:local e21 ($q . "2.1" . $q . ":1")
# 192.0.2.1/33 is neither a valid prefix nor a valid DNS name
:local e2bad ($q . "2.1/33" . $q . ":1")
:local b2bad [$replace $b2 $e21 $e2bad]
[$writeFile $TF ($b1 . [:pick $pad 0 (32768 - [:len $b1])] . $b2bad)]
[$setList $TL $before]
:set r [$run $diffSrc]
:set ok (($r = "ok") && [$listIs $TL $want9] && ([$logState] = $logBefore))
:if ([$check $ok "T9 one entry rejected by RouterOS: the other 5 still applied"]) do={ :set pass ($pass + 1) } else={
    :set fail ($fail + 1)
    :put "        result=$r, list now:"
    :foreach id in=[/ip firewall address-list find list=$TL] do={ :put ("          " . [/ip firewall address-list get $id address]) }
}

# T10: an entry wider than /10 is skipped (starts from the 6 valid
# entries, so the change stays below the 30% limit)
:local n6 ($q . "entries" . $q . ":6")
:local n7 ($q . "entries" . $q . ":7")
:local g18 ($q . "18" . $q . ":{" . $q . "0.1" . $q . ":1}")
:local g18w ($g18 . "," . $q . "0" . $q . ":{" . $q . "0.0/8" . $q . ":1}")
:local b1w [$replace $b1 $n6 $n7]
:local b2w [$replace $b2 $g18 $g18w]
[$writeFile $TF ($b1w . [:pick $pad 0 (32768 - [:len $b1w])] . $b2w)]
[$setList $TL $want]
:set r [$run $diffSrc]
:set ok (($r = "ok") && [$listIs $TL $want] && ([$logState] = $logBefore))
:if ([$check $ok "T10 entry wider than /10 (198.0.0.0/8): skipped"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }

# T11: list would change by far more than 30%: abort, list untouched
[$writeFile $TF $valid]
[$setList $TL $small]
:set r [$run $diffSrc]
:set ok (($r = "error") && [$listIs $TL $small] && ([$logState] = $logBefore))
:if ([$check $ok "T11 change from 2 to 6 entries (>30%): aborted, list untouched"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }

# T12: failed download reports an error; info on the previous file
[$writeFile $TF $valid]
:local sizeBefore [/file get [find name=$TF] size]
:set r [$run $dlBad]
:local sizeAfter "missing"
:if ([:len [/file find name=$TF]] > 0) do={ :set sizeAfter [/file get [find name=$TF] size] }
:if ([$check ($r = "error") "T12 failed download: reports an error"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }
:put ("  info  previous file after a failed download: " . $sizeBefore . " -> " . $sizeAfter . " bytes")

# T13: real download with certificate check
/file remove [find name=$TF]
:set r [$run $dlReal]
:local got 0
:if ([:len [/file find name=$TF]] > 0) do={ :set got [/file get [find name=$TF] size] }
:if ([$check (($r = "ok") && ($got > 100000)) "T13 download with certificate check: ok"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r size=$got" }

# cleanup
/ip firewall address-list remove [find list=$TL]
/file remove [find name=$TF]
:put ("== " . $pass . " passed, " . $fail . " failed ==")
}
