# mikrotik blocklist (aka blacklist)
In an attempt to make the solution compact as possible, we are trying to use prefix aggregation on a merged set of source lists.
This should increase the performance on the router while minimizing ressource usage and maintenance time.

Currently, this list updates every 3h - while working out what a good frequency would be.

There are now two lists maintained. The "normal" one, excluding cinsarmy and (ca. 25k entries). And another one with suffix "\_l", including everything (ca. 30k entries).
Yet, one more with suffix "\_xl", including everything and ipsum l1 (ca. 170k entries).

The following is ment as a reference for the blocklist sources, regex and basic mechanics - by no means should you cut, paste and run this in a production environement ... unless you add some proper error handling amongst other bells and whistles. 

### Aggregated blocklist for mikrotik (and others)

First, we grab the lists and extract IP/CIDR information from them (adding /32 where missing for aggregation later). In case your version of wget is a bit older, you might need to add `--secure-protocol=TLSv1_2` to make it download.

```
wget -O tor_exits.out https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst
wget -O spamhaus_drop.out https://www.spamhaus.org/drop/drop.txt
wget -O sslbl.out https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
wget -O blocklist_de.out https://lists.blocklist.de/lists/all.txt
wget -O cinsarmy.out https://cinsscore.com/list/ci-badguys.txt
wget -O feodo.out https://feodotracker.abuse.ch/downloads/ipblocklist.txt
wget -O firehol_l1.out https://iplists.firehol.org/files/firehol_level1.netset
wget -O ipsum_l1.out https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt

# dshield entires are in /24 
wget -O dshield.in https://feeds.dshield.org/block.txt
grep '^[1-9]' dshield.in | awk '{print $1"/24"}' > dshield.out
```

Alternatively, we could do the grab with curl (`-s` for silence):

```
curl https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst -o tor_exits.out_s
curl https://www.spamhaus.org/drop/drop.txt -o spamhaus_drop.out_s
curl https://sslbl.abuse.ch/blacklist/sslipblacklist.txt -o sslbl.out_s
curl https://lists.blocklist.de/lists/all.txt -o blocklist_de.out_s
curl https://cinsscore.com/list/ci-badguys.txt -o cinsarmy.out_l
curl https://feodotracker.abuse.ch/downloads/ipblocklist.txt -o feodo.out_s
curl https://iplists.firehol.org/files/firehol_level1.netset -o firehol_l1.out_s
curl https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt -o ipsum_l1.out_xl
curl https://raw.githubusercontent.com/stamparm/ipsum/master/levels/333xt -o ipsum_l3.out_s

# dshield entires are in /24 
curl https://feeds.dshield.org/block.txt -o dshield.in -s
grep '^[1-9]' dshield.in | awk '{print $1"/24"}' > dshield.out
```

Now, we merge all list entries, extraxt IP/CIDR information, and add missing /32 where needed (for aggregate-prefix to work).

Then we remove multicast 224.0.0.0/4 and RFC6890 not global IP/CIDRs since these should be handled in an independent firewall rule, e.g. see here https://help.mikrotik.com/docs/display/ROS/Building+Advanced+Firewall

Next, we aggregate (using https://github.com/tycho/aggregate-prefixes), strip /32 again (save some bits), and add RFC6890 reserved 240.0.0.0/4, which will give us the raw blocklist (which can be used e.g. as replacement for the "bad_ip4" address list in the mikrotik example above). Explicitly excluding 52.113.194.132 which is used for some Microsoft Teams sync services - that now has made in on firehol_l2.

```
cat *.out | grep -Eo '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?' | awk '!/\//{$0=$0"/32"}{print}' | sed -E '/^(22[4-9]|23[0-9]|192\.168|52\.113\.194\.132|0\.)/d' | aggregate-prefixes | sed 's/\/32$//' | sed '$a\240.0.0.0/4' > blocklist.txt
```

Finally, we generate mikrotik rsc versions of the raw blocklist for easy importing (note that we quoted the IP/CIDR, since on some mikrotiks the CIDR block will get lost otherwise). One for address-list based approach, and one for global array approach.

```
# address-list approach
cat blocklist.txt | awk '{print "add list=new_blocklist address=\""$0"\" comment=\"blocklist\""}' > blocklist.rsc
sed -i '1 i\\/ip firewall address-list' blocklist.rsc

# array approach
cat blocklist.txt | awk '{print ":set newips (newips,\""$0"\")"}' > blocklist_ga.rsc
sed -i '1 i\\:global newips \[\:toarray \"\"\]' blocklist_ga.rsc
```

### Downloading and updating on the mikrotik
You might want to consider using this blocklist in the ip firewall raw table. Also be aware that multicast (i.e. 224.0.0.0/4) should not be blocked to allow for IPTV to work.
For mikrotik starters, you can consult https://help.mikrotik.com/docs/display/ROS/Building+Advanced+Firewall to get going...and make sure you add the actual firewall rules to make use of the blocklist.

```
/tool fetch url="https://raw.githubusercontent.com/multiduplikator/mikrotik_blocklist/main/blocklist.rsc" mode=https
/ip firewall address-list remove [find where list="blocklist"]; /import file-name=blocklist.rsc
```

Clearly, the above mechanism leads to a short window of time, where blocking deteriorates, as the blocklist is emptied out and then reloaded.
However, its performance in terms of loading time is quite good.

A better approach would be to work with two lists (e.g. prod_blocklist and new_blocklist). With basic scripting we would do something like the following.

**THE FOLLOWING IS EXTREMELY SLOW! DON'T RUN THIS!**

```
# fetch the blocklist to file
/tool fetch url="https://raw.githubusercontent.com/multiduplikator/mikrotik_blocklist/main/blocklist.rsc" mode=https

# load blocklist
/import file-name=blocklist.rsc

# check if blocklist exists with entries
:if ([:len [/ip firewall address-list find list=new_blocklist]] > 0 ) do={
	# remove nonexisting in new_blocklist from prod_blocklist, and existing in both from new_blocklist
	:foreach i in=[/ip firewall address-list find list=prod_blocklist] do={
		:local oldaddress [/ip firewall address-list get $i address]
		:local existnew [/ip firewall address-list find where list=new_blocklist and address=$oldaddress]
		:if ([:len $existnew] > 0) do={
			/ip firewall address-list remove $existnew
		} else={
			/ip firewall address-list remove $i
		}
	}
	# add remaining new blocklist entries to prod_blocklist
	:foreach j in=[/ip firewall address-list find list=new_blocklist] do={
		:local newaddress [/ip firewall address-list get $j address]
		/ip firewall address-list add list=prod_blocklist address=$newaddress
		/ip firewall address-list remove $j
	}
} 
```

Well, then let us try this with arrays. Adding in a few more comments to make it easier to understand. Granted, there are some more corners that could be cut, but this way we have indication that it worked if new_blocklist has 0 (zero) entries on exit, and we try to be memory efficient by reducing list entries as early as possible. This takes about 140-180sec for two lists with some 26k entries each on a CCR-1036, for example. Since blocking does not deteriorate during this process, it is tolerable...

**THE FOLLOWING WORKS MUCH FASTER, ACTUALLY QUITE DECENT PERFORMANCE ALSO ON LARGER LISTS**

```
# fetch the blocklist to file
/tool fetch url="https://raw.githubusercontent.com/multiduplikator/mikrotik_blocklist/main/blocklist.rsc" mode=https

# load blocklist
/import file-name=blocklist.rsc

# enter the address-list section
/ip firewall address-list

# load blocklists into array
:local prdkeys [find list=prod_blocklist]
:local newkeys [find list=new_blocklist]

# check that we actually have new_blocklist entries
:if ([:len $newkeys] > 0 ) do={
	# translate newkeys to newips
	:local newips [:toarray ""]
	:foreach value in=$newkeys do={:set newips (newips,[get $value address])}
	# remove exisiting in both from new_blocklist, and nonexisting in new_blocklist from prod_blocklist
	:foreach value in=$prdkeys do={
		:local keyindex [:find $newips [get $value address]]
		:if ($keyindex > 0) do={
			# removal from new_blocklist
			remove ($newkeys->($keyindex))
			# erasing array entries to speedup next search and prepare for next stage
			:set ($newkeys->($keyindex)) ""
			:set ($newips->($keyindex)) ""
		} else={
			# removal from prod_blocklist
			remove $value
		}
	}
	# the newkeys and newips arrays now contain only the remaining entries
	# to be added to prod_blocklist and removed from new_blocklist
	:for i from=0 to=([:len $newkeys] - 1) do={
		:if ([:len ($newkeys->($i))] > 0) do={
			add list=prod_blocklist address=($newips->($i))
			remove ($newkeys->($i))
		}
	}
}
```
What if we did not import new_blocklist into an address-list but instead into a global array? We would not need two address-lists, and hence save a significant amount of operations, e.g. initial import into new_blocklist address-list, removal of entries therein, one array less to manipulate. Down to about 90-140sec for some 26k entries to process. Here we go, commenting only the key changes in mechanics ...

**THIS IS BY FAR THE FASTEST, YET**

```
/tool fetch url="https://raw.githubusercontent.com/multiduplikator/mikrotik_blocklist/main/blocklist_ga.rsc" mode=https

# load blocklist into global array newips
/import file-name=blocklist_ga.rsc

/ip firewall address-list

:local prdkeys [find list=prod_blocklist]

# load newips array (created with /import above)  
:global newips

:if ([:len $newips] > 0 ) do={
	:foreach value in=$prdkeys do={
		:local keyindex [:find $newips [get $value address]]
		:if ($keyindex > 0) do={
			:set ($newips->($keyindex)) ""
		} else={
			remove $value
		}
	}
	:foreach ip in=$newips do={
		:if ($ip != "") do={
			add list=prod_blocklist address="$ip"
		}
	}
}

# remove global newips array
:set newips
```

PS:
I have tried various approaches to **avoid the costly :find** and reduce the BigO. Most of which involve sorting the arrays and/or address lists.
Bubble sorting, merge sorting, quick sorting, etc. and using an associative array and exploit the automatic array sorting of mikrotik scripting.
Unfortunately, the sorting step is not trivial, since we have to deal with ip-prefixes as well and that does not lend itslef to easy comparison.
Long story short, they all work as expected, but the benefits seem to come only with much larger lists. **Ideas welcome!**


### SAMPLE SCRIPTS TO USE IN ROUTEROS

Thanks @njumaen for the ideas and code snippets! Added some exemplary bells and whistles...

**1 - Download (Policy: ftp, read, write, test Schedule: every 3h)**

```
:log info "blocklist-DL started"
/tool fetch url="https://raw.githubusercontent.com/multiduplikator/mikrotik_blocklist/main/blocklist_ga_l.rsc" mode=https
:log info "blocklist-DL finished"
```

**2 - Update - simplest form (Policy: read, write, test Schedule: every 3h, 5min after download above)**
```
:log info "blocklist-REP: started"
:log info "blocklist-REP: started - disabling info"
/system logging disable 0

:local duration [/system clock get time]

/import file-name=blocklist_ga_l.rsc

/ip firewall address-list

:local prdkeys [find list=prod_blocklist]
:global newips

:local countnew 0
:local countremoved 0
:local counttotal [:len $newips]

:if ($counttotal > 0 ) do={
	:foreach value in=$prdkeys do={
		:local keyindex [:find $newips [get $value address]]
		:if ($keyindex > 0) do={
			:set ($newips->($keyindex)) ""
		} else={
			remove $value
			:set countremoved ($countremoved+1)
		}
	}
	:foreach value in=$newips do={
		:if ($value != "") do={
			add list=prod_blocklist address="$value"
			:set countnew ($countnew+1)
		}
	}
}

:set newips
:set duration ([/system clock get time] - $duration)

/system logging enable 0
:log info "blocklist-REP: finished - enabled info"
:log info "blocklist-REP: finished - $countremoved removed, $countnew new, in $duration / $counttotal  total"
```

**2b - Update - with error detection, requires ROS >= 6.2 (Policy: read, write, test Schedule: every 3h, 5min after download above)**

This introduces about 2-3% performace hit.

```
:log info "blocklist-REP: started"
:log info "blocklist-REP: started - disabling info"
/system logging disable 0

:local duration [/system clock get time]

/import file-name=blocklist_ga_l.rsc

/ip firewall address-list

:local prdkeys [find list=prod_blocklist]
:global newips

:local countnew 0
:local countremoved 0
:local counttotal [:len $newips]
:local counterror 0

:if ($counttotal > 0 ) do={
	:foreach value in=$prdkeys do={
		:local keyindex [:find $newips [get $value address]]
		:if ($keyindex > 0) do={
			:set ($newips->($keyindex)) ""
		} else={
			remove $value
			:set countremoved ($countremoved+1)
		}
	}
	:foreach value in=$newips do={
		:if ($value != "") do={
			:do { add list=prod_blocklist address="$value" } on-error { :set counterror ($counterror+1) }
			:set countnew ($countnew+1)
		}
	}
}

:set newips
:set duration ([/system clock get time] - $duration)

/system logging enable 0
:log info "blocklist-REP: finished - enabled info"
:log info "blocklist-REP: finished - $countremoved removed, $countnew new, $counterror errors, in $duration / $counttotal  total"
```

**2c - Update - fancy with ROS version detection (Policy: read, write, test Schedule: every 3h, 5min after download above)**
```
:log info "blocklist-REP: started"

:local rbootver [/system routerboard get current-firmware]
:local version ([:tonum [:pick $rbootver 0 1]]*10 + [:tonum [:pick $rbootver 2 3]])
:local minversion 62

:log info "blocklist-REP: Detected ROS version $rbootver"
	
:if ($version >= $minversion ) do={
	:log info "blocklist-REP: Running with error handling"
} else={
	:log info "blocklist-REP: Running without error handling"
}

:log info "blocklist-REP: disabling info"
/system logging disable 0

:local duration [/system clock get time]

/import file-name=blocklist_ga_l.rsc

/ip firewall address-list

:local prdkeys [find list=prod_blocklist]
:global newips

:local countnew 0
:local countremoved 0
:local counttotal [:len $newips]
:local counterror 0

:if ($counttotal > 0 ) do={
	:foreach value in=$prdkeys do={
		:local keyindex [:find $newips [get $value address]]
		:if ($keyindex > 0) do={
			:set ($newips->($keyindex)) ""
		} else={
			remove $value
			:set countremoved ($countremoved+1)
		}
	}
	:if ($version >= $minversion ) do={
		:foreach value in=$newips do={
			:if ($value != "") do={
				:do { add list=prod_blocklist address="$value" } on-error { :set counterror ($counterror+1) }
				:set countnew ($countnew+1)
			}
		}
	} else={
		:foreach value in=$newips do={
			:if ($value != "") do={
				add list=prod_blocklist address="$value"
				:set countnew ($countnew+1)
			}
		}	
	}
}

:set newips
:set duration ([/system clock get time] - $duration)

/system logging enable 0
:log info "blocklist-REP: finished - enabled info"

:if ($version >= $minversion ) do={
	:log info "blocklist-REP: finished - $countremoved removed, $countnew new, $counterror errors, in $duration / $counttotal  total"
} else={
	:log info "blocklist-REP: finished - $countremoved removed, $countnew new, in $duration / $counttotal  total"
}
```
