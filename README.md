# mikrotik blocklist (aka blacklist)
In an attempt to make the list as compact as possible, we are trying to to use prefix aggregation on a merged set of source lists.
This should increase the performance on the router while minimizing ressource usage at the same time.

Currently, this list updates every 6h - while working out what a good frequency would be.

The following is ment as a reference for the blocklist sources, regex and basic mechanics - by no means should you cut, paste and run this in a production environement ... unless you add some proper error handling amongst other bells and whistles. 

### Aggregated blocklist for mikrotik (and others)

First, we grab the lists and extract IP/CIDR information from them (adding /32 where missing for aggregation later)

```
wget -O spamhaus_drop.out https://www.spamhaus.org/drop/drop.txt
wget -O spamhaus_edrop.out https://www.spamhaus.org/drop/edrop.txt
wget -O sslbl.out https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
wget -O malc0de.out https://malc0de.com/bl/IP_Blacklist.txt
wget -O blocklist_de.out https://lists.blocklist.de/lists/all.txt
wget -O feodo.out https://feodotracker.abuse.ch/downloads/ipblocklist.txt
wget -O firehol_l1.out https://iplists.firehol.org/files/firehol_level1.netset
wget -O firehol_l2.out https://iplists.firehol.org/files/firehol_level2.netset

# dshield entires are in /24 
wget -O dshield.in https://feeds.dshield.org/block.txt
grep '^[1-9]' dshield.in | awk '{print $1"/24"}' |  > dshield.out
```

Now, we merge all list entries, extraxt IP/CIDR information, and add missing /32 where needed (for aggregate-prefix to work).

Then we remove 0.0.0.0/8, 192.168.0.0/16 and 224.0.0.0/4 since these should be handled in an independent firewall rule, e.g. see here https://help.mikrotik.com/docs/display/ROS/Building+Advanced+Firewall

Next, we aggregate (using https://github.com/tycho/aggregate-prefixes) and strip /32 again (save some bits), which will give us the raw blocklist.

```
cat *.out | grep -Eo '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?' | awk '!/\//{$0=$0"/32"}{print}' | sed -E '/^(22[4-9]|23[0-9]|192\.168|0)/d' | aggregate-prefixes | sed 's/\/32$//' > blocklist.txt
```

Finally, we generate mikrotik rsc version of the raw blocklist for easy importing (note that we quoted the IP/CIDR, since on some mikrotiks the CIDR block will get lost otherwise)

```
cat blocklist.txt | awk '{print "add list=new_blocklist address=\""$0"\" comment=\"blocklist\""}' > blocklist.rsc
sed -i '1 i\\/ip firewall address-list' blocklist.rsc
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

Well, then let us try this with arrays. Adding in a few more comments to make it easier to understand. Granted, there are some more corners that could be cut, but this way we have indication that it worked if new_blocklist has 0 (zero) entries on exit, and we try to be memory efficient by reducing list entries as early as possible. This takes about 2min for two lists with some 26k entries each on a CCR-1036, for example. Since blocking does not deteriorate during this process, it is tolerable...

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
	:for i from=0 to=[:len $newkeys] do={
		:if ([:len ($newkeys->($i))] > 0) do={
			add list=prod_blocklist address=($newips->($i))
			remove ($newkeys->($i))
		}
	}
}
```
What if we did not import new_blocklist into an address-list but instead into a global array? We would not need two address-lists, and hence save a significant amount of operations, e.g. initial import into new_blocklist address-list, removal of entries therein, one array less to manipulate. Down to about 1min for some 26k entries to process. Here we go ...

**THIS IS BY FAR THE FASTEST, YET**

```
# fetch the blocklist to file
/tool fetch url="https://raw.githubusercontent.com/multiduplikator/mikrotik_blocklist/main/blocklist_ga.rsc" mode=https

# load blocklist into global array newips
/import file-name=blocklist_ga.rsc

# enter the address-list section
/ip firewall address-list

# load production blocklist into array
:local prdkeys [find list=prod_blocklist]

# load new blocklist (via global from import above)  
:global newips

# check that we actually have entries in newips
:if ([:len $newips] > 0 ) do={
	# remove exisiting in both from newips, and nonexisting in newips from prod_blocklist
	:foreach value in=$prdkeys do={
		:local keyindex [:find $newips [get $value address]]
		:if ($keyindex > 0) do={
			# erasing array entries to speedup next search and prepare follwing stage
			:set ($newips->($keyindex)) ""
		} else={
			# removal from prod_blocklist
			remove $value
		}
	}
	# the newips arrays now contain only the remaining entries to be added to prod_blocklist
	:for i from=0 to=[:len $newips] do={
		:if ([:len ($newips->($i))] > 0) do={
			add list=prod_blocklist address=($newips->($i))
		}
	}
}

# unset global newips array
:global newips [:toarray ""]
```
