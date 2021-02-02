# mikrotik_blocklist
In an attempt to make the list as compact as possible, we are trying to to use prefix aggregation on a merged set of source lists.
This should increase the performance on the router while minimizing ressource usage at the same time.

Currently, this list updates every 3h - while working out what a good frequency would be.

The following is ment as a reference for the blocklist sources, regex and basic mechanics - by no means should you cut, paste and run this in a production environement ... unless you add some proper error handling amongst other bells and whistles. 

### Aggregated blocklist for mikrotik (and others)

First, we grab the lists and extract IP/CIDR information from them (adding /32 where missing for aggregation later)

```
wget -O dshield.in https://feeds.dshield.org/block.txt
grep '^[1-9]' dshield.in | awk '{print $1"/24"}' > dshield.out

wget -O spamhaus_drop.in https://www.spamhaus.org/drop/drop.txt
grep -Eo '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?' spamhaus_drop.in | awk '!/\//{$0=$0"/32"}{print}' > spamhaus_drop.out

wget -O spamhaus_edrop.in https://www.spamhaus.org/drop/edrop.txt
grep -Eo '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?' spamhaus_edrop.in | awk '!/\//{$0=$0"/32"}{print}' > spamhaus_edrop.out

wget -O abuse.in https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
grep -Eo '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?' abuse.in | awk '!/\//{$0=$0"/32"}{print}' > abuse.out

wget -O malc0de.in https://malc0de.com/bl/IP_Blacklist.txt
grep -Eo '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?' malc0de.in | awk '!/\//{$0=$0"/32"}{print}' > malc0de.out

wget -O blocklist_de.in https://lists.blocklist.de/lists/all.txt
grep -Eo '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?' blocklist_de.in | awk '!/\//{$0=$0"/32"}{print}' > blocklist_de.out

wget -O feodo.in https://feodotracker.abuse.ch/downloads/ipblocklist.txt
grep -Eo '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?' feodo.in | awk '!/\//{$0=$0"/32"}{print}' > feodo.out

wget -O firehol_l1.in https://iplists.firehol.org/files/firehol_level1.netset
grep -Eo '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?' firehol_l1.in | awk '!/\//{$0=$0"/32"}{print}' > firehol_l1.out

wget -O firehol_l2.in https://iplists.firehol.org/files/firehol_level2.netset
grep -Eo '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?' firehol_l2.in | awk '!/\//{$0=$0"/32"}{print}' > firehol_l2.out
```

Now, we merge all list entries, aggregate (using https://github.com/tycho/aggregate-prefixes) and strip /32 CIDR, which will give us the raw blocklist .
Before aggregation, we remove 0.0.0.0*, 192.168.0.0* and 224.0.0.0* (i.e. all your local networks!) from the lists to make sure we don't lock ourselves out accidentally on update.
These three IP sets should be handled in an independent firewall rule, e.g. see here https://help.mikrotik.com/docs/display/ROS/Building+Advanced+Firewall 

```
cat *.out | sed '/^0\.0\.0\.0\|^192\.168\.0\.0\|^224\.0\.0\.0/d' | aggregate-prefixes | sed 's/\/32$//' > blocklist.txt
```

Finally, we generate mikrotik rsc version of the raw blocklist for easy importing (note that we quoted the IP/CIDR, since on some mikrotiks the CIDR block will get lost otherwise)

```
cat blocklist.txt | awk '{print "add list=new_blocklist address=\""$0"\" comment=\"blocklist\""}' > blocklist.rsc
sed -i '1 i\\/ip firewall address-list' blocklist.rsc
```

### Strawman for downloading and updating on the mikrotik (firewall rule not included!)
You might want to consider using this in the raw table. Also be aware that multicast (i.e. 224.0.0.0/4) should not be blocked to allow for IPTV to work.
For mikrotik starters, you can consult https://help.mikrotik.com/docs/display/ROS/Building+Advanced+Firewall to get going...

```
/tool fetch url="https://raw.githubusercontent.com/multiduplikator/mikrotik_blocklist/main/blocklist.rsc" mode=https
/ip firewall address-list remove [find where list="blocklist"]; /import file-name=blocklist.rsc
```

Clearly, this mechanism leads to a short window of time, where blocking deteriorates, as the blocklist is emptied out and then reloaded.
However, its performance in terms of loading time is acceptable.

A better approach would be to work with two lists (e.g. prod_blocklist and new_blocklist). So after the fetching part, we would do something like the following.
**THE FOLLOWING IS EXTREMELY SLOW! DON'T RUN THIS!**

```
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

Well, the let us try this with arrays - again taking it away from right after the fetching part. Adding in a few more comments to make it easier to understand. Granted, there are some more corners that could be cut, but this way we know it worked if new_blocklist has 0 (zero) entries on exit, and we try to be memory efficient by reducing list entries as early as possible. **THE FOLLOWING WORKS MUCH(!!!) FASTER, ACTUALLY QUITE DECENT PERFORMANCE ALSO ON LARGER LISTS**. About 2min for two lists with some 26k entries each on a CCR-1036, for example. Since blocking does not deteriorete during this process, works for me...

```
# load blocklist
/import file-name=blocklist.rsc

# enter the address-list section
/ip firewall address-list

# load blocklists into array
:local prdkeys [find list=prod_blocklist]
:local newkeys [find list=new_blocklist]

# translate newkeys to newips
:local newips [:toarray ""]
:foreach value in=$newkeys do={:set newips (newips,[get $value address])}

# check that we actually have new_blocklist entries
:if ([:len $newkeys] > 0 ) do={
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
