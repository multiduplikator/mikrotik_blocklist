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
Before aggregation, we remove 0.0.0.0*, 192.168.0.0* and 224.0.0.0* from the lists to make sure we don't lock ourselves out accidentally on update.
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

A better approach would be to work with two lists (e.g. prod_blocklist and blocklist). So after the fetching part, we would do something like the following.
THIS IS EXTREMELY SLOW! DON'T RUN THIS!

```
# load blocklist
/import file-name=blocklist.rsc

# check if blocklist exists with entries
:if ([:len [/ip firewall address-list find list=new_blocklist]] > 0 ) do={
	# remove nonexisting in blocklist from prod_blocklist, and existing in both from blocklist
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
