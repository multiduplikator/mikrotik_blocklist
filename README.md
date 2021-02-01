# mikrotik_blocklist
### Aggregated blocklist for mikrotik (and others)

First, we grab the lists and extract IP/CIDR information from them

```
wget -O dshield.in https://www.dshield.org/block.txt
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
```

Now, we merge all (prefixed) list entries, aggregate (using https://github.com/tycho/aggregate-prefixes) and strip /32 CIDR, which will give use the raw blocklist 

```
cat *.out | aggregate-prefixes | sed 's/\/32$//' > blocklist.txt
```

Finally, we generate mikrotik rsc version of the raw blocklist for easy importing

```
cat blocklist.txt | awk '{print "add list=blocklist address=\""$0"\" comment=\"blocklist\""}' > blocklist.rsc
sed -i '1 i\\/ip firewall address-list' blocklist.rsc
```
