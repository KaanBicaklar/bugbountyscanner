#!/bin/bash
domain=$1
with_nessus=$2
username=$3
password=$4

mkdir $domain.monascanner

subfinder -d $domain -o $domain.monascanner/subdomains1
if [ $with_nesus="nessus" ]; then
echo "nesus working"
a=$(pwd)
python3 nessus4mona.py -u $username -p $password -sn $domain  -sf $a/$domain.monascanner/subdomains1

fi
echo "nesus finish"
cat $domain.monascanner/subdomains1 |waybackurls >$domain.monascanner/waybackdata1
echo "wayback finish"
cat $domain.monascanner/subdomains1| httpx >$domain.monascanner/httpx
echo "httpx finish"
katana -list $domain.monascanner/httpx -jc -d 7 -aff -p 10 -rl 50  -proxy "http://127.0.0.1:8080" -silent  >> waybackdata1
echo "katana finish"

cat $domain.monascanner/waybackdata1 | sort -u > $domain.monascanner/waybacksorted

echo "waybacksorted"
cat $domain.monascanner/waybacksorted|gf ssrf >$domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf rce >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf redirect >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf sqli >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf lfi >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf ssti >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf xss >> $domain.monascanner/gfcikti
echo "gf end "
cat $domain.monascanner/gfcikti|sort -u > $domain.monascanner/gfciktison
echo "burp suite integration "
cat $domain.monascanner/gfcikti | parallel -j 10 "curl --proxy http://127.0.0.1:8080 -sk > /dev/null"

nuclei -l $domain.monascanner/httpx.$domain -as -sa
