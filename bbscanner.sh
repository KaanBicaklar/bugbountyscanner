#!/bin/bash
domain=$1
with_nessus=$3
username=$4
password=$5
proxy=$2
echo "usage: ./bbscanner.sh 'domain.com' nessus username  password  'http://127.0.0.1:8080' "
mkdir $domain.monascanner
subfinder -d $domain -o $domain.monascanner/subdomains1
#assetfinder -subs-only $domain  >> $domain.monascanner/subdomains1 
#amass enum  -d $domain  >> $domain.monascanner/subdomains1 
echo "subdomains sort"
cat $domain.monascanner/subdomains1|sort -u >$domain.monascanner/subdomains
if [ $with_nesus="nessus" ]; then
echo "nesus working"
a=$(pwd)
python3 nessus4mona.py -u $username -p $password -sn $domain  -sf $a/$domain.monascanner/subdomains

fi
echo "nesus finish"

echo "subdomains httpx begin"
cat $domain.monascanner/subdomains| httpx >$domain.monascanner/httpx
echo "subdomains httpx end"
echo "nuclei begin"
nuclei -l $domain.monascanner/httpx -as  -p $proxy -o $domain.monascanner/nucleihttpxas
nuclei -l $domain.monascanner/httpx   -p $proxy -o $domain.monascanner/nucleihttpx
nuclei -l $domain.monascanner/subdomains -sa -p $proxy -o $domain.monascanner/nucleisubs
echo "nuclei end"
echo "wayback end"
cat $domain.monascanner/subdomains |waybackurls >$domain.monascanner/waybackdata1

echo "httpx finish"

echo "katana begin"
katana -list $domain.monascanner/httpx -jc -d 3 -aff -p 10 -rl 10  -proxy $proxy -silent  >> $domain.monascanner/waybackdata1
echo "katana end"

echo "waybacksorted"
cat $domain.monascanner/waybackdata1 | sort -u > $domain.monascanner/waybacksorted

echo "gf begin"
cat $domain.monascanner/waybacksorted|gf ssrf >$domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf rce >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf redirect >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf sqli >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf lfi >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf ssti >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf xss >> $domain.monascanner/gfcikti
echo "gf end "

cat $domain.monascanner/gfcikti|sort -u > $domain.monascanner/gfciktison

cat $domain.monascanner/gfciktison | qsreplace  infi -a > $domain.monascanner/replacedgf
sort -u $domain.monascanner/replacedgf > $domain.monascanner/realfinalgf


echo "burp suite integration "
cat $domain.monascanner/realfinalgf | parallel -j 5 "curl --proxy $proxy -sk > /dev/null"
