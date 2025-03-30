#!/bin/bash
domain=$1
with_nessus=$3
username=$4
password=$5
proxy=$2
echo 'usage: ./bbscanner.sh "domain.com" "http://burpadres:8080" nessus username password'
mkdir $domain.monascanner
subfinder -d $domain -rL dns-resolvers.txt -recursive  -o $domain.monascanner/subdomains1
assetfinder -subs-only $domain  >> $domain.monascanner/subdomains1 
#amass enum  -d $domain  -active -passive >> $domain.monascanner/subdomains1 
shuffledns -d $domain  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r dns-resolvers.txt -mode bruteforce >> $domain.monascanner/subdomains1 

echo "subdomains sort"
cat $domain.monascanner/subdomains1|sort -u >$domain.monascanner/subdomains
if [ $with_nesus="nessus" ]; then
echo "nesus working"
a=$(pwd)
python3 nessus4mona.py -u $username -p $password -sn $domain  -sf $a/$domain.monascanner/subdomains

fi
echo "nesus finish"

echo "subdomains httpx begin"
cat $domain.monascanner/subdomains|httpx -silent -no-color -random-agent -ports 80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4443,4444,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8444,8500,8800,8834,8880,8881,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,27201,32000,55440,55672 >$domain.monascanner/httpx
echo "subdomains httpx end"

echo "nuclei end"
echo "wayback end"
cat $domain.monascanner/subdomains |waybackurls >$domain.monascanner/waybackdata1

echo "httpx finish"

echo "katana begin"
katana -list $domain.monascanner/httpx -jc -d 2 -aff -p 10 -rl 10   -silent  >> $domain.monascanner/waybackdata1
echo "katana end"

echo "directory scan"
 for sub in $(cat $domain.monascanner/httpx);
 do
echo "dirb scan for $sub"
dirb  $sub -w /usr/share/seclists/Discovery/Web-Content/common.txt >> $domain.monascanner/waybackdata1
done;

echo "waybacksorted"
cat $domain.monascanner/waybackdata1 | sort -u >> $domain.monascanner/waybacksorted






echo "gf begin"
cat $domain.monascanner/waybacksorted|gf ssrf | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200,202,201,429 -silent | awk '{ print $1}' > $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf rce | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200,202,201,429 -silent | awk '{ print $1}' >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf redirect | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200,202,201,429 -silent | awk '{ print $1}' >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf sqli | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200,202,201,429 -silent | awk '{ print $1}' >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf lfi | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200,202,201,429 -silent | awk '{ print $1}' >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf ssti | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200,202,201,429 -silent | awk '{ print $1}' >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted|gf xss | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200,202,201,429 -silent | awk '{ print $1}' >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted| gf interestingEXT | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200,202,201,429 -silent | awk '{ print $1}' >> $domain.monascanner/gfcikti
cat $domain.monascanner/waybacksorted| gf debug_logic.json | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200,202,201,429 -silent | awk '{ print $1}' >> $domain.monascanner/gfcikti

echo "gf end "




cat $domain.monascanner/gfcikti|sort -u > $domain.monascanner/gfciktison

cat $domain.monascanner/gfciktison | qsreplace  m0n4 -a > $domain.monascanner/replacedgf
sort -u $domain.monascanner/replacedgf  >> $domain.monascanner/realfinalgf

echo "nuclei with gf"

nuclei -list $domain.monascanner/realfinalgf -dast   -rl 3 -o $domain.monascanner/fuzzing_dast 


echo "burp suite integration "
#cat $domain.monascanner/realfinalgf | parallel -j 5 "curl --proxy $proxy -sk > /dev/null"


echo "nuclei begin"
nuclei -l $domain.monascanner/httpx -as   -rl 3 -o $domain.monascanner/nucleihttpxas
echo "first end"

nuclei -l $domain.monascanner/httpx   -rl 3   -o $domain.monascanner/nucleihttpx
echo "second end"
nuclei -l $domain.monascanner/subdomains -sa  -rl 3 -o $domain.monascanner/nucleisubs

echo "nuclei end"



