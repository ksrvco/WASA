#!/bin/bash
# Project name: WASA - Web App Security Analyzer
# Version: 1.0
# Written by: KsrvcO
# Tested on: Linux operation systems
# Video demo: 
# Requirements: curl , httpx
# Contact me: flower.k2000[at]gmail.com
reset
httpxbinary=$(whereis httpx | grep "/usr/bin/httpx")
curlbinary=$(whereis curl | grep "/usr/bin/curl")
if [ -z "$httpxbinary" ]
    then
        echo "[-] httpx NOT found. Without this package this tool dont work correctly."
    else
        echo "[+] httpx found.OK!"
fi
if [ -z "$curlbinary" ]
    then
        echo "[-] curl NOT found. Without this package this tool dont work correctly."
    else
        echo "[+] curl found.OK!"
fi 
sleep 5
reset
echo -e "

██╗    ██╗ █████╗ ███████╗ █████╗ 
██║    ██║██╔══██╗██╔════╝██╔══██╗
██║ █╗ ██║███████║███████╗███████║
██║███╗██║██╔══██║╚════██║██╔══██║
╚███╔███╔╝██║  ██║███████║██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                         by KsrvcO

Project name: WASA - Web App Security Analyzer
Version: 1.0
Written by: KsrvcO
Tested on: Linux operation systems
Contact me: flower.k2000[at]gmail.com


1. Information Gathering
2. Directory Crawling
3. Subdomain Finding
4. CORS Misconfiguration Vulnerability Check
5. Host Header Injection Vulnerability Check
6. ClickJacking Vulnerability Check

"
read -p "[+] Enter your selection: " option
if [ $option == 1 ]
    then
        read -p "[+] Enter your target (ex: https://target.com): " target
        echo ""
        echo ""
        domain=$(echo $target | awk -F '//' '{print $2}')
        ip_domain=$(ping $domain -c 1 | grep "PING" | cut -d " " -f3 | cut -d "(" -f2 | cut -d ")" -f1)
        echo "[-] IP: $ip_domain"
        wserver=$(curl --silent -I $target | grep -e "server" -e "Server" | awk -F ':' '{print $2}' | awk -F ' ' '{print $1}')
        echo "[-] WebServer: $wserver"
        res_code=$(curl --silent -I "$target/<script>alert(2)</script>" | grep "HTTP" | cut -d " " -f2)
        if [ "$res_code" == 500 ]
            then
                echo "[-] Target is behind WAF."
            elif [ "$res_code" == 403 ]
            then
                echo "[-] Target is behind WAF."
            else
                echo "[+] Target have not any WAF. But it may be behind CDN WAF."
        fi
        cdomain=$(curl --silent $target/crossdomain.xml | grep 'allow-access-from domain="*"')
        if [ -z "$cdomain" ]
            then
                echo "[-] Target is not vulnerable to CrossDomain.xml attack."
        else
                echo "[+] Target is vulnerable to CrossDomain.xml attack."
        fi
        xmfile=$(curl --silent  -I $target/xmlrpc.php | grep "HTTP" | cut -d " " -f2)
        if [ "$xmfile" == 405 ] 
            then
                echo "[+] Target have file xmlrpc.php for attack." 
            elif [ "$xmfile" == 403 ]
            then
                echo "[+] File xmlrpc.php found but you dont have permission for attack it."
            else
            echo "[-] Target not vulnerable to file xmlrpc.php attack."
        fi 
        htmethods=$(curl --silent -I -X OPTIONS $target | grep -e "allow" -e "Allow" | awk -F ':' '{print $2}')
        if [ -z "$htmethods" ]
            then
                echo "[-] HTTP Methods don't detected."
        else
                echo "[+] Detected HTTP Methods: $htmethods"
        fi
elif [ $option == 2 ]
    then
        read -p "[+] Enter your target (ex: https://target.com): " tget
        read -p "[+] Enter your dictionary address (ex: /home/user/dic.lst): " dictionary
        for i in $(cat $dictionary)
        do
        fol=$(curl --silent -I $tget/$i | head -n 1 | cut -d " " -f2)
        if [ "$fol" == 200 ]
            then
                echo $tget$i
        fi
        done
elif [ $option == 3 ]
    then
        read -p "[+] Enter your target (ex: target.com): " website
        echo -e "\n[+] Active Subdomains List: "
        curl -s https://dns.bufferover.run/dns?q=.$website | jq -r .FDNS_A[] |cut -d',' -f2 | sort -u | httpx -status-code -silent | grep "200" | cut -d " " -f1

elif [ $option == 4 ]
    then
        read -p "[+] Enter an important file url (ex: https://target.com/file/admin.js): " impurl
        rescors=$(curl --silent -I -H "Origin: https://github.com" $impurl | grep -e "Access-Control-Allow-Origin: github.com" -e "Access-Control-Allow-Credentials: True")
        if [ -z "$rescors" ]
            then
                echo "[-] Target is not vulnerable to CORS Misconfiguration."
        else
                echo "[+] Target is vulnerable to CORS Misconfiguration."
        fi
elif [ $option == 5 ]
    then
        read -p "[+] Enter your target (ex: https://target.com): " hhiurl
        hhires=$(curl --silent -I -H "Host: github.com" $hhiurl | head -n 1 | awk -F ' ' '{print $2}')
        if [ "$hhires" == 200 ]
            then
                echo "[+] Target is Vulnerable to Host Header Injection Attack."
            else
                echo "[-] Target is NOT Vulnerable to Host Header Injection Attack."
        fi  
elif [ $option == 6 ]
    then
        read -p "[+] Enter your target (ex: target.com): " cliurl
        clires=$(curl --silent -I $cliurl | grep "X-Frame-Options:")
        if [ -z "$clires" ]
            then
                echo "[+] Target is Vulnerable to ClickJacking attack."
        else
                echo "[-] Target is NOT Vulnerable to ClickJacking attack."
        fi         

fi