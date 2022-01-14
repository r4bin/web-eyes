# WEB-EYES V1.0

<p align="center" width="100%">
    <img width="45%" src="https://github.com/r4bin/web-eyes/blob/master/assest/head.png">
</p>

<h1 align="center">web-eyes: OSINT tools for website research, 14 research methods are available:</h1>

<p align="center" width="100%">
    <img width="45%" src="https://github.com/r4bin/web-eyes/blob/master/assest/methods.png">
</p>

 1) HINFO: HTTP HEADERS SCANNER
 2) HSECURE: HTTP SECURITY HEADERS SCANNER
 3) WEBTECH: WEBSITE TECHNOLOGY LOOKUP
 4) WHOIS: WHOIS LOOKUP
 5) RWHOIS: REVERSE WHOIS LOOKUP
 6) IPHISTORY: IP HISTORY LOOKUP
 7) DNSLOOK: DNS RECORDS LOOKUP
 8) SUBDOMAINS: SUBDOMAINS SCANNER
 9) CERTFILE: CERTIFICATE LOOKUP
 10) IPLOOK: IP ADDRESS LOOKUP
 11) RIPLOOK: REVERSE IP ADDRESS LOOKUP
 12) RDNSLOOK: REVERSE DNS LOOKUP
 13) TCPSCAN: TCP PORTS SCANNER
 14) UDPSCAN: UDP PORTS SCANNER

<p align="center" width="100%">
    <img width="65%" src="https://github.com/r4bin/web-eyes/blob/master/assest/usage.png">
</p>

 1) HINFO: HINFO [URL] => HINFO [https://example.com]
 2) HSECURE: HSECURE [URL] => HSECURE [https://example.com]
 3) WEBTECH: WEBTECH [DOMAIN] => WEBTECH [example.com]
 4) WHOIS: WHOIS: WHOIS [DOMAIN] => WHOIS [example.com]
 5) RWHOIS: RWHOIS: RWHOIS [DOMAIN] => RWHOIS [example.com]
 6) IPHISTORY: IPHISTORY: IPHISTORY [DOMAIN] => IPHISTORY [example.com]
 7) DNSLOOK: DNSLOOK [DOMAIN] => DNSLOOK [example.com]
 8) SUBDOMAINS: SUBDOMAINS [DOMAIN] => SUBDOMAINS [example.com]
 9) CERTFILE: CERTFILE [DOMAIN] => CERTFILE [example.com]
 10) IPLOOK: IPLOOK [IP] => IPLOOK [1.1.1.1]
 11) RIPLOOK: RIPLOOK [DOMAIN, IP] => RIPLOOK [example.com, 1.1.1.1]
 12) RDNSLOOK: RDNSLOOK [IP] => RDNSLOOK [1.1.1.1]
 13) TCPSCAN: TCPSCAN [IP] [PORT => COMMON, OWN] => TCPSCAN [1.1.1.1] [COMMON, 80]
 14) UDPSCAN: UDPSCAN [IP] [PORT => COMMON, OWN] => UDPSCAN [1.1.1.1] [COMMON, 80]

## Prerequisites

```
apt-get install python3
```
```
pip3 install requests
```
```
pip3 install dnspython
```

## Install

``` bash
git clone https://github.com/r4bin/web-eyes.git
cd web-eyes
chmod +x web-eyes.py
./web-eyes.py
```
### or

``` bash
git clone https://github.com/r4bin/web-eyes.git
cd web-eyes
python3 web-eyes.py
```


