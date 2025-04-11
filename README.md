# sDNSradar
A penetration testing tool to identify secure DNS (DoH) services on multiple servers. 

## Usage

```bash 
$ ./sDNSradar.py cloudflare-dns.com example.com
Checking cloudflare-dns.com on port 443 for DoH service...
[+] DoH service detected at cloudflare-dns.com:443
Checking example.com on port 443 for DoH service...
[-] No valid DoH service detected at example.com:443
```
### More
```bash
$ ./sDNSradar.py --help                                                                   
usage: sDNSradar.py [-h] [-d DOMAIN] [--port PORT] SERVERS [SERVERS ...]

Check for DNS over HTTPS (DoH) services on multiple servers.

positional arguments:
  SERVERS              List of IP addresses to check for DoH services.

options:
  -h, --help           show this help message and exit
  -d, --domain DOMAIN  Domain to query to test DoH service (default is example.com).
  --port PORT          Port to query for DoH service (default is 443).

Brought to you by Handshake
Version: 0.0.1
MIT License
```
