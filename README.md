# sDNSradar
A penetration testing tool to identify secure DNS (DoH & DoT) services on multiple servers. 

## Usage

```bash 
$ ./sDNSradar.py cloudflare-dns.com:443 dns.google:853
Checking cloudflare-dns.com on port 443 for DoH service...
[+] DoH service detected at cloudflare-dns.com:443
Checking dns.google on port 853 for DoH service...
[*] Error contacting dns.google:853: ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))
Checking cloudflare-dns.com on port 443 for DoT service...
Checking dns.google on port 853 for DoT service...
[+] DoT service detected at dns.google:853
```

### More
```bash
$ ./sDNSradar.py --help                                                                   
usage: sDNSradar.py [-h] [-d DOMAIN] [-iL INPUT] [-j JSON] [SERVERS ...]

Check for DNS over HTTPS (DoH) services on multiple servers.

positional arguments:
  SERVERS              List of endpoints to be checked in the format 'host:port' (e.g., 1.1.1.1:443, cloudflare-dns.com:443).

options:
  -h, --help           show this help message and exit
  -d, --domain DOMAIN  Domain name to query for testing the DoH service (default: example.com).
  -iL, --input INPUT   Path to a file containing a list of DoH endpoints (one per line). If provided, the 'servers' argument will be ignored.
  -j, --json JSON      Save the results to a JSON file

Brought to you by Handshake
Version: 0.0.1
MIT License
```
