#!/usr/bin/python3
#
# MIT License
#
# Copyright (c) 2025 Handshake Networking Limited.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# provided to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import requests
import argparse

GREEN = '\033[32m'
RED = '\033[31m'
YELLOW = '\033[33m'
CYAN = '\033[36m'
RESET = '\033[0m'


def send_doh_request(doh_server, domain, port):
    url = f"https://{doh_server}:{port}/dns-query"
    headers = {
        "Accept": "application/dns-message",
        "Content-Type": "application/dns-message"
    }

    # Create a sample DNS query for the domain
    dns_query = create_dns_query(domain)

    try:
        response = requests.post(url, headers=headers,
                                 data=dns_query, timeout=5)
        if response.status_code == 200 and response.headers.get('Content-Type') == 'application/dns-message':
            print(
                f"{GREEN}[+] DoH service detected at {doh_server}:{port}{RESET}")
            return True
        else:
            print(
                f"{RED}[-] No valid DoH service detected at {doh_server}:{port}{RESET}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"{YELLOW}[*] Error contacting {doh_server}:{port}: {e}{RESET}")
        return False


def create_dns_query(domain):
    # Create a basic DNS query packet for the domain
    query = b'\x00\x00'  # ID (transaction ID)
    query += b'\x01\x00'  # Flags (standard query)
    query += b'\x00\x01'  # Questions (1)
    query += b'\x00\x00'  # Answer RRs (0)
    query += b'\x00\x00'  # Authority RRs (0)
    query += b'\x00\x00'  # Additional RRs (0)

    # Add the domain name (e.g., example.com)
    for part in domain.split('.'):
        query += bytes([len(part)]) + part.encode()

    query += b'\x00'  # End of domain name
    query += b'\x00\x01'  # Type A (IPv4 address)
    query += b'\x00\x01'  # Class IN (Internet)

    return query


def check_doh_multiple_ips(ip_list, domain, port):
    for ip in ip_list:
        print(f"{CYAN}Checking {ip} on port {port} for DoH service...{RESET}")
        send_doh_request(ip, domain, port)


def main():
    parser = argparse.ArgumentParser(
        description="Check for DNS over HTTPS (DoH) services on multiple servers.",
        epilog="Brought to you by Handshake\nVersion: 0.0.1\nMIT License",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("servers", metavar="SERVERS", type=str, nargs="+",
                        help="List of IP addresses to check for DoH services.")
    parser.add_argument("-d", "--domain", default="example.com",
                        help="Domain to query to test DoH service (default is example.com).")
    parser.add_argument("--port", type=int, default=443,
                        help="Port to query for DoH service (default is 443).")

    args = parser.parse_args()

    check_doh_multiple_ips(args.servers, args.domain, args.port)


if __name__ == "__main__":
    main()
