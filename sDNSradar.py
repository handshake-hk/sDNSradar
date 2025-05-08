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

import json
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

    response = requests.post(url, headers=headers,
                             data=dns_query, timeout=5)
    return response.status_code == 200 and response.headers.get('Content-Type') == 'application/dns-message'


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


def check_doh_multiple_ips(endpoints, domain, results):
    for host, port in endpoints:
        print(f"{CYAN}Checking {host} on port {port} for DoH service...{RESET}")
        try:
            valid_doh = send_doh_request(host, domain, port)
        except requests.exceptions.RequestException as e:
            print(f"{YELLOW}[*] Error contacting {host}:{port}: {e}{RESET}")
            results["error"].append(f"{host}:{port}")
        except Exception as e:
            print(
                f"{RED}[-] An unexpected error occurred while checking {host}:{port}: {e}{RESET}")
            results["error"].append(f"{host}:{port}")
        else:
            if valid_doh:
                print(
                    f"{GREEN}[+] DoH service detected at {host}:{port}{RESET}")
                results["doh"].append(f"{host}:{port}")
            else:
                print(
                    f"{RED}[-] No valid DoH service detected at {host}:{port}{RESET}")
                results["unsupported"].append(f"{host}:{port}")


def process_endpoints(endpoints):
    processed_endpoints = []
    for endpoint in endpoints:
        parts = endpoint.split(":")
        if len(parts) == 2 and parts[0].strip() and parts[1].isnumeric():
            processed_endpoints.append(parts)
        else:
            raise ValueError("Invalid endpoints")
    return processed_endpoints


def main():
    parser = argparse.ArgumentParser(
        description="Check for DNS over HTTPS (DoH) services on multiple servers.",
        epilog="Brought to you by Handshake\nVersion: 0.0.1\nMIT License",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "servers",
        metavar="SERVERS",
        type=str,
        nargs="*",
        help="List of DoH endpoint addresses in the format 'host:port' (e.g., 1.1.1.1:443, cloudflare-dns.com:443).",
    )
    parser.add_argument(
        "-d",
        "--domain",
        default="example.com",
        help="Domain name to query for testing the DoH service (default: example.com).",
    )
    parser.add_argument(
        "-iL",
        "--input",
        default=None,
        help=(
            "Path to a file containing a list of DoH endpoints (one per line). "
            "If provided, the 'servers' argument will be ignored."
        ),
    )
    parser.add_argument(
        "-j",
        "--json",
        default=None,
        help="Save the results to a JSON file"
    )

    args = parser.parse_args()

    if not args.servers and args.input is None:
        parser.error("You must specify at least one endpoint to be checked.")

    if args.input:
        try:
            with open(args.input, 'r') as f:
                endpoints = [line.strip() for line in f if line.strip()]
            print(f"Checking servers from file: {args.input}")
        except FileNotFoundError:
            parser.error(f"Input file '{args.input}' not found.")
    elif args.servers:
        endpoints = args.servers

    try:
        processed_endpoints = process_endpoints(endpoints)
    except ValueError:
        parser.error("Invalid endpoints.")

    results = {"doh": [], "unsupported": [], "error": []}
    check_doh_multiple_ips(processed_endpoints, args.domain, results)

    if args.json is not None:
        if not args.json.endswith(".json"):
            args.json += ".json"
        with open(args.json, "w") as f:
            json.dump(results, f, indent=4)


if __name__ == "__main__":
    main()
