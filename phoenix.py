import dns.resolver
import argparse
import concurrent.futures
from collections import defaultdict
import requests
import socket
import ssl
import urllib3
import re
import json
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def resolve_subdomain(subdomain):
    """Resolves a subdomain to its IP address. Returns None if resolution fails."""
    try:
        result = dns.resolver.resolve(subdomain, 'A')
        return subdomain, result[0].to_text()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except Exception as e:
        print(f"Error resolving {subdomain}: {e}")
        return None

def get_server_type(subdomain, ip, check_ports=None, header_keyword=None):
    """Attempts to determine the server type and other headers, optionally checks ports and filters by header keyword."""
    try:
        url = f"http://{subdomain}"
        response = requests.head(url, timeout=5, allow_redirects=True, verify=False)
        headers = dict(response.headers)
        server_header = headers.get('Server', "Unknown")
        server_type = clean_server_header(server_header)

        if check_ports:
            open_ports = check_open_ports(ip, check_ports)
            if not open_ports:
                return None, None, None  # Skip if no specified ports are open

        if header_keyword:
            if not any(header_keyword.lower() in str(value).lower() for value in headers.values()):
                return None, None, None  # Skip if keyword not found in headers

        return server_type, headers, check_ports
    except (requests.exceptions.RequestException, socket.gaierror):
        try:
            url_https = f"https://{subdomain}"
            response_https = requests.head(url_https, timeout=5, allow_redirects=True, verify=False)
            headers = dict(response_https.headers)
            server_header = headers.get('Server', "Unknown")
            server_type = clean_server_header(server_header)

            if check_ports:
                open_ports = check_open_ports(ip, check_ports)
                if not open_ports:
                    return None, None, None  # Skip if no specified ports are open

            if header_keyword:
                if not any(header_keyword.lower() in str(value).lower() for value in headers.values()):
                    return None, None, None  # Skip if keyword not found in headers

            return server_type, headers, check_ports
        except:
            return "Unknown", {}, None

def check_open_ports(ip, ports):
    """Checks if specified ports are open on a given IP address."""
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except:
            pass
        finally:
            sock.close()
    return open_ports

def clean_server_header(server_header):
    """Cleans and standardizes server header output."""
    server_header = server_header.strip()
    server_header = re.sub(r'[\d./]+', '', server_header)
    if "IIS" in server_header:
        return "Microsoft IIS"
    if "Apache" in server_header:
        return "Apache"
    if "nginx" in server_header:
        return "nginx"
    return server_header

def format_headers(headers):
    """Formats HTTP headers for improved readability."""
    if not headers:
        return "    No headers retrieved."
    formatted_headers = "\n".join(f"      {key}: {value}" for key, value in headers.items())
    return formatted_headers

def enumerate_subdomains(domain, wordlist_path, output_file, json_output=False, verbose=False, check_ports=None, header_keyword=None):
    """Enumerates subdomains using a wordlist and concurrent threads."""
    start_time = time.time()
    found_subdomains_count = 0
    try:
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() + '.' + domain for line in f]

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_subdomain = {executor.submit(resolve_subdomain, subdomain): subdomain for subdomain in subdomains}
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    results.append(result)

        ip_to_subdomains = defaultdict(list)
        for subdomain, ip in results:
            ip_to_subdomains[ip].append(subdomain)

        output_data = {}

        print("\n[+] Subdomain Enumeration Results:\n")
        for ip, subdomains in sorted(ip_to_subdomains.items()):
            print(f"IP: {ip}")
            output_data[ip] = {}
            for subdomain in sorted(subdomains):
                server_type, headers, open_ports = get_server_type(subdomain, ip, check_ports, header_keyword)
                if server_type is None:
                    continue  # Skip if filtered out
                found_subdomains_count += 1
                print(f"  - {subdomain} (Server: {server_type})")
                print(format_headers(headers))
                if open_ports:
                    print(f"    Open Ports: {open_ports}")
                output_data[ip][subdomain] = {"server": server_type, "headers": headers, "open_ports": open_ports}

        if output_file:
            if json_output:
                with open(output_file, 'w') as outfile:
                    json.dump(output_data, outfile, indent=4)
            else:
                with open(output_file, 'w') as outfile:
                    for ip, subdomains_data in output_data.items():
                        for subdomain, data in subdomains_data.items():
                            outfile.write(f"{subdomain},{ip},{data['server']},{data['headers']},{data['open_ports']}\n")

        end_time = time.time()
        print(f"\n[+] Found {found_subdomains_count} subdomains in {end_time - start_time:.2f} seconds.")
        return output_data

    except FileNotFoundError:
        print(f"Error: Wordlist file not found at {wordlist_path}")
        return {}
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {}

def main():
    """Main function to parse arguments and execute subdomain enumeration."""
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool (dnspython)")
    parser.add_argument("-d", "--domain", required=True, help="Domain to enumerate subdomains for (e.g., hilton.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-o", "--output", help="Path to output file (optional)")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (show headers)")
    parser.add_argument("-p", "--ports", nargs='+', type=int, help="Check for open ports (e.g., 80 443)")
    parser.add_argument("-k", "--keyword", help="Filter subdomains by keyword in headers")
    args = parser.parse_args()
    enumerate_subdomains(args.domain, args.wordlist, args.output, args.json, args.verbose, args.ports, args.keyword)

if __name__ == "__main__":
    main()
