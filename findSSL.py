# After identifying which ports have SSL/TLS, using sudo nmap -v -p- --open --script ssl-enum-ciphers -iL serverips.txt -oA servertestname
# Use this script to parse the .nmap output file to identify which ports have SSL/TLS.
# Use the file output option to create a file that can be used with https://github.com/mr-tomr/CryptographicFailures/blob/main/ScanMultiplePortsSingleHost.txt

import re
import argparse
import os
 
def extract_ssl_ports(nmap_file_path):
    ssl_ports = []
    with open(nmap_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
 
    current_port = None
    ssl_block = False
 
    for line in lines:
        line = line.strip()
        port_match = re.match(r'^(\d+)/tcp\s+open', line)
        if port_match:
            current_port = port_match.group(1)
            ssl_block = False
        elif current_port and "ssl-enum-ciphers:" in line:
            ssl_block = True
        elif ssl_block and line.startswith('|_'):
            ssl_ports.append(current_port)
            ssl_block = False
            current_port = None
 
    return ssl_ports
 
def write_output(ports, filepath, ports_only):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for port in ports:
                f.write(f"{port if ports_only else port + '/tcp'}\n")
        print(f"[+] Results written to: {filepath}")
    except Exception as e:
        print(f"[!] Failed to write output: {e}")
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract SSL-enabled ports from Nmap output created by --script ssl-enum-ciphers.")
    parser.add_argument("filename", help="Nmap output file (standard format, not XML)")
    parser.add_argument("--ports-only", action="store_true", help="Only output port number (e.g., 443 instead of 443/tcp)")
    parser.add_argument("--output", "-o", help="Output results to a .txt file")
 
    args = parser.parse_args()
 
    filepath = args.filename
    if not os.path.isabs(filepath):
        filepath = os.path.join(os.getcwd(), filepath)
 
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        exit(1)
 
    ssl_ports = extract_ssl_ports(filepath)
 
    if ssl_ports:
        if args.output:
            output_path = args.output
            if not os.path.isabs(output_path):
                output_path = os.path.join(os.getcwd(), output_path)
            write_output(ssl_ports, output_path, args.ports_only)
        else:
            print("[+] Ports with SSL found:")
            for port in ssl_ports:
                print(port if args.ports_only else f"{port}/tcp")
    else:
        print("[!] No SSL ports found.")
 
    # Example usage:
    #   python parse_ssl_ports.py scan_output.nmap
    #   python parse_ssl_ports.py scan_output.nmap --ports-only
    #   python parse_ssl_ports.py scan_output.nmap --output ssl_ports.txt
    #   python parse_ssl_ports.py scan_output.nmap --ports-only --output ssl_ports.txt
