#!/usr/bin/env python3
"""
Network Scanner - Discovers live hosts and open ports on a network
Author: Bourice
Date:Dec 2025
"""

import socket
import sys
import argparse
from datetime import datetime
import concurrent.futures
from ipaddress import IPv4Network, IPv4Address

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Common ports to scan with their typical services
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt'
}

def print_banner():
    """Display scanner banner"""
    banner = f"""
{Colors.OKCYAN}
╔═══════════════════════════════════════════════╗
║          CUSTOM NETWORK SCANNER               ║
║          Discover Hosts & Services            ║
╚═══════════════════════════════════════════════╝
{Colors.ENDC}
    """
    print(banner)

def validate_ip(ip):
    """Validate IP address format"""
    try:
        IPv4Address(ip)
        return True
    except:
        return False

def ping_host(ip):
    """
    Check if host is alive using TCP SYN to port 80/443
    (More reliable than ICMP in firewalled environments)
    """
    ports_to_try = [80, 443, 22]
    
    for port in ports_to_try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                return True
        except:
            continue
    
    return False

def scan_port(ip, port, timeout=1):
    """
    Scan a single port on a host
    Returns: (port, is_open, service_name)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            service = COMMON_PORTS.get(port, 'Unknown')
            return (port, True, service)
        else:
            return (port, False, None)
    except socket.error:
        return (port, False, None)
    except Exception as e:
        return (port, False, None)

def grab_banner(ip, port, timeout=2):
    """
    Attempt to grab service banner for identification
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Try to receive banner
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            sock.close()
            return None
    except:
        return None

def scan_host(ip, ports, grab_banners=False):
    """
    Scan all specified ports on a single host
    """
    print(f"\n{Colors.OKBLUE}[*] Scanning {ip}...{Colors.ENDC}")
    
    open_ports = []
    
    # Use thread pool for faster scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in ports}
        
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open, service = future.result()
            
            if is_open:
                banner = None
                if grab_banners:
                    banner = grab_banner(ip, port)
                
                open_ports.append({
                    'port': port,
                    'service': service,
                    'banner': banner
                })
                
                # Print as we discover
                if banner:
                    print(f"{Colors.OKGREEN}  [+] Port {port}/tcp - {service} - {banner[:50]}{Colors.ENDC}")
                else:
                    print(f"{Colors.OKGREEN}  [+] Port {port}/tcp - {service}{Colors.ENDC}")
    
    return open_ports

def scan_network(network, ports, grab_banners=False):
    """
    Scan entire network range for live hosts and open ports
    """
    try:
        net = IPv4Network(network, strict=False)
    except ValueError as e:
        print(f"{Colors.FAIL}[!] Invalid network format: {e}{Colors.ENDC}")
        return
    
    print(f"{Colors.HEADER}[*] Scanning network: {network}{Colors.ENDC}")
    print(f"{Colors.HEADER}[*] Total hosts: {net.num_addresses}{Colors.ENDC}")
    print(f"{Colors.HEADER}[*] Ports to scan: {len(ports)}{Colors.ENDC}\n")
    
    live_hosts = []
    
    # Phase 1: Host Discovery
    print(f"{Colors.WARNING}[*] Phase 1: Discovering live hosts...{Colors.ENDC}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(ping_host, str(ip)): str(ip) for ip in net.hosts()}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                live_hosts.append(ip)
                print(f"{Colors.OKGREEN}[+] Host {ip} is alive{Colors.ENDC}")
    
    print(f"\n{Colors.OKCYAN}[*] Found {len(live_hosts)} live host(s){Colors.ENDC}")
    
    # Phase 2: Port Scanning
    if live_hosts:
        print(f"\n{Colors.WARNING}[*] Phase 2: Scanning ports on live hosts...{Colors.ENDC}")
        
        results = {}
        for ip in live_hosts:
            open_ports = scan_host(ip, ports, grab_banners)
            if open_ports:
                results[ip] = open_ports
        
        # Summary
        print_summary(results)
        return results
    else:
        print(f"{Colors.FAIL}[!] No live hosts found{Colors.ENDC}")
        return {}

def print_summary(results):
    """
    Print scan summary
    """
    print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}SCAN SUMMARY{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
    
    for ip, ports in results.items():
        print(f"{Colors.OKBLUE}Host: {ip}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}{'─'*40}{Colors.ENDC}")
        
        for port_info in ports:
            port = port_info['port']
            service = port_info['service']
            banner = port_info['banner']
            
            if banner:
                print(f"  {Colors.OKGREEN}Port {port:5d}/tcp  {service:15s}  {banner[:40]}{Colors.ENDC}")
            else:
                print(f"  {Colors.OKGREEN}Port {port:5d}/tcp  {service:15s}{Colors.ENDC}")
        print()

def save_results(results, filename):
    """
    Save scan results to file
    """
    try:
        with open(filename, 'w') as f:
            f.write(f"Network Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
            
            for ip, ports in results.items():
                f.write(f"Host: {ip}\n")
                f.write("-"*40 + "\n")
                
                for port_info in ports:
                    port = port_info['port']
                    service = port_info['service']
                    banner = port_info['banner']
                    
                    if banner:
                        f.write(f"  Port {port}/tcp - {service} - {banner}\n")
                    else:
                        f.write(f"  Port {port}/tcp - {service}\n")
                f.write("\n")
        
        print(f"{Colors.OKGREEN}[+] Results saved to {filename}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error saving results: {e}{Colors.ENDC}")

def main():
    """
    Main function - parse arguments and run scanner
    """
    parser = argparse.ArgumentParser(
        description='Network Scanner - Discover hosts and services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan single host with common ports:
    python3 scanner.py -t 192.168.1.1
  
  Scan network range:
    python3 scanner.py -t 192.168.1.0/24
  
  Scan specific ports:
    python3 scanner.py -t 192.168.1.1 -p 80,443,22
  
  Scan port range:
    python3 scanner.py -t 192.168.1.1 -p 1-1000
  
  Grab service banners:
    python3 scanner.py -t 192.168.1.1 -b
  
  Save results to file:
    python3 scanner.py -t 192.168.1.0/24 -o results.txt
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                        help='Target IP or network (e.g., 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('-p', '--ports',
                        help='Ports to scan (comma-separated or range, e.g., 80,443 or 1-1000)')
    parser.add_argument('-b', '--banner', action='store_true',
                        help='Attempt to grab service banners')
    parser.add_argument('-o', '--output',
                        help='Save results to file')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Parse ports
    if args.ports:
        ports = []
        for part in args.ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
    else:
        # Use common ports by default
        ports = list(COMMON_PORTS.keys())
    
    # Record start time
    start_time = datetime.now()
    print(f"{Colors.OKCYAN}[*] Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}\n")
    
    # Run scan
    if '/' in args.target:
        # Network scan
        results = scan_network(args.target, ports, args.banner)
    else:
        # Single host scan
        if validate_ip(args.target):
            results = {args.target: scan_host(args.target, ports, args.banner)}
        else:
            print(f"{Colors.FAIL}[!] Invalid IP address{Colors.ENDC}")
            sys.exit(1)
    
    # Record end time
    end_time = datetime.now()
    duration = end_time - start_time
    
    print(f"\n{Colors.OKCYAN}[*] Scan completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}[*] Total duration: {duration}{Colors.ENDC}\n")
    
    # Save results if requested
    if args.output:
        save_results(results, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
        sys.exit(1)
