# Detailed Usage Guide

## Basic Concepts

### What is Port Scanning?
Port scanning is the process of checking which ports on a network host are open and accepting connections.

### Common Ports
- **22**: SSH (Secure Shell)
- **80**: HTTP (Web)
- **443**: HTTPS (Secure Web)
- **3306**: MySQL Database
- **3389**: RDP (Remote Desktop)

## Step-by-Step Examples

### Example 1: Check if a Web Server is Running
```bash
python3 scanner.py -t example.com -p 80,443
```

**Expected Output:**
- Port 80 open = HTTP server running
- Port 443 open = HTTPS server running

### Example 2: Discover All Devices on Your Home Network
```bash
python3 scanner.py -t 192.168.1.0/24
```

This scans all 254 possible hosts on your network.

### Example 3: Deep Scan of a Single Server
```bash
python3 scanner.py -t 192.168.1.10 -p 1-1000 -b -o server_scan.txt
```

Scans first 1000 ports, grabs banners, saves to file.

## Performance Tips

- **Faster Scanning**: Scan fewer ports
- **More Thorough**: Include banner grabbing (`-b`)
- **Large Networks**: Save to file (`-o`) to review later

## Interpreting Results

### Open Port
```
[+] Port 22/tcp - SSH
```
Service is running and accepting connections.

### No Response
If a port isn't listed, it's either:
- Closed (no service)
- Filtered (firewall blocking)

### Banner Information
```
[+] Port 22/tcp - SSH - OpenSSH_8.2p1 Ubuntu
```
Banner reveals service version (useful for vulnerability research).

## Common Use Cases

### Network Administration
- Verify firewall rules
- Check service availability
- Inventory network devices

### Security Testing
- Find open services
- Identify outdated software
- Discover forgotten services

### Troubleshooting
- Verify service is running
- Check connectivity
- Diagnose connection issues
