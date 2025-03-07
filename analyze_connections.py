#!/usr/bin/env python3

import json
from pathlib import Path
from collections import Counter
from datetime import datetime
import sys

def analyze_connections(log_file: Path):
    """Analyze connection logs and provide insights."""
    if not log_file.exists():
        print(f"Log file {log_file} does not exist!")
        return

    with open(log_file, 'r') as f:
        connections = json.load(f)

    if not connections:
        print("No connections found in log file.")
        return

    # Analyze connections
    total_connections = len(connections)
    unique_ips = set(conn['remote_ip'] for conn in connections)
    processes = Counter(conn['process']['name'] for conn in connections if conn['process'] and 'name' in conn['process'])
    domains = Counter(conn['dns_info'].get('hostname', 'Unknown') for conn in connections)
    organizations = Counter(conn['whois_info'].get('org', 'Unknown') for conn in connections)

    # Print analysis
    print(f"\nConnection Analysis Report")
    print("=" * 50)
    print(f"Total connections logged: {total_connections}")
    print(f"Unique IP addresses: {len(unique_ips)}")
    
    print("\nTop 10 Processes making connections:")
    print("-" * 50)
    for proc, count in processes.most_common(10):
        print(f"{proc}: {count} connections")

    print("\nTop 10 Domains contacted:")
    print("-" * 50)
    for domain, count in domains.most_common(10):
        print(f"{domain}: {count} connections")

    print("\nTop 10 Organizations (from WHOIS):")
    print("-" * 50)
    for org, count in organizations.most_common(10):
        print(f"{org}: {count} connections")

def main():
    if len(sys.argv) > 1:
        log_file = Path(sys.argv[1])
    else:
        # Use today's log file by default
        today = datetime.now().strftime('%Y%m%d')
        log_file = Path("logs") / f"connections_{today}.json"

    analyze_connections(log_file)

if __name__ == "__main__":
    main()