#!/usr/bin/env python3

import psutil
import socket
import whois
import dns.resolver
import time
from datetime import datetime
import json
from pathlib import Path
import subprocess
from typing import Dict, List, Optional

class ConnectionMonitor:
    def __init__(self):
        self.known_connections = set()
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)

    def get_process_info(self, pid: int) -> Dict:
        """Get information about a process."""
        try:
            process = psutil.Process(pid)
            return {
                "name": process.name(),
                "exe": process.exe(),
                "cmdline": process.cmdline(),
                "username": process.username(),
                "create_time": datetime.fromtimestamp(process.create_time()).isoformat()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"error": f"Could not access process info for PID {pid}"}

    def perform_nslookup(self, ip: str) -> Dict:
        """Perform reverse DNS lookup for an IP address."""
        try:
            host = socket.gethostbyaddr(ip)
            return {
                "hostname": host[0],
                "aliases": host[1],
                "ip_addresses": host[2]
            }
        except socket.herror:
            return {"error": f"Could not perform reverse DNS lookup for {ip}"}

    def perform_whois(self, ip: str) -> Dict:
        """Perform WHOIS lookup for an IP address."""
        try:
            w = whois.whois(ip)
            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "org": w.org,
                "country": w.country,
                "hostname": w.get('name', None)  # Add hostname from WHOIS if available
            }
        except Exception as e:
            return {"error": f"Could not perform WHOIS lookup for {ip}: {str(e)}"}

    def monitor_connections(self):
        """Monitor and log outgoing connections."""
        while True:
            try:
                # Get all network connections
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    # Skip if no remote address or if connection is not established
                    if not conn.raddr or conn.status != 'ESTABLISHED':
                        continue

                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    local_port = conn.laddr.port
                    pid = conn.pid

                    # Create unique connection identifier
                    conn_id = f"{remote_ip}:{remote_port}-{local_port}"

                    # Skip if we've already logged this connection
                    if conn_id in self.known_connections:
                        continue

                    # Add to known connections
                    self.known_connections.add(conn_id)

                    # Gather connection information
                    connection_info = {
                        "timestamp": datetime.now().isoformat(),
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": local_port,
                        "process": self.get_process_info(pid) if pid else None,
                        "dns_info": self.perform_nslookup(remote_ip),
                        "whois_info": self.perform_whois(remote_ip)
                    }

                    # Log the connection information
                    log_file = self.log_dir / f"connections_{datetime.now().strftime('%Y%m%d')}.json"
                    
                    # Read existing logs if file exists
                    existing_logs = []
                    if log_file.exists():
                        with open(log_file, 'r') as f:
                            existing_logs = json.load(f)

                    # Append new connection
                    existing_logs.append(connection_info)

                    # Write updated logs
                    with open(log_file, 'w') as f:
                        json.dump(existing_logs, f, indent=2)

                    print(f"\nNew connection detected:")
                    print(f"Remote: {remote_ip}:{remote_port}")
                    print(f"Process: {connection_info['process']['name'] if connection_info['process'] else 'Unknown'}")
                    if connection_info['whois_info'].get('hostname'):
                        print(f"WHOIS Hostname: {connection_info['whois_info']['hostname']}")
                    elif connection_info['dns_info'].get('hostname'):
                        print(f"DNS Hostname: {connection_info['dns_info']['hostname']}")
                    print("-" * 50)

            except Exception as e:
                print(f"Error monitoring connections: {str(e)}")

            time.sleep(1)  # Check every second

if __name__ == "__main__":
    print("Starting connection monitor...")
    print("Monitoring outgoing connections. Press Ctrl+C to stop.")
    monitor = ConnectionMonitor()
    try:
        monitor.monitor_connections()
    except KeyboardInterrupt:
        print("\nStopping connection monitor...")