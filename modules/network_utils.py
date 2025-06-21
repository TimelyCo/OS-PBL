"""
Network utilities module for Universal CLI Utility
"""

import socket
import ipaddress
import logging
import time
import subprocess
import threading
import queue
from datetime import datetime

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class NetworkUtilities:
    """
    Provides network scanning, monitoring, and analysis functions
    """
    def __init__(self):
        self.logger = logging.getLogger('ucli.net')
        self.stop_monitor = False
        
    def scan(self, target, ports=None):
        """Scan network target for open ports"""
        self.logger.info(f"Scanning target: {target}, ports: {ports}")
        
        try:
            # Resolve target if it's a hostname
            try:
                target_ip = socket.gethostbyname(target)
                if target != target_ip:
                    print(f"Resolved {target} to {target_ip}")
            except socket.gaierror:
                print(f"Error: Could not resolve hostname {target}")
                return
                
            # Parse port range
            port_list = []
            if ports:
                for part in ports.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        port_list.extend(range(start, end + 1))
                    else:
                        port_list.append(int(part))
            else:
                # Default to common ports
                port_list = [21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
            
            print(f"Starting scan of {target_ip} on {len(port_list)} ports...")
            start_time = time.time()
            
            # Create a queue for scan results
            result_queue = queue.Queue()
            
            # Create threads for parallel scanning
            threads = []
            for port in port_list:
                thread = threading.Thread(target=self._scan_port, args=(target_ip, port, result_queue))
                threads.append(thread)
                thread.start()
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            # Collect results
            open_ports = []
            while not result_queue.empty():
                port, service = result_queue.get()
                open_ports.append((port, service))
                
            # Sort results by port number
            open_ports.sort(key=lambda x: x[0])
            
            # Display results
            scan_time = time.time() - start_time
            print(f"\nScan completed in {scan_time:.2f} seconds")
            
            if open_ports:
                print(f"\nFound {len(open_ports)} open ports on {target_ip}:")
                print(f"{'PORT':<10} {'SERVICE':<20}")
                print("-" * 30)
                for port, service in open_ports:
                    print(f"{port:<10} {service:<20}")
            else:
                print(f"\nNo open ports found on {target_ip}")
                
        except Exception as e:
            self.logger.error(f"Error scanning target: {str(e)}")
            print(f"Error scanning target: {str(e)}")
    
    def _scan_port(self, ip, port, result_queue):
        """Scan a single port and put result in queue if open"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            s.close()
            
            if result == 0:
                # Port is open, try to identify service
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                    
                result_queue.put((port, service))
        except:
            pass
    
    def monitor(self, interface=None, packet_filter=None):
        """Monitor network traffic"""
        self.logger.info(f"Starting network monitor (interface: {interface}, filter: {packet_filter})")
        
        if not SCAPY_AVAILABLE:
            print("Error: This feature requires the scapy package. Install it with 'pip install scapy'")
            return
            
        try:
            # Reset monitoring flag
            self.stop_monitor = False
            
            print("Starting network traffic monitor (Press Ctrl+C to stop)...")
            
            # Initialize counters
            packet_count = 0
            protocol_stats = {}
            ip_stats = {}
            start_time = time.time()
            
            def packet_callback(packet):
                nonlocal packet_count
                
                if self.stop_monitor:
                    return
                    
                # Increment packet counter
                packet_count += 1
                
                # Extract basic info
                timestamp = datetime.now().strftime('%H:%M:%S')
                src = ""
                dst = ""
                proto = "Other"
                size = len(packet)
                
                # Get IP information if available
                if packet.haslayer(scapy.IP):
                    src = packet[scapy.IP].src
                    dst = packet[scapy.IP].dst
                    
                    # Update IP statistics
                    ip_stats[src] = ip_stats.get(src, 0) + size
                    ip_stats[dst] = ip_stats.get(dst, 0) + size
                    
                    # Determine protocol
                    if packet.haslayer(scapy.TCP):
                        proto = f"TCP {packet[scapy.TCP].sport} -> {packet[scapy.TCP].dport}"
                        if packet[scapy.TCP].dport == 80 or packet[scapy.TCP].sport == 80:
                            proto = "HTTP"
                        elif packet[scapy.TCP].dport == 443 or packet[scapy.TCP].sport == 443:
                            proto = "HTTPS"
                    elif packet.haslayer(scapy.UDP):
                        proto = f"UDP {packet[scapy.UDP].sport} -> {packet[scapy.UDP].dport}"
                        if packet[scapy.UDP].dport == 53 or packet[scapy.UDP].sport == 53:
                            proto = "DNS"
                    elif packet.haslayer(scapy.ICMP):
                        proto = "ICMP"
                        
                # Update protocol statistics
                protocol_stats[proto] = protocol_stats.get(proto, 0) + 1
                
                # Print packet info
                print(f"[{timestamp}] {src:15} -> {dst:15} | {proto:20} | {size:5} bytes")
                
                # Periodically show statistics
                if packet_count % 100 == 0:
                    runtime = time.time() - start_time
                    print("\n--- Statistics ---")
                    print(f"Captured {packet_count} packets in {runtime:.1f} seconds ({packet_count/runtime:.1f} packets/sec)")
                    
                    # Show protocol distribution
                    print("\nProtocol Distribution:")
                    for proto, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                        print(f"  {proto}: {count} ({count/packet_count*100:.1f}%)")
                        
                    # Show top talkers
                    print("\nTop Talkers:")
                    for ip, bytes_count in sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                        print(f"  {ip}: {self._format_bytes(bytes_count)}")
                    
                    print("\nContinuing capture...\n")
            
            # Start packet capture
            try:
                scapy.sniff(iface=interface, filter=packet_filter, prn=packet_callback, store=0)
            except KeyboardInterrupt:
                runtime = time.time() - start_time
                print("\n\nCapture stopped by user")
                print(f"Captured {packet_count} packets in {runtime:.1f} seconds ({packet_count/runtime:.1f} packets/sec)")
                
        except Exception as e:
            self.logger.error(f"Error in network monitor: {str(e)}")
            print(f"Error in network monitor: {str(e)}")
            
    def _format_bytes(self, bytes_value):
        """Format bytes in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024:
                return f"{bytes_value:.1f}{unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f}PB"