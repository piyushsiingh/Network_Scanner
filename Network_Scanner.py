import socket import subprocess import ipaddress import platform import re import argparse import shutil import logging from concurrent.futures import ThreadPoolExecutor, as_completed from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(message)s')

class NetworkScanner: def init(self, network_cidr, ports=None, max_threads=100): self.network_cidr = network_cidr self.ports = ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389] self.max_threads = max_threads self.results = {} self.os_type = platform.system().lower()

def ping_host(self, ip):
    try:
        param = '-n' if self.os_type == 'windows' else '-c'
        command = ['ping', param, '1']
        if self.os_type == 'windows':
            command += ['-w', '1000']  # 1 sec in ms
        else:
            command += ['-W', '1']     # 1 sec timeout
        command.append(str(ip))
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        return output.returncode == 0
    except Exception:
        return False

def scan_port(self, ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((str(ip), port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return port, service
    except Exception:
        return None

def get_mac_address(self, ip):
    try:
        command = ['arp', '-a', str(ip)] if self.os_type == 'windows' else ['arp', '-n', str(ip)]
        if not shutil.which('arp'):
            return "ARP not available"
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        mac = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output.stdout)
        return mac.group(0) if mac else "Unknown"
    except Exception:
        return "Unknown"

def scan_network(self):
    try:
        network = ipaddress.ip_network(self.network_cidr, strict=False)
        logging.info(f"[*] Scanning {network.num_addresses} hosts in {self.network_cidr}...")

        active_hosts = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.ping_host, ip): ip for ip in network.hosts()}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        active_hosts.append(ip)
                        logging.info(f"[+] Host {ip} is up")
                except Exception as e:
                    logging.warning(f"[-] Error scanning {ip}: {e}")

        for host in active_hosts:
            self.results[host] = {
                'mac': self.get_mac_address(host),
                'ports': []
            }
            logging.info(f"\n[*] Scanning ports on {host}")
            with ThreadPoolExecutor(max_workers=min(self.max_threads, len(self.ports))) as executor:
                futures = [executor.submit(self.scan_port, host, port) for port in self.ports]
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            port, service = result
                            self.results[host]['ports'].append((port, service))
                            logging.info(f"[+] Port {port} ({service}) is open")
                    except Exception as e:
                        logging.warning(f"[-] Error scanning port: {e}")

        logging.info("\n[!] Scan Summary:")
        logging.info(f"  Hosts Up: {len(active_hosts)}")
        logging.info(f"  Ports Scanned per Host: {len(self.ports)}")
        total_open_ports = sum(len(data['ports']) for data in self.results.values())
        logging.info(f"  Total Open Ports Found: {total_open_ports}")

        return self.results

    except ValueError as e:
        logging.error(f"[-] Invalid network address: {e}")
        return {}
    except Exception as e:
        logging.error(f"[-] Unexpected error: {e}")
        return {}

def generate_report(self, filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_scan_{timestamp}.txt"

    try:
        with open(filename, 'w') as f:
            f.write(f"Network Scan Report - {datetime.now()}\n")
            f.write(f"Network: {self.network_cidr}\n")
            f.write("="*50 + "\n\n")

            for ip, data in self.results.items():
                f.write(f"Host: {ip}\n")
                f.write(f"MAC Address: {data['mac']}\n")
                f.write("Open Ports:\n")
                for port, service in data['ports']:
                    f.write(f"  - Port {port}: {service}\n")
                f.write("\n")

        logging.info(f"[*] Report saved to {filename}")
        return True
    except Exception as e:
        logging.error(f"[-] Error generating report: {e}")
        return False

def main(): parser = argparse.ArgumentParser(description="Simple Network Scanner") parser.add_argument("network", help="Network to scan in CIDR notation (e.g., 192.168.1.0/24)") parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan (default: common ports)") parser.add_argument("-t", "--threads", type=int, default=100, help="Maximum number of threads (default: 100)") parser.add_argument("-o", "--output", help="Output file name for the report")

args = parser.parse_args()

ports = None
if args.ports:
    try:
        ports = [int(p) for p in args.ports.split(",")]
    except ValueError:
        logging.error("[-] Invalid port list. Please provide comma-separated port numbers.")
        return

scanner = NetworkScanner(
    network_cidr=args.network,
    ports=ports,
    max_threads=args.threads
)

results = scanner.scan_network()

if results:
    scanner.generate_report(args.output)

if name == "main": main()

