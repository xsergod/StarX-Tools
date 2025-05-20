import socket
import concurrent.futures
import os
import platform
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class TCPPortScanner:
    def __init__(self):
        self.open_ports = []
        self.closed_ports = 0
        self.filtered_ports = 0
        self.start_time = None
        self.end_time = None
        self.target = ""

    def clear_console(self):
        os.system("cls" if os.name == "nt" else "clear")

    def banner(self):
        self.clear_console()
        os_type = platform.system()
        print(Fore.MAGENTA + Style.BRIGHT + "╔════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + Style.BRIGHT + f"             StarX TCP Port Scanner [{os_type}]")
        print(Fore.MAGENTA + Style.BRIGHT + "╚════════════════════════════════════════════════════════════╝")

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except:
                        service = "Unknown"
                    self.open_ports.append((port, service))
                else:
                    self.closed_ports += 1
        except socket.timeout:
            self.filtered_ports += 1
        except Exception:
            self.filtered_ports += 1

    def run_scan(self):
        self.start_time = datetime.now()
        print(Fore.YELLOW + f"\n[~] Scan started at: {self.start_time.strftime('%H:%M:%S')}\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=500) as executor:
            executor.map(self.scan_port, range(1, 65536))
        self.end_time = datetime.now()

    def show_results(self):
        duration = (self.end_time - self.start_time).total_seconds()
        print(Fore.GREEN + f"\n Scan finished in {duration:.2f} seconds")
        print(Fore.CYAN + f" Open ports ({len(self.open_ports)}):")
        for port, service in sorted(self.open_ports):
            print(Fore.LIGHTGREEN_EX + f"   - Port {port}: {service}")
        print(Fore.YELLOW + f"\n[-] Closed ports: {self.closed_ports}")
        print(Fore.RED + f"[-] Filtered ports: {self.filtered_ports}")

    def run(self):
        self.banner()
        self.target = input(Fore.CYAN + "\nEnter IP address or domain to scan: ").strip()
        print(Fore.YELLOW + f"\n[~] Scanning all TCP ports on {self.target}...\n")
        self.run_scan()
        self.show_results()

if __name__ == "__main__":
    scannerTCP = TCPPortScanner()
    scannerTCP.run()
