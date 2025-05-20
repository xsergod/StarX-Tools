import os
import platform
import subprocess
import time
import re
from colorama import Fore, Style, init

init(autoreset=True)

class IpPinger:
    def __init__(self):
        self.target = ""
        self.success = 0
        self.failed = 0
        self.latencies = []

    def clear_console(self):
        os.system("cls" if os.name == "nt" else "clear")

    def banner(self):
        self.clear_console()
        print(Fore.MAGENTA + Style.BRIGHT + "╔══════════════════════════════════════════════════════╗")
        print(Fore.CYAN + Style.BRIGHT + "                  StarX IP Pinger                       ")
        print(Fore.MAGENTA + Style.BRIGHT + "╚══════════════════════════════════════════════════════╝")

    def detect_os_by_ttl(self, ttl_value):
        if ttl_value is None:
            return "Unknown"
        elif ttl_value >= 128:
            return "Windows (Likely)"
        elif ttl_value >= 64:
            return "Linux/macOS (Likely)"
        elif ttl_value >= 255:
            return "Unix/Cisco (Likely)"
        else:
            return "Unknown"

    def extract_ttl(self, output):
        match = re.search(r'TTL[=|:](\d+)', output, re.IGNORECASE)
        return int(match.group(1)) if match else None

    def parse_latency(self, output):
        match = re.search(r"time[=<](\d+\.?\d*)\s*ms", output, re.IGNORECASE)
        return float(match.group(1)) if match else None

    def ping_once(self):
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", self.target]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            ttl = self.extract_ttl(output)
            latency = self.parse_latency(output)
            if latency:
                self.latencies.append(latency)
            os_guess = self.detect_os_by_ttl(ttl)
            self.success += 1
            print(Fore.GREEN + f" Ping successful | TTL={ttl} | Remote OS: {os_guess} | Latency: {latency} ms")
        except subprocess.CalledProcessError as e:
            self.failed += 1
            print(Fore.RED + f" Ping failed | Error: {e.output.strip()}")

    def start_pinging(self):
        try:
            while True:
                self.ping_once()
                total = self.success + self.failed
                avg_latency = f"{sum(self.latencies) / len(self.latencies):.2f} ms" if self.latencies else "N/A"
                print(Fore.CYAN + f"Total: {total} | Success: {self.success} | Failed: {self.failed} | Avg Latency: {avg_latency}")
                time.sleep(1)
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Ping stopped by user.")
            avg_latency = f"{sum(self.latencies) / len(self.latencies):.2f} ms" if self.latencies else "N/A"
            print(Fore.CYAN + f"Summary -> Success: {self.success}, Failed: {self.failed}, Avg Latency: {avg_latency}")

    def run(self):
        self.banner()
        self.target = input(Fore.CYAN + "\nEnter IP address or domain: ").strip()
        print(Fore.YELLOW + f"\n[~] Starting ping to {self.target}...\n")
        self.start_pinging()

if __name__ == "__main__":
    IpPinger().run()
