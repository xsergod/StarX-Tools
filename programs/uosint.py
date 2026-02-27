import time
import sys
from requests import get
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init
from fuzzywuzzy import fuzz
from urllib.parse import urlparse, urljoin, unquote
import re

try:
    from duckduckgo_search import ddg
    DDG_AVAILABLE = True
except ImportError:
    DDG_AVAILABLE = False

try:
    from googlesearch import search
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

init(autoreset=True)

SX_LOGO = '''
███████╗██╗  ██╗         ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔════╝╚██╗██╔╝        ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
███████╗ ╚███╔╝         ██║   ██║███████╗██║██╔██╗ ██║   ██║   
╚════██║ ██╔██╗         ██║   ██║╚════██║██║██║╚██╗██║   ██║   
███████║██╔╝ ██╗        ╚██████╔╝███████║██║██║ ╚████║   ██║   
╚══════╝╚═╝  ╚═╝         ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
'''

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36'
}
MAX_RESULTS = 2000

def extract_real_url(url):
    if 'duckduckgo.com/l/?uddg=' in url:
        match = re.search(r'uddg=([^&]+)', url)
        if match:
            try:
                return unquote(match.group(1))
            except:
                pass
    return url

def normalize_href(href, base=None):
    if not href:
        return None
    href = href.strip()
    if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
        return None
    if href.startswith('//'):
        return 'https:' + href
    if base and not href.startswith('http'):
        try:
            return urljoin(base, href)
        except Exception:
            return None
    return href

def duckduckgo_results(q, max_results=2000):
    if DDG_AVAILABLE:
        try:
            results = ddg(q, max_results=max_results)
            for r in results:
                if isinstance(r, dict):
                    url = r.get('href') or r.get('link') or r.get('url')
                else:
                    url = r
                if url:
                    real_url = extract_real_url(url)
                    yield real_url
            return
        except Exception:
            pass
    
    try:
        resp = get('https://html.duckduckgo.com/html/', params={'q': q}, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        anchors = soup.select('a.result__a')
        count = 0
        for a in anchors:
            if count >= max_results:
                break
            href = a.get('href')
            if href:
                real_url = extract_real_url(href)
                if real_url:
                    yield real_url
                    count += 1
    except Exception:
        return

def google_results(q, max_results=2000):
    if GOOGLE_AVAILABLE:
        try:
            for url in search(q, stop=max_results):
                yield url
        except Exception:
            return
    return

def analyze_page(url, query):
    print('\n' + Fore.CYAN + '[+] Url detected: ' + url)
    
    try:
        page = get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        text = page.text
    except Exception as e:
        print(Fore.RED + f'   (fetch error: {e})')
        return
    
    soup = BeautifulSoup(text, "html.parser")
    
    try:
        title = soup.title.text.replace('\n', '').strip()
        if title:
            print(Fore.MAGENTA + '- Title: ' + title[:100] + '...' if len(title) > 100 else Fore.MAGENTA + '- Title: ' + title)
        else:
            print(Fore.RED + '- Title: null')
    except Exception:
        print(Fore.RED + '- Title: null')
    
    links_detected = []
    for link in soup.find_all('a', href=True):
        href = normalize_href(link.get('href'), base=url)
        if not href or not href.startswith('http') or href in links_detected:
            continue
        
        try:
            link_text = (link.text or '').strip()
            query_lower = query.lower()
            
            if query_lower in href.lower():
                print(Fore.GREEN + '--- Requested data found at link : ' + href)
                links_detected.append(href)
            elif query_lower in link_text.lower():
                print(Fore.GREEN + '--- Link text contains query : ' + link_text)
                print(Fore.CYAN + '      ' + href)
                links_detected.append(href)
            elif fuzz.ratio(link_text, query) >= 60:
                print(Fore.GREEN + '--- Text and link are similar : ' + link_text)
                print(Fore.CYAN + '      ' + href)
                links_detected.append(href)
        except Exception:
            continue
    
    if not links_detected:
        if query.lower() in soup.get_text().lower():
            print(Fore.YELLOW + '- Keyword found in text but no related links')
        else:
            print(Fore.RED + '- No data')

def startosint(query, max_results=150):
    print(Fore.GREEN + '- Searching ' + query)
    
    try:
        count = 0
        for url in duckduckgo_results(query, max_results):
            analyze_page(url, query)
            count += 1
            time.sleep(0.5)
            if count >= max_results // 3:
                break
        count = 0
        for url in google_results(query, max_results // 3):
            analyze_page(url, query)
            count += 1
            time.sleep(0.6)
            if count >= max_results // 3:
                break
        
        print('\n' + Fore.GREEN + '[+] Search finished.')
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Search interrupted by user (Ctrl+C).")
        return False
    except Exception as e:
        print(Fore.RED + f"\n[!] Error during search: {e}")
        return False
    
    return True

def sikimosint():
    print(Fore.YELLOW + SX_LOGO)
    query = input(Back.BLACK + Fore.YELLOW + 'Find > ' + Back.RESET + Fore.WHITE)
    startosint(query, MAX_RESULTS)
