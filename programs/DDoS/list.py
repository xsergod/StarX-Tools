import os
import sys
from colorama import Fore, Style

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def rda():
    clear_console()
    print(Fore.MAGENTA + Style.BRIGHT + "╔══════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "       StarX DDoSeRs (Only Linux)       ")
    print(Fore.MAGENTA + Style.BRIGHT + "╚══════════════════════════════════════╝")
    print(Fore.YELLOW + "Select an option:")
    print(Fore.BLUE + "1 - TCP")
    print(Fore.BLUE + "2 - HTTP")
    print(Fore.BLUE + "3 - UDP")

    choice = input(Fore.WHITE + "Enter your choice (1/2/3): ")

    if choice == '1':
        run_TCP()
    elif choice == '2':
        run_HTTP()
    elif choice == '3':
        run_UDP()
    else:
        print(Fore.RED + "Invalid choice! Please try again.")
        rda()

def run_TCP():
    print(Fore.GREEN + "Running TCP DDoS Attack...")
    try:
        from programs.DDoS import tcp_flood
        tcp_flood.tcpstart()
    except ImportError as ee:
        print(ee)

def run_HTTP():
    print(Fore.CYAN + "Running HTTP DDoS Attack...")
    try:
        from programs.DDoS import http_flood
        http_flood.httstt()
    except ImportError as e:
        print(e)

def run_UDP():
    print(Fore.RED + "[UDP DDOSER] IS UNDER MAINTENANCE")


if __name__ == "__main__":
    rda()
