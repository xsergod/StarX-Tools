import time
import requests
import threading
import os
from colorama import Fore, Style, init

init(autoreset=True)  

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def spam(webhook, msg, sleep):
    while True:
        try:
            data = requests.post(webhook, json={'content': msg})
            if data.status_code == 204:
                print(Fore.GREEN + f"Sent MSG: {msg}")
            elif data.status_code == 200:
                print(Fore.GREEN + f"Message Delivered: {msg}")
            else:
                print(Fore.YELLOW + f"Unexpected Response: {data.status_code}")
        except Exception as e:
            print(Fore.RED + f"Failed to send message. Error: {e}")
        time.sleep(sleep)

def run():
    clear_console()
    print(Fore.MAGENTA + Style.BRIGHT + "╔══════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "       StarX Discord Webhook Spammer   ")
    print(Fore.MAGENTA + Style.BRIGHT + "╚══════════════════════════════════════╝")

    webhook = input(Fore.CYAN + "\n Enter Webhook Url: ")
    msg = input(Fore.CYAN + "\n Enter Message: ")
    th = int(input(Fore.CYAN + "\n Enter Thread (recommended 200): "))
    sleep = int(input(Fore.CYAN + "\n Enter Delay (recommended 2): "))

    for _ in range(th):
        t = threading.Thread(target=spam, args=(webhook, msg, sleep))
        t.daemon = True  
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Stopped by user.")

if __name__ == "__main__":
    run()
