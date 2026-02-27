import os
import time
import programs.ippinger
import programs.TCPPort
import programs.UDPPort
import programs.XSS
import programs.DDoS.list
import programs.webscan
import programs.virusmake
from programs.webscan import SXWebScanner
from programs.ippinger import IpPinger
from programs.TCPPort import TCPPortScanner
from programs.UDPPort import UDPPortScanner
from programs.XSS import XSSScanner
import programs.uosint
from colorama import Fore, Style, init
init(autoreset=True)
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def run_main_menu():
    clear()
    option_info_txt = Fore.CYAN + "StarX Tools Panel"
    option_11_txt = Fore.YELLOW + "[11] WebSite Scanner"
    option_02_txt = Fore.YELLOW + "[2] Osint"
    option_03_txt = Fore.YELLOW + "[3] Virus Generator"
    option_01_txt = Fore.YELLOW + "[1] Ip Pinger"
    option_12_txt = Fore.YELLOW + "[12] XSS Scanner"
    option_04_txt = Fore.YELLOW + "[4] All UDP Ports Scanner"
    option_05_txt = Fore.YELLOW + "[5] All TCP Ports Scanner"
    option_13_txt = Fore.YELLOW + "[13] DDOS"
    option_21_txt = Fore.YELLOW + "Wireless section soon"
    option_14_txt = option_22_txt = option_16_txt = option_15_txt = option_06_txt = Fore.WHITE + "[ ] N/A"
    option_17_txt = option_18_txt = option_19_txt = Fore.WHITE + "[ ] N/A"
    option_23_txt = option_24_txt = option_25_txt = option_26_txt = option_27_txt = Fore.WHITE + "[ ] N/A"
    menu1 = f"""{Fore.CYAN}
 ┌─ {option_info_txt:<95}
 ├─          ┌─────────────────┐                        ┌───────┐                           ┌───────────┐            │
 └─┬─────────┤       Hack      ├─────────┬──────────────┤ Site  ├──────────────┬────────────┤  WireLess ├────────────┴─
   │         └─────────────────┘         │              └───────┘              │            └───────────┘
   {Fore.CYAN}├─ {option_01_txt:<35}     {Fore.CYAN}├─ {option_11_txt:<35}     {Fore.CYAN}├─ {option_21_txt}
   {Fore.CYAN}├─ {option_02_txt:<35}     {Fore.CYAN}├─ {option_12_txt:<35}     {Fore.CYAN}├─ {option_22_txt}
   {Fore.CYAN}├─ {option_03_txt:<35}     {Fore.CYAN}├─ {option_13_txt:<35}     {Fore.CYAN}├─ {option_23_txt}
   {Fore.CYAN}├─ {option_04_txt:<35}     {Fore.CYAN}├─ {option_14_txt:<35}     {Fore.CYAN}├─ {option_24_txt}
   {Fore.CYAN}├─ {option_05_txt:<35}     {Fore.CYAN}├─ {option_15_txt:<35}     {Fore.CYAN}├─ {option_25_txt}
   {Fore.CYAN}└─ {option_06_txt:<35}     {Fore.CYAN}├─ {option_16_txt:<35}     {Fore.CYAN}├─ {option_26_txt}
                                         {Fore.CYAN}├─ {option_17_txt:<35}     {Fore.CYAN}└─ {option_27_txt}
                                         {Fore.CYAN}├─ {option_18_txt:<35}
                                         {Fore.CYAN}└─ {option_19_txt:<35}
"""
    print(menu1)
    choice = input(Fore.CYAN + "\n ➤ Enter option number: ").strip()
    if choice == "11":
        clear()
        programs.webscan.webrun()
        input(Fore.MAGENTA + "\n↩ Press Enter to return to main menu...")
    elif choice == "2":
        clear()
        programs.uosint.sikimosint()
        input(Fore.MAGENTA + "\n↩ Press Enter to return to main menu...")
    elif choice == "3":
        clear()
        programs.virusmake.virusgen()
        input(Fore.MAGENTA + "\n↩ Press Enter to return to main menu...")
    elif choice == "01":
        clear()
        pinger = IpPinger()
        pinger.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to return to main menu...")
    elif choice == "12":
        clear()
        scannerxss = XSSScanner()
        scannerxss.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "4":
        clear()
        scannerUDP = UDPPortScanner()
        scannerUDP.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "5":
        clear()
        scannerTCP = TCPPortScanner()
        scannerTCP.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "13":
        clear()
        programs.DDoS.list.rda()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "21":
        clear()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "22":
        clear()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    else:
        print(Fore.RED + "Invalid option.")
        time.sleep(1)
        run_main_menu()
if __name__ == "__main__":
    run_main_menu()
