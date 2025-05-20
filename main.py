import os
import time
#bakshe import haye discord
import programs.Cleaner
import programs.accountnuker
import programs.webhookspam
#bakhshe import haye site
import programs.ippinger
import programs.TCPPort
import programs.UDPPort
import programs.SQLI
import programs.XSS
import programs.DDoS.DDOSLoading


from programs.ippinger import IpPinger
from programs.TCPPort import TCPPortScanner
from programs.UDPPort import UDPPortScanner
from programs.SQLI import StarXSQLiScanner
from programs.XSS import StarXSSScanner
#utils
import programs.hash
import programs.decoders


from programs.hash import show_hash_menu
from programs.decoders import show_decode_menu
#-----------------
from colorama import Fore, Style, init


init(autoreset=True)

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def run_main_menu():
    clear()
    
    
    option_info_txt = Fore.CYAN + "StarX Tools Panel"


    #Bakhshe Discord
    option_01_txt = Fore.YELLOW + "[1] Server Nuker"
    option_02_txt = Fore.YELLOW + "[2] Account Nuker"
    option_03_txt = Fore.YELLOW + "[3] Webhook Spammer"



    #bakhshe Site
    option_11_txt = Fore.YELLOW + "[11] Ip Pinger"
    option_12_txt = Fore.YELLOW + "[12] Sqli Scanner"
    option_13_txt = Fore.YELLOW + "[13] XSS Scanner"
    option_14_txt = Fore.YELLOW + "[14] All UDP Ports Scanner"
    option_15_txt = Fore.YELLOW + "[15] All TCP Ports Scanner"
    option_16_txt = Fore.YELLOW + "[16] DDOS"

    #bakhshe util
    option_21_txt = Fore.YELLOW + "[21] Hash Tools"
    option_22_txt = Fore.YELLOW + "[22] decoder Tools"


    option_04_txt = option_05_txt = option_06_txt = Fore.WHITE + "[ ] N/A"



    option_17_txt = option_18_txt = option_19_txt = Fore.WHITE + "[ ] N/A"



    option_23_txt = option_24_txt = option_25_txt = option_26_txt = option_27_txt = Fore.WHITE + "[ ] N/A"



    menu1 = f"""{Fore.CYAN}
 ┌─ {option_info_txt:<95}
 ├─          ┌─────────────────┐                        ┌───────┐                           ┌───────────┐            │
 └─┬─────────┤     Discord     ├─────────┬──────────────┤ Site  ├──────────────┬────────────┤ Utilities ├────────────┴─
   │         └─────────────────┘         │              └───────┘              │            └───────────┘
   ├─ {option_01_txt:<35}     ├─ {option_11_txt:<35}├─ {option_21_txt}
   ├─ {option_02_txt:<35}     ├─ {option_12_txt:<35}├─ {option_22_txt}
   ├─ {option_03_txt:<35}     ├─ {option_13_txt:<35}├─ {option_23_txt}
   ├─ {option_04_txt:<35}     ├─ {option_14_txt:<35}├─ {option_24_txt}
   ├─ {option_05_txt:<35}     ├─ {option_15_txt:<35}├─ {option_25_txt}
   └─ {option_06_txt:<35}     ├─ {option_16_txt:<35}├─ {option_26_txt}
                                         ├─ {option_17_txt:<35}└─ {option_27_txt}
                                         ├─ {option_18_txt:<35}
                                         └─ {option_19_txt:<35}
"""

    print(menu1)

    choice = input(Fore.CYAN + "\n ➤ Enter option number: ").strip()

    if choice == "1":
        clear()
        programs.Cleaner.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to return to main menu...")


    elif choice == "2":
        clear()
        programs.accountnuker.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to return to main menu...")

    elif choice == "3":
        clear()
        programs.webhookspam.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to return to main menu...")


    elif choice == "11":
        clear()
        pinger = IpPinger()
        pinger.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to return to main menu...")
    elif choice == "12":
        clear()
        scannersqli = StarXSQLiScanner()
        scannersqli.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "13":
        clear()
        scannerxss = StarXSSScanner()
        scannerxss.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "14":
        clear()
        scannerUDP = UDPPortScanner()
        scannerUDP.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "15":
        clear()
        scannerTCP = TCPPortScanner()
        scannerTCP.run()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "16":
        clear()
        programs.DDoS.DDOSLoading.run_ddos_attack()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "21":
        clear()
        programs.hash.show_hash_menu()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")
    elif choice == "22":
        clear()
        programs.decoders.show_decode_menu()
        input(Fore.MAGENTA + "\n↩ Press Enter to exit")


    else:
        print(Fore.RED + "Invalid option.")
        time.sleep(1)
        run_main_menu()


if __name__ == "__main__":
    run_main_menu()
