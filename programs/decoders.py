import base64
import binascii
import urllib.parse
import html
import codecs
import json
import gzip
import zlib
import os

from colorama import Fore, Style, init

init(autoreset=True)

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_console()
    print(Fore.MAGENTA + Style.BRIGHT + "╔══════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "        StarX Universal Decoder        ")
    print(Fore.MAGENTA + Style.BRIGHT + "╚══════════════════════════════════════╝")

def decode_text(text, method):
    try:
        if method == 'base64':
            return base64.b64decode(text).decode("utf-8", "ignore")
        elif method == 'base32':
            return base64.b32decode(text).decode("utf-8", "ignore")
        elif method == 'base85':
            return base64.b85decode(text).decode("utf-8", "ignore")
        elif method == 'hex':
            return bytes.fromhex(text).decode("utf-8", "ignore")
        elif method == 'url':
            return urllib.parse.unquote(text)
        elif method == 'html':
            return html.unescape(text)
        elif method == 'rot13':
            return codecs.decode(text, 'rot_13')
        elif method == 'binary':
            return ''.join([chr(int(b, 2)) for b in text.split()])
        elif method == 'unicode_escape':
            return text.encode('utf-8').decode('unicode_escape')
        elif method == 'zlib_base64':
            return zlib.decompress(base64.b64decode(text)).decode("utf-8", "ignore")
        elif method == 'gzip_base64':
            return gzip.decompress(base64.b64decode(text)).decode("utf-8", "ignore")
        elif method == 'jwt':
            parts = text.strip().split('.')
            if len(parts) < 2:
                return "Invalid JWT format"
            def decode_part(part):
                padding = '=' * ((4 - len(part) % 4) % 4)
                return json.loads(base64.urlsafe_b64decode(part + padding).decode('utf-8', 'ignore'))
            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            return (
                Fore.YELLOW + "Header:\n" +
                Fore.WHITE + json.dumps(header, indent=2) +
                "\n\n" +
                Fore.YELLOW + "Payload:\n" +
                Fore.WHITE + json.dumps(payload, indent=2)
            )
        else:
            return "Unknown decoding method!"
    except Exception as e:
        return f"Error: {str(e)}"

def show_decode_menu():
    methods = [
        ("Base64", "base64"),
        ("Base32", "base32"),
        ("Base85", "base85"),
        ("Hex", "hex"),
        ("URL Decode", "url"),
        ("HTML Entities", "html"),
        ("ROT13", "rot13"),
        ("Binary", "binary"),
        ("Unicode Escape", "unicode_escape"),
        ("Zlib (Base64 Encoded)", "zlib_base64"),
        ("Gzip (Base64 Encoded)", "gzip_base64"),
        ("JWT", "jwt"),
    ]

    while True:
        print_banner()
        print(Fore.YELLOW + Style.BRIGHT + " Select a decoding method:\n")
        for idx, (name, _) in enumerate(methods, 1):
            print(f"  {idx} - {name}")
        print("  0 - Exit")

        try:
            choice = int(input("\n Your choice: "))
            if choice == 0:
                break
            elif 1 <= choice <= len(methods):
                method_name = methods[choice - 1][1]
                text = input(Fore.GREEN + "\n Enter the text to decode: ")
                result = decode_text(text, method_name)
                print(Fore.CYAN + "\n Decoded result:\n")
                print(Fore.WHITE + Style.BRIGHT + result)
                input(Fore.YELLOW + "\n Press Enter to continue...")
            else:
                print(Fore.RED + "Invalid choice!")
        except ValueError:
            print(Fore.RED + "Please enter a number only!")

if __name__ == "__main__":
    show_decode_menu()
