import hashlib
import bcrypt
import os
from argon2 import PasswordHasher
from passlib.hash import scrypt
from colorama import Fore, Style, init

init(autoreset=True)

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_console()
    print(Fore.MAGENTA + Style.BRIGHT + "╔══════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "         StarX Universal Hasher        ")
    print(Fore.MAGENTA + Style.BRIGHT + "╚══════════════════════════════════════╝")

def hash_text(text, method):
    encoded = text.encode('utf-8')
    ph = PasswordHasher()
    
    try:
        if method == 'md5':
            return hashlib.md5(encoded).hexdigest()
        elif method == 'sha1':
            return hashlib.sha1(encoded).hexdigest()
        elif method == 'sha224':
            return hashlib.sha224(encoded).hexdigest()
        elif method == 'sha256':
            return hashlib.sha256(encoded).hexdigest()
        elif method == 'sha384':
            return hashlib.sha384(encoded).hexdigest()
        elif method == 'sha512':
            return hashlib.sha512(encoded).hexdigest()
        elif method == 'sha3_256':
            return hashlib.sha3_256(encoded).hexdigest()
        elif method == 'sha3_512':
            return hashlib.sha3_512(encoded).hexdigest()
        elif method == 'blake2b':
            return hashlib.blake2b(encoded).hexdigest()
        elif method == 'blake2s':
            return hashlib.blake2s(encoded).hexdigest()
        elif method == 'bcrypt':
            return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode()
        elif method == 'scrypt':
            return scrypt.hash(text)
        elif method == 'argon2':
            return ph.hash(text)
        else:
            return "Unknown algorithm!"
    except Exception as e:
        return f"Error: {str(e)}"

def show_hash_menu():
    algorithms = [
        ("MD5", "md5"),
        ("SHA-1", "sha1"),
        ("SHA-224", "sha224"),
        ("SHA-256", "sha256"),
        ("SHA-384", "sha384"),
        ("SHA-512", "sha512"),
        ("SHA3-256", "sha3_256"),
        ("SHA3-512", "sha3_512"),
        ("BLAKE2b", "blake2b"),
        ("BLAKE2s", "blake2s"),
        ("bcrypt", "bcrypt"),
        ("scrypt", "scrypt"),
        ("argon2", "argon2"),
    ]

    while True:
        print_banner()
        print(Fore.YELLOW + Style.BRIGHT + " Select a hashing algorithm:\n")
        for idx, (name, _) in enumerate(algorithms, 1):
            print(f"  {idx} - {name}")
        print("  0 - Exit")

        try:
            choice = int(input("\n Your choice: "))
            if choice == 0:
                break
            elif 1 <= choice <= len(algorithms):
                method_name = algorithms[choice - 1][1]
                text = input(Fore.GREEN + "\n Enter the text to hash: ")
                result = hash_text(text, method_name)
                print(Fore.CYAN + "\n Hashed result:")
                print(Fore.WHITE + Style.BRIGHT + result)
                input(Fore.YELLOW + "\n Press Enter to continue...")
            else:
                print(Fore.RED + "Invalid choice!")
        except ValueError:
            print(Fore.RED + "Please enter a number only!")

if __name__ == "__main__":
    show_hash_menu()
