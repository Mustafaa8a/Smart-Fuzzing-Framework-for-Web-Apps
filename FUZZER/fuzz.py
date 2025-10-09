import argparse,requests,pyfiglet,colorama
from pyfiglet import figlet_format
from colorama import Fore, Style, init

init()

ascii_art = figlet_format('F U Z Z E R')
print(Fore.GREEN + ascii_art + Style.RESET_ALL)
print("-------------------------------------------------")


# Create parser
parser = argparse.ArgumentParser()

# Define arguments
parser.add_argument("-u", "--url", help="Target URL", required=True)
parser.add_argument("-w", "--wordlist", help="Path to wordlist", required=True)
parser.add_argument("-b", "--cookie", help="Cookie header (optional)")

# Parse them
args = parser.parse_args()

url = args.url
wordlistPath=args.wordlist


with open(f"{wordlistPath}","r") as file :
    for line in file :
        line=line.strip()
        fURL=url.replace("FUZZ",line)
        res=requests.get(f"{fURL}")
        if res.status_code!=404:
            print(f"Found: [{res.status_code}] {line} ")
            print("-------------------------------------------------")
