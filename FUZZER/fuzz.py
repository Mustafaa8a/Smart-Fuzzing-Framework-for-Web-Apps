import argparse,requests,pyfiglet,colorama,re
from pyfiglet import figlet_format
from colorama import Fore, Style, init


# Create parser
parser = argparse.ArgumentParser()

# Define arguments
parser.add_argument("-u", "--url", help="Target URL", required=True)
parser.add_argument("-w", "--wordlist", help="Path to wordlist")
parser.add_argument("-H", "--headers", help="Headers (optional)")
parser.add_argument("-X", "--method", help="HTTP method to use (GET/POST/PUT/DELETE/...). Default: GET", default="GET")
parser.add_argument("-d", "--data", help="Request data (e.g. 'a=1&b=2' or raw body). Optional.", default=None)
parser.add_argument("-dir", "--dirfuzz", 
                    nargs="?", const=True, default=False,
                    help="Directory fuzzing mode (optional wordlist after flag)")
parser.add_argument("-file", "--filefuzz", 
                    nargs="?", const=True, default=False,
                    help="File fuzzing mode (optional wordlist after flag)")


# Parse them
args = parser.parse_args()

url = args.url
wordlistPath=args.wordlist
data=args.data
mehtod=args.method
header=args.headers
dirFuzz= args.dirfuzz 
fileFuzz= args.filefuzz 


def get_default_wordlist(mode):
    defaults = {
        "dir": "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
        "file": "/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt",
        "passwords":"~/rockyou.txt"
    }
    return defaults[mode]


def search(wordlistPath):
    with open(f"{wordlistPath}","r") as file :
        for line in file :
            line=line.strip()

            if data :
                if "FUZZ" in data:
                    fURL=data.replace("FUZZ",line)   
                    res=requests.request(method=mehtod,url=f"{fURL}",data=data,headers=header)
            elif "FUZZ" in url :
                fURL=url.replace("FUZZ",line)   
                res=requests.request(method=mehtod,url=f"{fURL}",headers=header)
            
            if res.status_code!=404:
                print(f"Found: [{res.status_code}] {line} ")
                print("-"*60)


def main():
    init()
    ascii_art = figlet_format('F U Z Z E R')
    print(Fore.GREEN + ascii_art + Style.RESET_ALL)
    print("-"*60)

    if args.dirfuzz:
        print("[+] Started directory fuzzing")
        print("-"*60)

        if args.dirfuzz is True:
            wordlist = get_default_wordlist("dir")
            print(f"Using default: {wordlist}")
            print("-"*60)
        else:
            wordlist = args.dirfuzz
            print(f"Using custom: {wordlist}")
            print("-"*60)

        search(wordlist)

    if args.filefuzz:
        print("[+] Started file fuzzing")
        print("-"*60)

        if args.filefuzz is True:
            wordlist = get_default_wordlist("file")
            print(f"Using default: {wordlist}")
            print("-"*60)
        else:
            wordlist = args.filefuzz
            print(f"Using custom: {wordlist}")
            print("-"*60)

        search(wordlist)

    if not args.dirfuzz and not args.filefuzz:
        print(f"{Fore.RED}[-] Error: Use -dir or -file mode!{Style.RESET_ALL}")
    
if __name__=="__main__":
    main()
