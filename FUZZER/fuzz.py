import argparse,requests,pyfiglet,colorama,re
from pyfiglet import figlet_format
from colorama import Fore, Style, init


# Create parser
parser = argparse.ArgumentParser()

# Define arguments
parser.add_argument("-u", "--url", help="Target URL", required=True)
parser.add_argument("-w", "--wordlist", help="Path to wordlist")
parser.add_argument(
    "-H", "--headers",
    action="append",
    help='Add headers, example: -H "User-Agent: test" -H "Authorization: token"',
    default=[]
)
parser.add_argument("-X", "--method", help="HTTP method to use (GET/POST/PUT/DELETE/...). Default: GET", default="GET")
parser.add_argument("-d", "--data", help="Request data (e.g. 'a=1&b=2' or raw body). Optional.", default=None)
parser.add_argument("-fc", "--filterCode", help="Filter stats code while fuzzing (-fc 403)", default=None,type=int)
parser.add_argument("-mc", "--matchCode", help="Filter stats code while fuzzing (-mc 200)", default=None,type=int)
parser.add_argument("-dir", "--dirfuzz", 
                    nargs="?", const=True, default=False,
                    help="Directory fuzzing mode (optional wordlist after flag)")
parser.add_argument("-file", "--filefuzz", 
                    nargs="?", const=True, default=False,
                    help="File fuzzing mode (optional wordlist after flag)")
parser.add_argument("-search", "--fuzz", 
                    nargs="?", const=True, default=False,
                    help="Fuzzing mode (optional wordlist after flag)")
parser.add_argument("-pass", "--passwords", 
                    nargs="?", const=True, default=False,
                    help="Fuzzing passowrds mode (optional wordlist after flag)")
parser.add_argument("-ci", "--commandInjection", 
                    nargs="?", const=True, default=False,
                    help="Command injection fuzzing mode (optional wordlist after flag)")
parser.add_argument("-lfi", "--localFileInclusion", 
                    nargs="?", const=True, default=False,
                    help="Local File Inclusion fuzzing mode (optional wordlist after flag)")


# Parse them
args = parser.parse_args()

url = args.url
wordlistPath=args.wordlist
data=args.data
mehtod=args.method
dirFuzz= args.dirfuzz 
fileFuzz= args.filefuzz 
fuzz= args.fuzz 
pasw= args.passwords 
ci= args.commandInjection 
lfi= args.localFileInclusion

# Parse header and split them as a key and value in a dictionary 
def parseHeaders(raw_headers):
    headerDict = {}
    for h in raw_headers:
        if ":" not in h:
            print(f"[!] Invalid header format: {h}")
            continue
        k, v = h.split(":", 1)
        headerDict[k.strip()] = v.strip()
    return headerDict

headers = parseHeaders(args.headers)

# Default word lists 
def get_default_wordlist(mode):
    defaults = {
        "dir": "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
        "file": "/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt",
        "fuzz": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "pass":"/usr/share/wordlists/rockyou.txt",
        "ci": "ci.txt",
        "lfi": "lfi.txt"
    }
    return defaults[mode]


def search(wordlistPath, fc, mc):
    try:
        with open(f"{wordlistPath}", "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()
                if not line:  # Skip empty lines
                    continue

                try:
                    # Handle data fuzzing (POST body)
                    if data and "FUZZ" in data:
                        fuzzed_data = data.replace("FUZZ", line)
                        res = requests.request(method=mehtod, url=url, data=fuzzed_data, headers=headers, timeout=10,allow_redirects=False)
                    # Handle URL fuzzing
                    elif "FUZZ" in url:
                        fuzzed_url = url.replace("FUZZ", line)
                        res = requests.request(method=mehtod, url=fuzzed_url, headers=headers, timeout=10)
                    else:
                        print(f"{Fore.RED}[-] Error: No FUZZ keyword found in URL or data!{Style.RESET_ALL}")
                        return
                    


                    # Match specific status code
                    if mc is not None:
                        if res.status_code == mc:
                            print(f"{Fore.GREEN}[+] Found: [{res.status_code}] {line}{Style.RESET_ALL}")
                            print("-"*60)
                    # Filter out specific status code and 404 (when no match code specified)
                    else:
                        # Skip if it matches filter code or is 404
                        if res.status_code == 404:
                            continue
                        if fc is not None and res.status_code == fc:
                            continue
                        # Show all other responses
                        print(f"{Fore.GREEN}[+] Found: [{res.status_code}] {line}{Style.RESET_ALL}")
                        print("-"*60)

                except requests.exceptions.RequestException as e:
                    print(f"{Fore.YELLOW}[!] Request failed for '{line}': {str(e)}{Style.RESET_ALL}")
                    continue

    except FileNotFoundError:
        print(f"{Fore.RED}[-] Error: Wordlist file not found: {wordlistPath}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error reading wordlist: {str(e)}{Style.RESET_ALL}")


def cmdI(wordlistPath):
    with open(f"{wordlistPath}", "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            # Only run if mode enabled AND FUZZ exists
            if args.commandInjection and "FUZZ" in data:

                # Replace FUZZ in the payload (correct behavior)
                payload = data.replace("FUZZ", line)

                try:
                    res = requests.request(
                        method=mehtod,
                        url=url,
                        data=payload,
                        timeout=10,
                        allow_redirects=False,
                        headers=headers
                    )

                    # Detection of /etc/passwd output
                    if "root:x:0:0:root:/root:/bin/bash" in res.text:
                        print(f"{Fore.RED}[+] Command injection detected{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[+] Working payload: \"{line}\" [{res.status_code}]{Style.RESET_ALL}")
                        print("-"*60)

                except requests.exceptions.Timeout:
                    print(f"{Fore.YELLOW}[!] Timeout for payload: {line}{Style.RESET_ALL}")

                except requests.exceptions.ConnectionError:
                    print(f"{Fore.YELLOW}[!] Connection error for payload: {line}{Style.RESET_ALL}")

                except Exception as e:
                    print(f"{Fore.RED}[!] Unexpected error with payload: {line}{Style.RESET_ALL}")
                    print(f"    Error: {e}")

def lfiF(wordlistPath):
    try:
        # Check if FUZZ keyword exists
        if data and "FUZZ" not in data:
            print(f"{Fore.RED}[-] Error: No FUZZ keyword found in data!{Style.RESET_ALL}")
            return
        
        if not data:
            print(f"{Fore.RED}[-] Error: No data provided! Use -d flag with FUZZ keyword{Style.RESET_ALL}")
            return

        with open(f"{wordlistPath}", "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                # Replace FUZZ in the payload
                payload = data.replace("FUZZ", line)

                try:
                    res = requests.request(
                        method=mehtod,
                        url=url,
                        data=payload,
                        timeout=10,
                        allow_redirects=False,
                        headers=headers
                    )

                    # Detection of flag in response
                    if "flag{" in res.text:
                        print(f"{Fore.RED}[+] LFI detected{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[+] Working payload: \"{line}\" [{res.status_code}]{Style.RESET_ALL}")
                        print("-"*60)

                except requests.exceptions.Timeout:
                    print(f"{Fore.YELLOW}[!] Timeout for payload: {line}{Style.RESET_ALL}")

                except requests.exceptions.ConnectionError:
                    print(f"{Fore.YELLOW}[!] Connection error for payload: {line}{Style.RESET_ALL}")

                except Exception as e:
                    print(f"{Fore.RED}[!] Unexpected error with payload: {line}{Style.RESET_ALL}")
                    print(f"    Error: {e}")

    except FileNotFoundError:
        print(f"{Fore.RED}[-] Error: Wordlist file not found: {wordlistPath}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error reading wordlist: {str(e)}{Style.RESET_ALL}")
 

def main():
    init()
    ascii_art = figlet_format('F U Z Z E R')
    print(Fore.GREEN + ascii_art + Style.RESET_ALL)
    print("-"*60)

    fc = args.filterCode if args.filterCode else None
    mc = args.matchCode if args.matchCode else None

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

        search(wordlist,fc,mc)

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

        search(wordlist,fc,mc)


    if args.fuzz:
        print("[+] Started fuzzing")
        print("-"*60)

        if args.fuzz is True:
            wordlist = get_default_wordlist("fuzz")
            print(f"Using default: {wordlist}")
            print("-"*60)
        else:
            wordlist = args.fuzz
            print(f"Using custom: {wordlist}")
            print("-"*60)

        search(wordlist,fc,mc)
    
    if args.passwords:
        print("[+] Started fuzzing passwords")
        print("-"*60)

        if args.passwords is True:
            wordlist = get_default_wordlist("pass")
            print(f"Using default: {wordlist}")
            print("-"*60)
        else:
            wordlist = args.passwords
            print(f"Using custom: {wordlist}")
            print("-"*60)

        search(wordlist,fc,mc)
    
    
    if args.commandInjection:
        print("[+] Started testing for command injection")
        print("-"*60)

        if args.commandInjection is True:
            wordlist = get_default_wordlist("ci")
            print(f"Using default: {wordlist}")
            print("-"*60)
        else:
            wordlist = args.commandInjection
            print(f"Using custom: {wordlist}")
            print("-"*60)

        cmdI(wordlist)
        
    if args.localFileInclusion:
        print("[+] Started testing for local file inclusion")
        print("-"*60)

        if args.localFileInclusion is True:
            wordlist = get_default_wordlist("lfi")
            print(f"Using default: {wordlist}")
            print("-"*60)
        else:
            wordlist = args.localFileInclusion
            print(f"Using custom: {wordlist}")
            print("-"*60)

        lfiF(wordlist)

if __name__=="__main__":
    main()
