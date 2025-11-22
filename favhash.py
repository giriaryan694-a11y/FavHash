#!/usr/bin/env python3
# --- Dependency Check ---
# This must be the first block of code to run.
import sys
import os
import codecs  # <-- IMPORTED FOR CORRECT MMH3 HASHING

try:
    import requests
    import mmh3
    import hashlib
    import base64
    import argparse
    from urllib.parse import urlparse, urlunparse
    import colorama
    from termcolor import colored
    from pyfiglet import Figlet
except ImportError:
    print("[!] FATAL: Missing required dependencies.", file=sys.stderr)
    print("    Please install them using pip:", file=sys.stderr)
    print("    pip install requests mmh3 pyfiglet termcolor colorama", file=sys.stderr)
    sys.exit(1)
# --- End Dependency Check ---


# Global flag to control color output
COLOR_ENABLED = True


def c_print(text, color=None, on_color=None, attrs=None, force=False, **kwargs):
    """
    Custom print function that respects the global COLOR_ENABLED flag.
    """
    if COLOR_ENABLED or force:
        print(colored(text, color, on_color, attrs), **kwargs)
    else:
        print(text, **kwargs)


def print_banner():
    """
    Prints the ASCII art banner and credit.
    """
    try:
        # Use a standard, ASCII-safe font
        f = Figlet(font='standard')
        banner = f.renderText('Fav Hash')
        c_print(banner, 'cyan', attrs=['bold'])
    except Exception:
        # Fallback if pyfiglet fails
        c_print("\n=== Fav Hash ===\n", 'cyan', attrs=['bold'])
    
    c_print("    Made by Aryan Giri\n", 'white')


def parse_args():
    """
    Parses command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Favhash - A utility to calculate favicon hashes for OSINT.",
        epilog="Usage Example: python main.py -u http://testphp.vulnweb.com"
    )
    
    # Mutually exclusive group for file or URL
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f", "--file", 
        help="Path to a local favicon file"
    )
    group.add_argument(
        "-u", "--url", 
        help="URL to fetch favicon from (defaults to http:// if no scheme)"
    )
    
    # Optional arguments
    parser.add_argument(
        "-s", "--save", 
        help="Optional: Path to save the downloaded favicon"
    )
    parser.add_argument(
        "-a", "--alg", 
        choices=['sha256', 'sha1', 'md5'], 
        default='sha256', 
        help="Hash algorithm to use (default: sha256)"
    )
    
    # Color control
    parser.add_argument(
        "--no-color", 
        action="store_true", 
        help="Disable all color output"
    )
    parser.add_argument(
        "--plain", 
        action="store_true", 
        help="Alias for --no-color"
    )
    
    return parser.parse_args()


def get_favicon_from_file(path):
    """
    Reads favicon bytes from a local file.
    """
    c_print(f"[*] Loaded favicon from {path}", "blue")
    try:
        with open(path, 'rb') as f:
            return f.read()
    except (IOError, FileNotFoundError) as e:
        c_print(f"[!] Error reading file: {e}", "red", file=sys.stderr)
        return None


def get_favicon_from_url(url_input):
    """
    Fetches favicon bytes from a URL, trying common locations.
    """
    c_print(f"[*] Fetching favicon from {url_input}...", "blue")
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Favhash-CLI-Tool/1.0'
    })
    
    # Normalize URL
    try:
        parsed_url = urlparse(url_input)
        if not parsed_url.scheme:
            parsed_url = urlparse(f"http://{url_input}")
    except Exception as e:
        c_print(f"[!] Invalid URL provided: {e}", "red", file=sys.stderr)
        return None

    # Create candidate list
    base_url_tuple = (parsed_url.scheme, parsed_url.netloc, '', '', '', '')
    
    candidates = []
    
    # 1. Try direct URL first if it has a path (e.g., /icon.png)
    if parsed_url.path and parsed_url.path != '/':
        candidates.append(urlunparse(parsed_url))
    
    # 2. Add common fallbacks
    candidates.append(urlunparse((parsed_url.scheme, parsed_url.netloc, 'favicon.ico', '', '', '')))
    candidates.append(urlunparse((parsed_url.scheme, parsed_url.netloc, 'favicon.png', '', '', '')))
    candidates.append(urlunparse((parsed_url.scheme, parsed_url.netloc, 'apple-touch-icon.png', '', '', '')))
    
    # De-duplicate while preserving order
    seen = set()
    unique_candidates = [x for x in candidates if not (x in seen or seen.add(x))]

    for url in unique_candidates:
        try:
            response = session.get(url, timeout=10, allow_redirects=True)
            
            if response.status_code == 200:
                # Check if response is clearly HTML
                ctype = response.headers.get('content-type', '').lower()
                if 'text/html' in ctype:
                    continue  # Skip this candidate, it's HTML
                
                # Check for empty response
                if not response.content:
                    continue

                # Found it!
                return response.content
                
        except requests.exceptions.RequestException:
            # Silently continue to the next candidate on network errors
            continue
            
    return None  # Failed to find favicon


def save_favicon(path, data_bytes):
    """
    Saves the favicon bytes to disk.
    """
    try:
        with open(path, 'wb') as f:
            f.write(data_bytes)
        # Silently succeed as requested
    except IOError as e:
        # Print a warning but do not exit
        c_print(f"[!] Warning: Failed to save favicon to {path}: {e}", "yellow", file=sys.stderr)


def calculate_hashes(data_bytes, alg_name):
    """
    Calculates MD5, the selected algorithm, and Shodan-style MMH3.
    """
    # 1. MD5
    md5 = hashlib.md5(data_bytes).hexdigest()
    
    # 2. Selected Algorithm (sha256, sha1, md5)
    other_hash_obj = hashlib.new(alg_name)
    other_hash_obj.update(data_bytes)
    alg_hash = other_hash_obj.hexdigest()
    
    # 3. Shodan MMH3
    # *** THIS IS THE FIX ***
    # Use codecs.encode(..., 'base64') which mimics the legacy
    # standard of including newlines in the b64 output. This is
    # what Shodan and other tools expect.
    b64_bytes = codecs.encode(data_bytes, 'base64')
    mmh3_hash = mmh3.hash(b64_bytes) # Returns signed 32-bit int
    
    return {
        'md5': md5,
        'mmh3': mmh3_hash,
        'alg_name': alg_name,
        'alg_hash': alg_hash
    }


def print_output(hashes):
    """
    Prints the final hash output in the required format.
    """
    md5 = hashes['md5']
    mmh3_val = str(hashes['mmh3'])
    alg_name = hashes['alg_name'].upper()
    alg_hash = hashes['alg_hash']

    # 1. Standard Hashes
    c_print(f"{alg_name:<4}: ", "cyan", end="")
    c_print(alg_hash, "green")
    
    c_print(f"MD5 : ", "cyan", end="")
    c_print(md5, "green")
    
    c_print(f"MMH3: ", "cyan", end="")
    c_print(mmh3_val, "green")
    
    print()  # Spacer

    # 2. OSINT Box
    # Define query strings
    shodan_str = f"http.favicon.hash:{mmh3_val}"
    fofa_md5_str = f'icon_md5="{md5}"'
    fofa_hash_str = f'icon_hash="{mmh3_val}"'
    zoomeye_str = f'iconhash:"{md5}"'
    censys_str = f"services.http.response.favicon.md5:{md5}"

    # Print box, following the prompt's visual layout exactly
    
    # Top border
    c_print("    ", end=""); c_print("┌", "yellow", end=""); c_print("─" * 2, "yellow", end="");
    c_print(" OSINT Correlation ", "white", attrs=['bold'], end="");
    c_print("─" * 38, "yellow", end=""); # 61 total width
    c_print("┐\n", "yellow")

    # Shodan
    c_print("    ", end=""); c_print("│ ", "yellow", end="");
    c_print("Shodan     : ", "red", attrs=['bold'], end=""); 
    c_print(shodan_str, "green")
    
    # FOFA MD5
    c_print("    ", end=""); c_print("│ ", "yellow", end="");
    c_print("FOFA MD5   : ", "red", attrs=['bold'], end=""); 
    c_print(fofa_md5_str, "green")

    # FOFA Hash
    c_print("    ", end=""); c_print("│ ", "yellow", end="");
    c_print("FOFA Hash  : ", "red", attrs=['bold'], end=""); 
    c_print(fofa_hash_str, "green")

    # Zoomeye
    c_print("    ", end=""); c_print("│ ", "yellow", end="");
    c_print("Zoomeye    : ", "red", attrs=['bold'], end=""); 
    c_print(zoomeye_str, "green")
    
    # Censys MD5 (this line is intentionally longer)
    c_print("    ", end=""); c_print("│ ", "yellow", end="");
    c_print("Censys MD5 : ", "red", attrs=['bold'], end=""); 
    c_print(censys_str, "green")

    # Bottom border
    c_print("    ", end=""); c_print("└", "yellow", end="");
    c_print("─" * 59, "yellow", end=""); # 61 total width
    c_print("┘\n", "yellow")


def main():
    """
    Main execution flow.
    """
    global COLOR_ENABLED
    args = parse_args()

    # 1. Configure Color
    # Disable if TTY is not detected or if flags are set
    COLOR_ENABLED = (sys.stdout.isatty() and not args.no_color and not args.plain)
    # strip=True removes color codes if disabled, autoreset=True stops color bleed
    colorama.init(autoreset=True, strip=(not COLOR_ENABLED))

    # 2. Print Banner
    print_banner()

    favicon_bytes = None
    try:
        # 3. Get Favicon Data
        if args.url:
            favicon_bytes = get_favicon_from_url(args.url)
        elif args.file:
            favicon_bytes = get_favicon_from_file(args.file)

        # 4. Check for Failure
        if not favicon_bytes:
            c_print("[!] Failed to retrieve or read favicon.", "red", file=sys.stderr)
            sys.exit(1)
        
        # 5. Save if requested
        if args.save and args.url:
            save_favicon(args.save, favicon_bytes)

        # 6. Calculate and Print Hashes
        hashes = calculate_hashes(favicon_bytes, args.alg)
        print_output(hashes)
    
    except KeyboardInterrupt:
        c_print("\n[!] User aborted operation.", "yellow", file=sys.stderr)
        sys.exit(130)  # Standard exit code for Ctrl+C
    except Exception as e:
        c_print(f"\n[!] An unexpected error occurred: {e}", "red", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
