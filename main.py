import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List

import requests

import automation

class SubdomainScanner:
    def __init__(self, domain, wordlist_file="subdomains.txt", threads=50):
        self.domain = domain
        self.wordlist_file = wordlist_file
        self.threads = threads
        self.found_subdomains = []
        
    def load_wordlist(self):
        """Load subdomain wordlist from file"""
        try:
            with open(self.wordlist_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Default wordlist if file not found
            return ['hacked']
    
    def check_subdomain(self, subdomain):
        """Check if subdomain exists"""
        url = f"http://{subdomain}.{self.domain}"
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                print(f"[+] Found: {subdomain}.{self.domain}")
                self.found_subdomains.append(f"{subdomain}.{self.domain}")
        except requests.exceptions.RequestException:
            pass
    
    def scan(self):
        """Main scanning function"""
        print(f"Starting subdomain enumeration for {self.domain}")
        print(f"Using {self.threads} threads")
        print("-" * 50)
        
        wordlist = self.load_wordlist()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_subdomain, wordlist)
        
        print("-" * 50)
        print(f"Scan completed. Found {len(self.found_subdomains)} subdomains:")
        for subdomain in self.found_subdomains:
            print(f"  {subdomain}")

def add_scan_subparser(subparsers: argparse._SubParsersAction) -> None:
    scan_parser = subparsers.add_parser("scan", help="Run subdomain enumeration")
    scan_parser.add_argument("domain", help="Target domain to scan")
    scan_parser.add_argument(
        "-w",
        "--wordlist",
        default="subdomains.txt",
        help="Wordlist file (default: subdomains.txt)",
    )
    scan_parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=50,
        help="Number of threads (default: 50)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Subdomain enumeration and automation toolkit"
    )
    subparsers = parser.add_subparsers(dest="command")
    add_scan_subparser(subparsers)
    automation.add_subcommands(subparsers)
    return parser


def run_scan(args: argparse.Namespace) -> None:
    scanner = SubdomainScanner(args.domain, args.wordlist, args.threads)
    scanner.scan()


def parse_legacy_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Basic Subdomain Scanner")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument(
        "-w",
        "--wordlist",
        default="subdomains.txt",
        help="Wordlist file (default: subdomains.txt)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=50,
        help="Number of threads (default: 50)",
    )
    return parser.parse_args(argv)


def main() -> None:
    parser = build_parser()
    if len(sys.argv) > 1:
        args = parser.parse_args()
        if args.command == "scan":
            run_scan(args)
            return
        if args.command:
            automation.handle_command(args)
            return

    legacy_args = parse_legacy_args(sys.argv[1:])
    run_scan(legacy_args)

if __name__ == "__main__":
    main()
