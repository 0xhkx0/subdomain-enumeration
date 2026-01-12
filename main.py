import argparse
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List

import requests

import automation

DEFAULT_WORDLIST = [
    "admin",
    "api",
    "app",
    "assets",
    "auth",
    "beta",
    "blog",
    "cdn",
    "dashboard",
    "dev",
    "docs",
    "files",
    "ftp",
    "git",
    "help",
    "internal",
    "login",
    "mail",
    "mta",
    "mx",
    "ns1",
    "ns2",
    "portal",
    "public",
    "secure",
    "shop",
    "smtp",
    "staging",
    "static",
    "status",
    "support",
    "test",
    "vpn",
    "web",
    "www",
]

DEFAULT_PASSIVE_SOURCES = (
    "crtsh",
    "bufferover",
    "hackertarget",
)

class SubdomainScanner:
    def __init__(
        self,
        domain,
        wordlist_file="subdomains.txt",
        threads=50,
        passive=True,
        passive_sources=None,
    ):
        self.domain = domain
        self.wordlist_file = wordlist_file
        self.threads = threads
        self.passive = passive
        self.passive_sources = passive_sources or DEFAULT_PASSIVE_SOURCES
        self.found_subdomains = set()
        self._lock = threading.Lock()
        
    def load_wordlist(self):
        """Load subdomain wordlist from file"""
        try:
            with open(self.wordlist_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Default wordlist if file not found
            return DEFAULT_WORDLIST.copy()
    
    def _fetch_json(self, url):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError):
            return None

    def _fetch_text(self, url):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.text
        except requests.RequestException:
            return None

    def fetch_passive_subdomains(self):
        """Fetch subdomains from passive sources."""
        if not self.passive:
            return []
        subdomains = set()
        if "crtsh" in self.passive_sources:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            entries = self._fetch_json(url)
            if entries:
                for entry in entries:
                    name_value = entry.get("name_value")
                    if not name_value:
                        continue
                    subdomains.update(name_value.splitlines())
        if "bufferover" in self.passive_sources:
            url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
            data = self._fetch_json(url)
            if data:
                for record_type in ("FDNS_A", "RDNS"):
                    for record in data.get(record_type, []):
                        parts = record.split(",", 1)
                        if len(parts) == 2:
                            subdomains.add(parts[1])
        if "hackertarget" in self.passive_sources:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            text = self._fetch_text(url)
            if text and "error check your search parameter" not in text.lower():
                for line in text.splitlines():
                    host = line.split(",", 1)[0].strip()
                    if host:
                        subdomains.add(host)
        return list(subdomains)

    def _normalize_subdomain(self, subdomain):
        cleaned = subdomain.strip().lower().lstrip("*.") if subdomain else ""
        if not cleaned:
            return None
        if cleaned == self.domain:
            return None
        if cleaned.endswith(f".{self.domain}"):
            return cleaned
        return f"{cleaned}.{self.domain}"

    def _resolve_subdomain(self, fqdn):
        try:
            socket.getaddrinfo(fqdn, None)
            return True
        except socket.gaierror:
            return False

    def check_subdomain(self, subdomain):
        """Check if subdomain exists"""
        fqdn = self._normalize_subdomain(subdomain)
        if not fqdn:
            return

        found = self._resolve_subdomain(fqdn)
        for scheme in ("https", "http"):
            url = f"{scheme}://{fqdn}"
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                if response.status_code >= 200:
                    found = True
                    break
            except requests.exceptions.RequestException:
                continue

        if found:
            with self._lock:
                if fqdn not in self.found_subdomains:
                    print(f"[+] Found: {fqdn}")
                    self.found_subdomains.add(fqdn)
    
    def scan(self):
        """Main scanning function"""
        print(f"Starting subdomain enumeration for {self.domain}")
        print(f"Using {self.threads} threads")
        print("-" * 50)
        
        wordlist = self.load_wordlist()
        passive_subdomains = self.fetch_passive_subdomains()
        candidates = set(wordlist) | set(passive_subdomains)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_subdomain, candidates)
        
        print("-" * 50)
        print(f"Scan completed. Found {len(self.found_subdomains)} subdomains:")
        for subdomain in sorted(self.found_subdomains):
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
    passive_group = scan_parser.add_mutually_exclusive_group()
    passive_group.add_argument(
        "--passive",
        dest="passive",
        action="store_true",
        help="Enable passive enumeration (default)",
    )
    passive_group.add_argument(
        "--no-passive",
        dest="passive",
        action="store_false",
        help="Disable passive enumeration",
    )
    scan_parser.set_defaults(passive=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Subdomain enumeration and automation toolkit"
    )
    subparsers = parser.add_subparsers(dest="command")
    add_scan_subparser(subparsers)
    automation.add_subcommands(subparsers)
    return parser


def run_scan(args: argparse.Namespace) -> None:
    scanner = SubdomainScanner(args.domain, args.wordlist, args.threads, args.passive)
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
    passive_group = parser.add_mutually_exclusive_group()
    passive_group.add_argument(
        "--passive",
        dest="passive",
        action="store_true",
        help="Enable passive enumeration (default)",
    )
    passive_group.add_argument(
        "--no-passive",
        dest="passive",
        action="store_false",
        help="Disable passive enumeration",
    )
    parser.set_defaults(passive=True)
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
