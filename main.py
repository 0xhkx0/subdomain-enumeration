import requests
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse

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

def main():
    parser = argparse.ArgumentParser(description="Basic Subdomain Scanner")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-w", "--wordlist", default="subdomains.txt", 
                       help="Wordlist file (default: subdomains.txt)")
    parser.add_argument("-t", "--threads", type=int, default=50,
                       help="Number of threads (default: 50)")
    
    args = parser.parse_args()
    
    scanner = SubdomainScanner(args.domain, args.wordlist, args.threads)
    scanner.scan()

if __name__ == "__main__":
    main()