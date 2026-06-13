import socket
import sys
import os

# subdomain brute forcer / dns enum script
# useful during recon to find hidden subdomains

# basic wordlist - you can replace with a bigger one like subdomains-top1million
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "vpn", "remote", "portal", "shop", "blog", "forum", "beta",
    "m", "mobile", "static", "cdn", "cloud", "secure", "login",
    "app", "apps", "dashboard", "internal", "intranet", "git",
    "jenkins", "jira", "confluence", "gitlab", "backup", "db",
    "database", "mysql", "redis", "smtp", "pop", "imap", "ns1",
    "ns2", "mx", "webmail", "cpanel", "whm", "ssh", "sftp",
    "old", "new", "v2", "legacy", "prod", "production", "uat"
]

found = []

def resolve(subdomain, domain):
    full = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(full)
        return ip
    except:
        return None

def enum_subdomains(domain, wordlist=None):
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST

    print(f"\n[*] Starting subdomain enum on: {domain}")
    print(f"[*] Wordlist size: {len(wordlist)} entries\n")

    for word in wordlist:
        ip = resolve(word, domain)
        if ip:
            print(f"[+] Found: {word}.{domain}  ->  {ip}")
            found.append((f"{word}.{domain}", ip))

    print(f"\n[*] Done. {len(found)} subdomains found.\n")
    return found

def load_wordlist(filepath):
    if not os.path.exists(filepath):
        print(f"[-] Wordlist not found: {filepath}")
        sys.exit(1)
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip()]

def get_dns_records(domain):
    # basic A record lookup
    print(f"\n[*] DNS records for {domain}")
    try:
        results = socket.getaddrinfo(domain, None)
        ips = set(r[4][0] for r in results)
        for ip in ips:
            print(f"    A  ->  {ip}")
    except Exception as e:
        print(f"    [-] Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dns_enum.py <domain> [wordlist.txt]")
        print("Example: python dns_enum.py example.com wordlist.txt")
        sys.exit(0)

    domain = sys.argv[1]
    wordlist = None

    if len(sys.argv) > 2:
        wordlist = load_wordlist(sys.argv[2])

    get_dns_records(domain)
    enum_subdomains(domain, wordlist)
