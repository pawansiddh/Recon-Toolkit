import requests
import sys
import json

# checks http security headers on a target
# super useful during web app pentests to find misconfigs quickly
# ref: https://owasp.org/www-project-secure-headers/

# headers that should be present
REQUIRED_HEADERS = {
    "Content-Security-Policy": "Prevents XSS by restricting resource loading",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Strict-Transport-Security": "Forces HTTPS (HSTS)",
    "Referrer-Policy": "Controls referrer info leakage",
    "Permissions-Policy": "Controls browser features/APIs",
    "X-XSS-Protection": "Legacy XSS filter (mostly deprecated but still checked)",
}

# headers that sometimes leak info
INFO_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-Generator", "X-Drupal-Cache", "Via"
]

def check_headers(url):
    if not url.startswith("http"):
        url = "https://" + url

    print(f"\n[*] Checking security headers for: {url}\n")

    try:
        resp = requests.get(url, timeout=8, allow_redirects=True, verify=False)
    except requests.exceptions.ConnectionError:
        print(f"[-] Could not connect to {url}")
        return
    except Exception as e:
        print(f"[-] Error: {e}")
        return

    headers = resp.headers
    score = 0
    total = len(REQUIRED_HEADERS)

    print(f"  Status Code : {resp.status_code}")
    print(f"  Final URL   : {resp.url}\n")

    print("─" * 60)
    print("  SECURITY HEADERS CHECK")
    print("─" * 60)

    missing = []
    for header, desc in REQUIRED_HEADERS.items():
        if header in headers:
            print(f"  [✓] {header}")
            print(f"      Value: {headers[header][:80]}")
            score += 1
        else:
            print(f"  [✗] MISSING: {header}")
            print(f"      Why it matters: {desc}")
            missing.append(header)
        print()

    print("─" * 60)
    print("  INFO DISCLOSURE CHECK")
    print("─" * 60)

    for h in INFO_HEADERS:
        if h in headers:
            print(f"  [!] {h}: {headers[h]}  <-- may reveal server info")
    print()

    print("─" * 60)
    rating = score / total * 100
    grade = "A" if rating >= 90 else "B" if rating >= 75 else "C" if rating >= 50 else "F"
    print(f"  Score : {score}/{total}  ({rating:.0f}%)  Grade: {grade}")
    if missing:
        print(f"  Missing headers: {', '.join(missing)}")
    print("─" * 60)
    print()

def check_cookie_flags(url):
    if not url.startswith("http"):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=8, verify=False)
    except:
        return

    cookies = resp.cookies
    if not cookies:
        print("[*] No cookies set by server\n")
        return

    print("\n[*] Cookie Security Flags\n")
    for c in cookies:
        print(f"  Cookie: {c.name}")
        print(f"    Secure   : {'YES' if c.secure else 'NO -- can be sent over HTTP'}")
        print(f"    HttpOnly : {'YES' if c.has_nonstandard_attr('HttpOnly') else 'NO -- accessible via JS (XSS risk)'}")
        print(f"    SameSite : {c.get_nonstandard_attr('SameSite', 'NOT SET -- CSRF risk')}")
        print()


if __name__ == "__main__":
    # suppress ssl warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if len(sys.argv) < 2:
        print("Usage: python header_check.py <url>")
        print("Example: python header_check.py https://example.com")
        sys.exit(0)

    url = sys.argv[1]
    check_headers(url)
    check_cookie_flags(url)
