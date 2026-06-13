# Recon Toolkit

A collection of Python scripts I built for the reconnaissance phase of web application pentests. Nothing fancy — just tools that speed up the early stages of an assessment.

## Tools

### port_scanner.py
Multi-threaded TCP port scanner with banner grabbing. Scans a host and grabs service banners from open ports.

```bash
python port_scanner.py scanme.nmap.org
python port_scanner.py 192.168.1.1 1 65535
```

### dns_enum.py
Subdomain brute-forcer using a wordlist. Useful for finding hidden subdomains during recon.

```bash
python dns_enum.py example.com
python dns_enum.py example.com wordlist.txt
```

### header_check.py
Checks HTTP security headers on a target web application. Flags missing headers and info disclosure issues. Outputs a simple score/grade.

```bash
python header_check.py https://example.com
```

Checks for:
- Content-Security-Policy
- X-Frame-Options (clickjacking)
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- Referrer-Policy
- Cookie flags (Secure, HttpOnly, SameSite)

## Requirements

```
pip install requests urllib3
```

## Disclaimer

For educational purposes and authorized security testing only. Don't run these on systems you don't have permission to test.

## Context

Built these during my VAPT internship at Prasunet and refined them for personal use. The header checker especially comes in handy during web app assessments — saves time compared to checking manually in Burp.
