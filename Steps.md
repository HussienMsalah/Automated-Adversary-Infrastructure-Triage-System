# Automated Adversary Infrastructure Triage System
 
## 1. Update system & install OS-level dependencies
```python
	sudo apt update && sudo apt install -y python3-pip python3-venv build-essential libfuzzy-dev
```

## 2. Create project directory and virtual environment
```python
	mkdir -p cti-triage-system
	cd cti-triage-system
	python3 -m venv venv
	source venv/bin/activate
```
## 3. Install required Python packages
```python
	pip install certstream dnspython requests playwright
```
## 4. Install Playwright browser binaries and system dependencies
```python
	playwright install chromium
	playwright install-deps chromium
```


## 5. Script v.1


```python
import os
import re
import datetime
import requests
import dns.resolver
from playwright.sync_api import sync_playwright

# Targeted Keywords to avoid DB Heavy Joins on crt.sh
TARGET_KEYWORDS = [
    "paypal", "binance", "metamask", "coinbase",
    "login-secure", "verify-account", "bank-online", "update-auth"
]
OUTPUT_DIR = "triage_results"

os.makedirs(OUTPUT_DIR, exist_ok=True)
seen_domains = set()

def resolve_dns(domain):
    """Resolves IP addresses (A records) and Mail servers (MX records)."""
    results = {"ips": [], "mx": []}
    
    try:
        answers = dns.resolver.resolve(domain, 'A')
        results["ips"] = [r.to_text() for r in answers]
    except Exception:
        pass
        
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        results["mx"] = [r.to_text() for r in mx_answers]
    except Exception:
        pass
        
    return results

def run_triage(domain):
    """Executes headless browser to capture screenshots and logs DNS findings."""
    dns_info = resolve_dns(domain)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain_name = re.sub(r'[^a-zA-Z0-9_]', '_', domain)
    
    screenshot_path = os.path.join(OUTPUT_DIR, f"{safe_domain_name}_{timestamp}.png")
    
    print(f"\n[!] [TRIAGE STARTED] Domain: {domain}")
    print(f"    [+] Resolved IPs: {dns_info['ips']}")
    print(f"    [+] MX Records: {dns_info['mx']}")
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"]
            )
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            
            target_url = f"http://{domain}"
            page.goto(target_url, timeout=10000, wait_until="networkidle")
            
            page.screenshot(path=screenshot_path)
            print(f"    [+] Screenshot saved: {screenshot_path}")
            browser.close()
    except Exception as err:
        print(f"    [-] Triage failed for {domain}: {err}")

def fetch_certificates(keyword):
    """Fetches recent certificates containing target patterns from crt.sh."""
    url = f"https://crt.sh/?q={keyword}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    matches_found = 0
    
    try:
        response = requests.get(url, headers=headers, timeout=12)
        if response.status_code == 200:
            data = response.json()
            
            # Process up to 15 recent unique certificates
            for entry in data[:15]:
                name_value = entry.get("name_value", "")
                domains = name_value.split("\n")
                
                for domain in domains:
                    clean_domain = domain.lower().replace('*.', '').strip()
                    
                    if clean_domain and clean_domain not in seen_domains:
                        seen_domains.add(clean_domain)
                        matches_found += 1
                        print(f"\n[+] [MATCH FOUND] Query '{keyword}' -> Domain: {clean_domain}")
                        run_triage(clean_domain)
                        
    except Exception as e:
        print(f"[-] Request error for keyword '{keyword}': {e}")
        
    return matches_found

if __name__ == "__main__":
    start_time = datetime.datetime.now()
    print("=" * 65)
    print(f"[*] Starting Daily CT Infrastructure Triage Run - {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Target Keywords/Patterns: {TARGET_KEYWORDS}")
    print("=" * 65 + "\n")
    
    total_processed = 0
    for kw in TARGET_KEYWORDS:
        print(f"[*] Querying CT logs for pattern: '{kw}'...")
        count = fetch_certificates(kw)
        total_processed += count
        
    end_time = datetime.datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "=" * 65)
    print(f"[+] Daily Run Completed Successfully!")
    print(f"[+] Total Suspicious Domains Triaged: {total_processed}")
    print(f"[+] Total Duration: {duration:.2f} seconds")
    print(f"[+] Screenshots stored in: ./{OUTPUT_DIR}/")
    print("=" * 65)
```
## Excuting the code
 ```python
 	python3 app.py
 ```
