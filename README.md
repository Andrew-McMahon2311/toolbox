sub-domain-recon.py tags

-d, --domain
-w, --wordlist
-o, --output
-c, --concurrency

python sub-domain-recon.py -d example.com -w wordlist.txt -c 100 -o results.json

header-config-auditor.py:

-u, --url: Target URL to audit  
--json: Export audit results to a JSON file  
--timeout: HTTP request timeout in seconds (default: 8.0)

python header-config-auditor.py -u [https://example.com](https://example.com) --json audit_report.json


Auto Nmap Scanner:

CLI wrapper for configuring Nmap target scans, selecting execution timing templates, and performing service version detection.

python nmap_scanner.py
