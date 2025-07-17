Basic Usage:
bash
python3 deface_scanner.py --url TARGET_URL [OPTIONS]
Core Commands:
Full Website Scan
Scans for all vulnerabilities (admin panels, upload vulns, common files)

bash
python3 deface_scanner.py --url https://example.com --all
Admin Panel Finder
Scans for admin/login pages

bash
python3 deface_scanner.py --url https://example.com --admin
Upload Vulnerability Scanner
Tests file upload weaknesses

bash
python3 deface_scanner.py --url https://example.com --upload
Default Credentials Checker
Tests common credentials on found login pages

bash
python3 deface_scanner.py --url https://example.com --brute
Mirror Attack
Attempts mirror defacement technique

bash
python3 deface_scanner.py --url https://example.com --mirror
Advanced Options:
Option	Description	Example
--crawl	Enable website crawling	--crawl --max-pages 50
--deface	Attempt actual defacement if vulns found	--upload --deface
--simulate	Safe mode (no real changes)	--mirror --simulate
--threads NUM	Set number of threads (default: 5)	--threads 10
--timeout SEC	Request timeout in seconds (default: 15)	--timeout 20
--report FILE	Save results to JSON file	--report scan_results.json
--verbose	Show detailed output	--admin --verbose
--quiet	Show only critical findings	--upload --quiet
Interactive Mode:
Launch menu-driven interface:

bash
python3 deface_scanner.py --url https://example.com --interactive
Example Combos:
Comprehensive Test

bash
python3 deface_scanner.py --url https://example.com --all --crawl --threads 10 --timeout 20 --verbose
Stealthy Scan

bash
python3 deface_scanner.py --url https://example.com --admin --brute --quiet --threads 3
Exploitation Test

bash
python3 deface_scanner.py --url https://example.com --upload --deface --report deface_results.json
Key Features:
CMS Detection (WordPress/Joomla/Drupal)

1500+ admin path checks

50+ file upload bypass techniques

Mirror attack cloning

Default credential database

Real-time vulnerability logging

Pro Tips:
For legal testing, always use --simulate first

Combine --admin --brute for credential testing

Use --threads carefully to avoid detection

--crawl helps find hidden endpoints

--report generates actionable JSON output
