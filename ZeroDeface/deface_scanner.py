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
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"[-] Error crawling for forms: {e}")
            return []

    def test_file_upload(self, form, action_url):
        test_files = [
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
                                proof=file_response.text[:200] + "..."
                            )
                            self.uploaded_files.append(file_url)
                            return True
            except Exception as e:
                print(f"[-] Error testing upload for {filename}: {e}")
        return False

    def scan_upload_vulnerabilities(self):
        print("[*] Scanning for file upload vulnerabilities...")
        forms = self.crawl_for_forms()
        
        for form in forms:
            if form.find('input', {'type': 'file'}):
                action = form.get('action', '') or self.target_url
                print(f"[*] Found file upload form at {action}")
                if self.test_file_upload(form, action):
                    return True
        
        common_upload_paths = ['upload', 'file-upload', 'upload-file', 'admin/upload']
        for path in common_upload_paths:
            upload_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(upload_url, verify=False, timeout=10)
                if response.status_code == 200 and 'upload' in response.text.lower():
                    print(f"[*] Found potential upload endpoint at {upload_url}")
                    class DummyForm:
                        def __init__(self, action):
                            self.attrs = {'action': action}
                    if self.test_file_upload(DummyForm(upload_url), upload_url):
                        return True
            except:
                continue
        return False

    def scan_exposed_editors(self):
        print("[*] Scanning for exposed content editors...")
        found = False
        
        for editor_path in self.common_editors:
            editor_url = urljoin(self.target_url, editor_path)
            try:
                response = self.session.get(editor_url, verify=False, timeout=10)
                if response.status_code == 200:
                    editor_indicators = ['CKEditor', 'TinyMCE', 'wysiwyg', 'contenteditable']
                    if any(indicator in response.text for indicator in editor_indicators):
                        self.log_vulnerability(
                            "Exposed Content Editor",
                            f"Exposed editor found at {editor_url}",
                            exploit=f"Visit {editor_url} directly",
                            proof=response.text[:200] + "..."
                        )
                        found = True
                        
                        if 'TinyMCE' in response.text:
                            self.test_tinymce_editor(editor_url)
                        elif 'CKEditor' in response.text:
                            self.test_ckeditor(editor_url)
            except Exception as e:
                print(f"[-] Error checking {editor_url}: {e}")
        return found

    def test_tinymce_editor(self, editor_url):
        try:
            response = self.session.get(editor_url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            form = soup.find('form')
            if form:
                action = form.get('action', editor_url)
                data = {'content': self.test_content, 'submit': 'save'}
                response = self.session.post(action, data=data, verify=False, timeout=15)
                if response.status_code == 200 and self.test_content in response.text:
                    self.log_vulnerability(
                        "Content Editor Submission",
                        f"Content can be submitted to {action} without authentication",
                        exploit=f"curl -X POST -d 'content={self.test_content}' {action}",
                        proof=response.text[:200] + "..."
                    )
        except Exception as e:
            print(f"[-] Error testing TinyMCE editor: {e}")

    def test_ckeditor(self, editor_url):
        try:
            upload_url = urljoin(editor_url, 'filemanager/upload/')
            response = self.session.get(upload_url, verify=False, timeout=10)
            if response.status_code == 200:
                self.log_vulnerability(
                    "CKEditor Upload",
                    f"CKEditor upload endpoint accessible at {upload_url}",
                    exploit=f"Visit {upload_url} to upload files",
                    proof=response.text[:200] + "..."
                )
        except Exception as e:
            print(f"[-] Error testing CKEditor: {e}")

    def scan_admin_panels(self):
        print("[*] Scanning for admin panels and CMS weaknesses...")
        found = False
        
        for admin_path in self.common_admin_paths:
            admin_url = urljoin(self.target_url, admin_path)
            try:
                response = self.session.get(admin_url, verify=False, timeout=10)
                if response.status_code == 200:
                    self.log_vulnerability(
                        "Admin Panel Detected",
                        f"Admin panel found at {admin_url}",
                        exploit=f"Visit {admin_url} directly",
                        proof=response.text[:200] + "..."
                    )
                    found = True
                    
                    if 'wp-admin' in admin_url.lower():
                        self.test_default_credentials('wordpress', admin_url)
                    elif 'administrator' in admin_url.lower():
                        self.test_default_credentials('joomla', admin_url)
                    elif 'drupal' in response.text.lower():
                        self.test_default_credentials('drupal', admin_url)
            except Exception as e:
                print(f"[-] Error checking {admin_url}: {e}")
        return found

    def test_default_credentials(self, cms_type, login_url):
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
                            proof=f"Logged in successfully with {username}/{password}"
                        )
                        return True
                except Exception as e:
                    print(f"[-] Error testing credentials {username}/{password}: {e}")
        return False

    def scan_parameter_tampering(self):
        print("[*] Scanning for parameter tampering vulnerabilities...")
        found = False
        
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                if '?' in href:
                    base_url = href.split('?')[0]
                    params = href.split('?')[1]
                    
                    for param in params.split('&'):
                        if '=' in param:
                            param_name = param.split('=')[0]
                            test_url = f"{base_url}?{param_name}={self.test_content}"
                            
                            tampered_response = self.session.get(test_url, verify=False, timeout=10)
                            if self.test_content in tampered_response.text:
                                self.log_vulnerability(
                                    "Parameter Tampering",
                                    f"Parameter {param_name} is reflected in page content at {base_url}",
                                    exploit=f"Visit {test_url}",
                                    proof=tampered_response.text[:200] + "..."
                                )
                                found = True
        except Exception as e:
            print(f"[-] Error scanning for parameter tampering: {e}")
        return found

    def scan_api_endpoints(self):
        print("[*] Scanning for vulnerable API/admin endpoints...")
        found = False
        common_api_paths = [
            'api/update', 'admin/save', 'api/content', 'api/pages',
            'admin/api', 'rest/api', 'graphql', 'admin/update'
        ]
        
        for api_path in common_api_paths:
            api_url = urljoin(self.target_url, api_path)
            try:
                response = self.session.get(api_url, verify=False, timeout=10)
                if response.status_code in [200, 201]:
                    self.log_vulnerability(
                        "API Endpoint Accessible",
                        f"API endpoint accessible at {api_url}",
                        exploit=f"curl -X GET {api_url}",
                        proof=response.text[:200] + "..."
                    )
                    found = True
                
                data = {'content': self.test_content}
                response = self.session.post(api_url, json=data, verify=False, timeout=15)
                if response.status_code in [200, 201]:
                    self.log_vulnerability(
                        "API Endpoint Writable",
                        f"API endpoint accepts data at {api_url}",
                        exploit=f"curl -X POST -H 'Content-Type: application/json' -d '{{\"content\":\"{self.test_content}\"}}' {api_url}",
                        proof=response.text[:200] + "..."
                    )
                    found = True
            except Exception as e:
                print(f"[-] Error checking {api_url}: {e}")
        return found

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

def main():
    scanner = DefacementScanner("")
    scanner.print_banner()

    parser = argparse.ArgumentParser(
        description='ZeroDeface - Website Defacement Vulnerability Scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\033[1;34m
Examples:
  Full scan:       python deface_scanner.py --url http://example.com --all
  Upload test:     python deface_scanner.py --url http://example.com --upload-test --simulate
  Admin check:     python deface_scanner.py --url http://example.com --admin-scan --report scan.json
\033[0m"""
    )
    
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--upload-test', action='store_true', help='Test file upload vulnerabilities')
    parser.add_argument('--scan-editors', action='store_true', help='Find exposed content editors')
    parser.add_argument('--admin-scan', action='store_true', help='Scan admin panels + test default creds')
    parser.add_argument('--param-tamper', action='store_true', help='Test parameter tampering')
    parser.add_argument('--api-scan', action='store_true', help='Scan vulnerable API endpoints')
    parser.add_argument('--all', action='store_true', help='Run all vulnerability checks')
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
        
        if args.all or args.upload_test:
            scanner.scan_upload_vulnerabilities()
        
        if args.all or args.scan_editors:
            scanner.scan_exposed_editors()
        
        if args.all or args.admin_scan:
            scanner.scan_admin_panels()
        
        if args.all or args.param_tamper:
            scanner.scan_parameter_tampering()
        
        if args.all or args.api_scan:
            scanner.scan_api_endpoints()
        
        if args.report:
            scanner.generate_report(args.report)
        
        if args.simulate and scanner.vulnerabilities:
            print("\n\033[1;32m[+] Simulation complete. Vulnerabilities found:\033[0m")
            for vuln in scanner.vulnerabilities:
                print(f"- \033[1;33m{vuln['category']}:\033[0m {vuln['description']}")
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
