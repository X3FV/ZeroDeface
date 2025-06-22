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

# Suppress SSL warnings
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
        
        # Enhanced test content
        self.test_content = "ZERODEFACE_TEST_" + str(random.randint(1000,9999))
        
        # Common vulnerability paths
        self.common_editors = [
            'editor', 'ckeditor', 'tinymce', 'fckeditor', 
            'admin/editor', 'content/edit', 'edit/content'
        ]
        self.common_admin_paths = [
            'admin', 'wp-admin', 'administrator', 'dashboard',
            'manager', 'backend', 'adminpanel'
        ]
        self.common_upload_paths = [
            'upload', 'file-upload', 'upload-file', 
            'admin/upload', 'assets/upload'
        ]
        
        # More comprehensive default credentials
        self.default_credentials = {
            'wordpress': [('admin', 'admin'), ('admin', 'password'), ('editor', 'editor')],
            'joomla': [('admin', 'admin'), ('admin', 'password'), ('manager', 'manager')],
            'drupal': [('admin', 'admin'), ('admin', 'password')],
            'generic': [('admin', 'admin'), ('admin', 'password'), ('root', 'root'),
                       ('test', 'test'), ('user', 'user')]
        }

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
        print("\033[1;37mZeroDeface - Active Website Vulnerability Scanner\033[0m")
        print("\033[1;33mVersion 2.0 | Ethical Use Only\033[0m\n")

    def log_vulnerability(self, category, description, exploit=None, proof=None):
        vuln = {
            'category': category,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'exploit': exploit,
            'proof': proof if proof else "Verified"
        }
        self.vulnerabilities.append(vuln)
        print(f"\033[1;31m[!] {category}:\033[0m {description}")
        if exploit:
            print(f"   \033[1;34mExploit:\033[0m {exploit}")

    def crawl_site(self, max_pages=20):
        """Crawl the website to find interesting endpoints"""
        try:
            visited = set()
            queue = [self.target_url]
            
            while queue and len(visited) < max_pages:
                url = queue.pop(0)
                if url in visited:
                    continue
                    
                try:
                    response = self.session.get(url, verify=False, timeout=10)
                    visited.add(url)
                    
                    # Parse page content
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Add new links to queue
                    for link in soup.find_all('a', href=True):
                        absolute_url = urljoin(url, link['href'])
                        if self.target_url in absolute_url and absolute_url not in visited:
                            queue.append(absolute_url)
                            
                    # Check for forms
                    forms = soup.find_all('form')
                    for form in forms:
                        self.check_form_vulnerabilities(form, url)
                        
                except Exception as e:
                    continue
                    
            return visited
        except Exception as e:
            print(f"[-] Crawling error: {e}")
            return []

    def check_form_vulnerabilities(self, form, base_url):
        """Check a form for various vulnerabilities"""
        action = form.get('action', '')
        form_url = urljoin(base_url, action)
        method = form.get('method', 'get').lower()
        
        # Check for file uploads
        if form.find('input', {'type': 'file'}):
            self.test_file_upload(form, form_url)
            
        # Check for login forms
        if form.find('input', {'type': 'password'}):
            self.test_default_credentials(form_url)

    def test_file_upload(self, form, action_url):
        """Test file upload functionality"""
        test_files = [
            ('test.html', 'text/html', f'<html><body>{self.test_content}</body></html>'),
            ('test.php', 'application/x-php', '<?php echo "VULNERABLE_'+self.test_content+'"; ?>'),
            ('test.svg', 'image/svg+xml', '<svg><script>alert("XSS")</script></svg>')
        ]
        
        for filename, content_type, content in test_files:
            try:
                files = {'file': (filename, content, content_type)}
                response = self.session.post(action_url, files=files, verify=False, timeout=15)
                
                if response.status_code in [200, 201, 302]:
                    # Check if file is accessible
                    file_url = urljoin(action_url, filename)
                    file_response = self.session.get(file_url, verify=False, timeout=10)
                    
                    if file_response.status_code == 200 and self.test_content in file_response.text:
                        exploit = f"curl -F 'file=@{filename}' {action_url}"
                        self.log_vulnerability(
                            "File Upload Vulnerability",
                            f"Unrestricted file upload at {action_url}",
                            exploit=exploit
                        )
                        self.uploaded_files.append(file_url)
                        return True
                        
            except Exception as e:
                print(f"[-] Upload test failed for {filename}: {e}")
        return False

    def scan_upload_vulnerability(self):
        """Systematically check for upload vulnerabilities"""
        print("\n[+] Scanning for file upload vulnerabilities...")
        
        # Check common upload paths
        for path in self.common_upload_paths:
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
        
        # Crawl site to find upload forms
        print("[*] Crawling site to find upload forms...")
        visited_urls = self.crawl_site()
        print(f"[*] Crawled {len(visited_urls)} pages")
        
        return False

    def scan_admin_panels(self):
        """Check for common admin interfaces"""
        print("\n[+] Scanning for admin panels...")
        found = False
        
        for path in self.common_admin_paths:
            admin_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(admin_url, verify=False, timeout=10)
                if response.status_code == 200:
                    self.log_vulnerability(
                        "Admin Panel Exposed",
                        f"Admin panel found at {admin_url}",
                        f"Open in browser: {admin_url}"
                    )
                    found = True
                    
                    # Test default credentials
                    self.test_default_credentials(admin_url)
                    
            except Exception as e:
                print(f"[-] Error checking {admin_url}: {e}")
                
        return found

    def test_default_credentials(self, login_url):
        """Test common default credentials on login forms"""
        print(f"[*] Testing default credentials at {login_url}")
        
        # Try generic credentials first
        for username, password in self.default_credentials['generic']:
            if self.attempt_login(login_url, username, password):
                return True
                
        # Try CMS-specific credentials if detected
        try:
            response = self.session.get(login_url, verify=False, timeout=10)
            if 'wordpress' in response.text.lower():
                for creds in self.default_credentials['wordpress']:
                    if self.attempt_login(login_url, *creds):
                        return True
            elif 'joomla' in response.text.lower():
                for creds in self.default_credentials['joomla']:
                    if self.attempt_login(login_url, *creds):
                        return True
            elif 'drupal' in response.text.lower():
                for creds in self.default_credentials['drupal']:
                    if self.attempt_login(login_url, *creds):
                        return True
        except:
            pass
            
        return False

    def attempt_login(self, login_url, username, password):
        """Attempt to login with given credentials"""
        try:
            data = {
                'username': username,
                'password': password,
                'login': 'submit'
            }
            response = self.session.post(login_url, data=data, verify=False, timeout=15)
            
            if 'logout' in response.text.lower() or 'dashboard' in response.text.lower():
                self.log_vulnerability(
                    "Default Credentials",
                    f"Valid credentials found: {username}/{password}",
                    f"curl -X POST -d 'username={username}&password={password}' {login_url}"
                )
                return True
        except:
            return False
        return False

    def generate_report(self, filename):
        """Generate JSON report of findings"""
        report = {
            'target': self.target_url,
            'date': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to {filename}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")

    def cleanup(self):
        """Remove any test files we uploaded"""
        for file_url in self.uploaded_files:
            try:
                self.session.delete(file_url, verify=False, timeout=10)
            except:
                pass

def main():
    parser = argparse.ArgumentParser(description='ZeroDeface Website Vulnerability Scanner')
    parser.add_argument('--url', required=True, help='Target website URL')
    parser.add_argument('--all', action='store_true', help='Run all vulnerability checks')
    parser.add_argument('--upload', action='store_true', help='Check for file upload vulnerabilities')
    parser.add_argument('--admin', action='store_true', help='Scan for admin panels')
    parser.add_argument('--report', help='Save findings to JSON file')
    args = parser.parse_args()

    scanner = DefacementScanner(args.url)
    scanner.print_banner()

    try:
        if args.all or args.upload:
            scanner.scan_upload_vulnerability()
            
        if args.all or args.admin:
            scanner.scan_admin_panels()
            
        if args.report:
            scanner.generate_report(args.report)
            
        if not scanner.vulnerabilities:
            print("\n[-] No vulnerabilities found. Try manual testing:")
            print("- Check /upload.php, /admin.php manually")
            print("- Test common default credentials")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    finally:
        scanner.cleanup()

if __name__ == '__main__':
    main()
