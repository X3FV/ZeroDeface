#!/usr/bin/env python3
import argparse
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import json
from datetime import datetime

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings()

class DefacementScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        self.vulnerabilities = []
        
        # Test files for upload vulnerabilities
        self.test_files = [
            ('zerodeface.html', 'text/html', '<h1>Site Defaced</h1><p>Security Test</p>'),
            ('zerodeface.php', 'application/x-php', '<?php echo "VULNERABLE"; ?>')
        ]

    def scan_upload(self):
        """Check for file upload vulnerabilities"""
        try:
            # Check common upload paths
            upload_paths = ['upload', 'admin/upload', 'wp-content/uploads']
            for path in upload_paths:
                url = urljoin(self.target_url, path)
                try:
                    response = self.session.get(url, timeout=10, verify=False)
                    if response.status_code == 200 and 'upload' in response.text.lower():
                        print(f"[+] Found upload page at {url}")
                        self.test_upload(url)
                except:
                    continue
            
            # Check forms with file inputs
            response = self.session.get(self.target_url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                if form.find('input', {'type': 'file'}):
                    action = form.get('action') or self.target_url
                    self.test_upload(urljoin(self.target_url, action))
                    
        except Exception as e:
            print(f"[-] Upload scan error: {e}")

    def test_upload(self, url):
        """Test if we can upload malicious files"""
        for filename, content_type, content in self.test_files:
            try:
                files = {'file': (filename, content, content_type)}
                response = self.session.post(url, files=files, verify=False)
                
                if response.status_code in [200, 201, 302]:
                    # Check if file is accessible
                    file_url = urljoin(url, filename)
                    file_response = self.session.get(file_url, verify=False)
                    
                    if file_response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'file_upload',
                            'url': url,
                            'exploit': f"curl -F 'file=@{filename}' {url}",
                            'file_url': file_url
                        })
                        print(f"\n[CRITICAL] File upload vulnerability found!")
                        print(f"Upload URL: {url}")
                        print(f"Uploaded file accessible at: {file_url}")
                        return True
                        
            except Exception as e:
                print(f"[-] Upload test failed: {e}")
        return False

    def scan_admin_panels(self):
        """Check for common admin panels"""
        admin_paths = [
            'admin', 'wp-admin', 'administrator', 
            'backend', 'admin.php', 'login'
        ]
        
        for path in admin_paths:
            url = urljoin(self.target_url, path)
            try:
                response = self.session.get(url, verify=False)
                if response.status_code == 200:
                    print(f"\n[+] Admin panel found at {url}")
                    self.vulnerabilities.append({
                        'type': 'admin_panel',
                        'url': url,
                        'exploit': f"Open in browser: {url}"
                    })
                    
                    # Try default credentials
                    self.test_default_logins(url)
                    
            except:
                continue

    def test_default_logins(self, login_url):
        """Test common default credentials"""
        credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('administrator', 'password'),
            ('root', 'toor')
        ]
        
        for username, password in credentials:
            try:
                data = {
                    'username': username,
                    'password': password,
                    'login': 'submit'
                }
                response = self.session.post(login_url, data=data, verify=False)
                
                if 'logout' in response.text.lower() or 'dashboard' in response.text.lower():
                    print(f"\n[CRITICAL] Default credentials work: {username}/{password}")
                    self.vulnerabilities.append({
                        'type': 'default_credentials',
                        'url': login_url,
                        'credentials': f"{username}:{password}",
                        'exploit': f"curl -d 'username={username}&password={password}' {login_url}"
                    })
                    return True
                    
            except Exception as e:
                print(f"[-] Login test failed: {e}")
        return False

    def generate_report(self, filename):
        """Save results to JSON file"""
        if self.vulnerabilities:
            with open(filename, 'w') as f:
                json.dump(self.vulnerabilities, f, indent=2)
            print(f"\n[+] Report saved to {filename}")

def main():
    print("\nZeroDeface Web Vulnerability Scanner")
    print("-----------------------------------")
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True, help='Target website URL')
    parser.add_argument('--report', help='Save results to JSON file')
    args = parser.parse_args()
    
    scanner = DefacementScanner(args.url)
    
    print("\n[1/2] Scanning for file upload vulnerabilities...")
    scanner.scan_upload()
    
    print("\n[2/2] Scanning for admin panels...")
    scanner.scan_admin_panels()
    
    if args.report:
        scanner.generate_report(args.report)
    
    if not scanner.vulnerabilities:
        print("\n[-] No critical vulnerabilities found")
        print("Try manual tests for:")
        print("- /admin.php")
        print("- /upload.php")
        print("- Default credentials (admin:admin)")
    else:
        print("\n[+] Scan complete. Vulnerabilities found!")

if __name__ == '__main__':
    main()
