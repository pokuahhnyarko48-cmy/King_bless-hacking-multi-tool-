#!/usr/bin/env python3
"""
KING BLESS - Ultimate Hacking Multi-Tool
Author: Security Researcher
Version: 4.0
For Educational and Authorized Testing Only
"""

import os
import sys
import socket
import threading
import subprocess
import time
import requests
import urllib3
from urllib.parse import urlparse, urljoin
import dns.resolver
import hashlib
import base64
import random
import string
from datetime import datetime
import concurrent.futures
from colorama import Fore, Style, init

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

class KingBlessTool:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        self.banner = f"""
{Fore.RED}
╦╔═╔═╗╦╔═╗  ╔╗ ╔═╗╦╔╗╔╔═╗╦╔═╔═╗╦═╗
╠╩╗║╣ ║║ ╦  ╠╩╗╠═╣║║║║╠═╣╠╩╗║╣ ╠╦╝
╩ ╩╚═╝╩╚═╝  ╚═╝╩ ╩╩╝╚╝╩ ╩╩ ╩╚═╝╩╚═
{Style.RESET_ALL}
{Fore.CYAN}            ULTIMATE HACKING MULTI-TOOL v4.0{Style.RESET_ALL}
{Fore.YELLOW}         For Authorized Security Testing Only{Style.RESET_ALL}
"""
        
    def check_internet(self):
        """Check internet connection"""
        try:
            requests.get('https://www.google.com', timeout=5)
            return True
        except:
            return False

    def display_menu(self):
        print(self.banner)
        print(f"{Fore.GREEN}[1]  Network Scanner")
        print(f"[2]  Port Scanner") 
        print(f"[3]  Web Vulnerability Scanner")
        print(f"[4]  DNS Reconnaissance")
        print(f"[5]  Subdomain Discovery")
        print(f"[6]  Directory Brute Forcer")
        print(f"[7]  SQL Injection Tester")
        print(f"[8]  Hash Cracker")
        print(f"[9]  SSL/TLS Analyzer")
        print(f"[10] Social Media Finder")
        print(f"[11] Password Generator")
        print(f"[12] Code Obfuscator")
        print(f"[13] System Info")
        print(f"[14] Update Tool")
        print(f"[0]  Exit{Style.RESET_ALL}")

    def network_scanner(self):
        print(f"{Fore.CYAN}[*] KING BLESS Network Scanner...{Style.RESET_ALL}")
        
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"{Fore.GREEN}[+] Your Hostname: {hostname}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Your Local IP: {local_ip}{Style.RESET_ALL}")
            
            network_base = '.'.join(local_ip.split('.')[:-1]) + '.'
            print(f"{Fore.YELLOW}[*] Scanning {network_base}1-254...{Style.RESET_ALL}")
            
            def scan_host(ip):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        result = s.connect_ex((ip, 80))
                        if result == 0:
                            try:
                                host = socket.gethostbyaddr(ip)[0]
                            except:
                                host = "Unknown"
                            print(f"{Fore.GREEN}[+] LIVE: {ip} -> {host}{Style.RESET_ALL}")
                except:
                    pass

            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                executor.map(scan_host, [f"{network_base}{i}" for i in range(1, 255)])
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

    def port_scanner(self):
        print(f"{Fore.CYAN}[*] KING BLESS Port Scanner...{Style.RESET_ALL}")
        target = input(f"{Fore.YELLOW}[?] Enter target IP/hostname: {Style.RESET_ALL}")
        
        ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 27017: "MongoDB"
        }
        
        print(f"{Fore.YELLOW}[*] Scanning {target}...{Style.RESET_ALL}")
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        service = ports.get(port, "Unknown")
                        print(f"{Fore.GREEN}[+] OPEN: {port}/TCP - {service}{Style.RESET_ALL}")
            except:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, ports.keys())

    def web_scanner(self):
        print(f"{Fore.CYAN}[*] KING BLESS Web Vulnerability Scanner...{Style.RESET_ALL}")
        url = input(f"{Fore.YELLOW}[?] Enter target URL: {Style.RESET_ALL}")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        issues = []
        
        try:
            response = self.session.get(url, verify=False, timeout=10)
            
            # Check security headers
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security']
            for header in security_headers:
                if header not in response.headers:
                    issues.append(f"Missing header: {header}")
            
            # Check common files
            files = [
                '/.env', '/config.php', '/backup.zip', '/admin', '/wp-admin',
                '/phpmyadmin', '/.git/config', '/phpinfo.php', '/test.php'
            ]
            
            for file in files:
                test_url = urljoin(url, file)
                try:
                    r = self.session.get(test_url, timeout=5, verify=False)
                    if r.status_code in [200, 301, 302, 403]:
                        issues.append(f"Exposed: {test_url}")
                except:
                    pass
                    
            if issues:
                print(f"{Fore.RED}[!] Issues Found:{Style.RESET_ALL}")
                for issue in issues:
                    print(f"  {Fore.RED}• {issue}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No obvious issues found{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

    def dns_recon(self):
        print(f"{Fore.CYAN}[*] KING BLESS DNS Reconnaissance...{Style.RESET_ALL}")
        
        if not self.check_internet():
            print(f"{Fore.RED}[-] Internet required{Style.RESET_ALL}")
            return
            
        domain = input(f"{Fore.YELLOW}[?] Enter domain: {Style.RESET_ALL}")
        
        records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        try:
            for record in records:
                try:
                    answers = dns.resolver.resolve(domain, record)
                    print(f"\n{Fore.GREEN}[+] {record} Records:{Style.RESET_ALL}")
                    for data in answers:
                        print(f"    {data}")
                except:
                    print(f"{Fore.RED}[-] No {record} records{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"{Fore.RED}[-] DNS Error: {e}{Style.RESET_ALL}")

    def subdomain_finder(self):
        print(f"{Fore.CYAN}[*] KING BLESS Subdomain Discovery...{Style.RESET_ALL}")
        
        if not self.check_internet():
            print(f"{Fore.RED}[-] Internet required{Style.RESET_ALL}")
            return
            
        domain = input(f"{Fore.YELLOW}[?] Enter domain: {Style.RESET_ALL}")
        
        subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'admin', 'blog', 'shop', 'api', 'dev', 'test',
            'staging', 'secure', 'vpn', 'remote', 'server', 'cdn', 'static'
        ]
        
        print(f"{Fore.YELLOW}[*] Discovering subdomains...{Style.RESET_ALL}")
        
        def check_sub(sub):
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                print(f"{Fore.GREEN}[+] FOUND: {full_domain}{Style.RESET_ALL}")
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_sub, subdomains)

    def directory_bruteforce(self):
        print(f"{Fore.CYAN}[*] KING BLESS Directory Brute Forcer...{Style.RESET_ALL}")
        url = input(f"{Fore.YELLOW}[?] Enter target URL: {Style.RESET_ALL}")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        directories = [
            'admin', 'login', 'wp-admin', 'phpmyadmin', 'cpanel', 'webmail',
            'backup', 'config', 'uploads', 'images', 'css', 'js', 'api',
            'robots.txt', 'sitemap.xml', '.htaccess', '.git', '.env'
        ]
        
        print(f"{Fore.YELLOW}[*] Brute forcing directories...{Style.RESET_ALL}")
        
        def check_dir(directory):
            test_url = urljoin(url, directory)
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                if response.status_code in [200, 301, 302, 403]:
                    print(f"{Fore.GREEN}[+] FOUND [{response.status_code}]: {test_url}{Style.RESET_ALL}")
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_dir, directories)

    def sql_injection_test(self):
        print(f"{Fore.CYAN}[*] KING BLESS SQL Injection Tester...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Educational purposes only!{Style.RESET_ALL}")
        
        url = input(f"{Fore.YELLOW}[?] Enter URL with parameter: {Style.RESET_ALL}")
        
        payloads = ["'", "''", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT 1,2,3--"]
        
        try:
            original = self.session.get(url, verify=False, timeout=10)
            
            for payload in payloads:
                test_url = url + payload
                try:
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if len(response.text) != len(original.text):
                        print(f"{Fore.RED}[!] SQLi possible: {payload}{Style.RESET_ALL}")
                    elif "error" in response.text.lower() or "sql" in response.text.lower():
                        print(f"{Fore.RED}[!] Error-based SQLi: {payload}{Style.RESET_ALL}")
                        
                except:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

    def hash_cracker(self):
        print(f"{Fore.CYAN}[*] KING BLESS Hash Cracker...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Educational purposes only!{Style.RESET_ALL}")

        target_hash = input(f"{Fore.YELLOW}[?] Enter hash: {Style.RESET_ALL}")
        hash_type = input(f"{Fore.YELLOW}[?] Hash type (md5/sha1/sha256): {Style.RESET_ALL}").lower()
        
        passwords = [
            'password', '123456', 'password123', 'admin', 'qwerty', 'letmein',
            'welcome', 'monkey', '123456789', '12345678', '12345', '1234'
        ]
        
        print(f"{Fore.YELLOW}[*] Cracking hash...{Style.RESET_ALL}")
        
        for pwd in passwords:
            hashed = ""
            
            if hash_type == "md5":
                hashed = hashlib.md5(pwd.encode()).hexdigest()
            elif hash_type == "sha1":
                hashed = hashlib.sha1(pwd.encode()).hexdigest()
            elif hash_type == "sha256":
                hashed = hashlib.sha256(pwd.encode()).hexdigest()
            else:
                print(f"{Fore.RED}[-] Unsupported hash type{Style.RESET_ALL}")
                return
                
            if hashed == target_hash.lower():
                print(f"{Fore.GREEN}[+] CRACKED: {pwd}{Style.RESET_ALL}")
                return
                
        print(f"{Fore.RED}[-] Not found in wordlist{Style.RESET_ALL}")

    def ssl_analyzer(self):
        print(f"{Fore.CYAN}[*] KING BLESS SSL/TLS Analyzer...{Style.RESET_ALL}")
        domain = input(f"{Fore.YELLOW}[?] Enter domain: {Style.RESET_ALL}")
        
        try:
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    print(f"{Fore.GREEN}[+] SSL Info:{Style.RESET_ALL}")
                    print(f"    Subject: {cert.get('subject', 'N/A')}")
                    print(f"    Issuer: {cert.get('issuer', 'N/A')}")
                    print(f"    Cipher: {cipher[0] if cipher else 'N/A'}")
                    
        except Exception as e:
            print(f"{Fore.RED}[-] SSL Error: {e}{Style.RESET_ALL}")

    def password_generator(self):
        print(f"{Fore.CYAN}[*] KING BLESS Password Generator...{Style.RESET_ALL}")
        
        length = int(input(f"{Fore.YELLOW}[?] Password length: {Style.RESET_ALL}"))
        count = int(input(f"{Fore.YELLOW}[?] How many passwords: {Style.RESET_ALL}"))
        
        print(f"{Fore.GREEN}[+] Generated Passwords:{Style.RESET_ALL}")
        for i in range(count):
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            password = ''.join(random.choice(chars) for _ in range(length))
            print(f"    {i+1}. {password}")

    def system_info(self):
        print(f"{Fore.CYAN}[*] KING BLESS System Information{Style.RESET_ALL}")
        
        try:
            # Get system information
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            print(f"{Fore.GREEN}[+] System Info:{Style.RESET_ALL}")
            print(f"    Hostname: {hostname}")
            print(f"    Local IP: {local_ip}")
            print(f"    Python: {sys.version}")
            print(f"    Platform: {sys.platform}")
            
            # Check Termux environment
            if os.path.exists('/data/data/com.termux/files/usr'):
                print(f"    Environment: Termux")
            else:
                print(f"    Environment: Other")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

    def update_tool(self):
        print(f"{Fore.CYAN}[*] Updating KING BLESS...{Style.RESET_ALL}")
        
        if not self.check_internet():
            print(f"{Fore.RED}[-] No internet!{Style.RESET_ALL}")
            return
            
        try:
            # Update packages
            subprocess.run(['pkg', 'update', '-y'], check=True, capture_output=True)
            
            # Update Python packages
            packages = ['requests', 'colorama', 'dnspython', 'urllib3']
            
            for package in packages:
                subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', package], 
                             check=True, capture_output=True)
                
            print(f"{Fore.GREEN}[+] KING BLESS updated!{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Update failed: {e}{Style.RESET_ALL}")

    def run(self):
        # Check internet at startup
        if not self.check_internet():
            print(f"{Fore.YELLOW}[!] Limited functionality without internet{Style.RESET_ALL}")
            time.sleep(2)
        
        while True:
            os.system('clear')
            self.display_menu()
            choice = input(f"\n{Fore.YELLOW}[?] KING BLESS > {Style.RESET_ALL}")
            
            try:
                choice = int(choice)
            except:
                print(f"{Fore.RED}[-] Invalid input{Style.RESET_ALL}")
                time.sleep(2)
                continue
                
            if choice == 0:
                print(f"{Fore.CYAN}[*] KING BLESS out!{Style.RESET_ALL}")
                break
            elif choice == 1:
                self.network_scanner()
            elif choice == 2:
                self.port_scanner()
            elif choice == 3:
                self.web_scanner()
            elif choice == 4:
                self.dns_recon()
            elif choice == 5:
                self.subdomain_finder()
            elif choice == 6:
                self.directory_bruteforce()
            elif choice == 7:
                self.sql_injection_test()
            elif choice == 8:
                self.hash_cracker()
            elif choice == 9:
                self.ssl_analyzer()
            elif choice == 10:
                print(f"{Fore.YELLOW}[!] Social media finder in development{Style.RESET_ALL}")
            elif choice == 11:
                self.password_generator()
            elif choice == 12:
                print(f"{Fore.YELLOW}[!] Code obfuscator in development{Style.RESET_ALL}")
            elif choice == 13:
                self.system_info()
            elif choice == 14:
                self.update_tool()
            else:
                print(f"{Fore.RED}[-] Invalid option{Style.RESET_ALL}")
            
            input(f"\n{Fore.YELLOW}[?] Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        tool = KingBlessTool()
        tool.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}[*] KING BLESS terminated{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Fatal error: {e}{Style.RESET_ALL}")
