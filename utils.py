"""
Utility Functions for SQL Injection Scanner
Educational and Authorized Testing Only
"""

import re
import sys
import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Optional

def validate_url(url: str) -> bool:
    """
    Validate URL format
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if valid URL
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def validate_target_for_testing(url: str) -> tuple[bool, str]:
    """
    Validate if target is appropriate for educational testing
    
    Args:
        url (str): Target URL
        
    Returns:
        tuple: (is_valid, reason)
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return False, "Invalid URL format"
        
        # Allow localhost
        if hostname in ['localhost', '127.0.0.1']:
            return True, "Localhost allowed for testing"
        
        # Allow private IP ranges
        try:
            ip = ipaddress.ip_address(hostname)
            private_ranges = [
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
            ]
            for private_range in private_ranges:
                if ip in private_range:
                    return True, "Private IP allowed for testing"
        except ValueError:
            pass  # Not an IP address, continue with hostname checks
        
        # Allow educational testing sites
        educational_domains = [
            'testphp.vulnweb.com',
            'demo.testfire.net',
            'zero.webappsecurity.com',
            'httpbin.org',
            'httpbingo.org',
            'reqres.in',
            'jsonplaceholder.typicode.com',
            'api.github.com',
            'api.openweathermap.org',
            'jsonbin.org',
            'mocki.io',
            'webhook.site'
        ]
        
        if hostname in educational_domains:
            return True, "Educational testing site allowed"
        
        return False, "Only localhost, private networks, and educational testing sites allowed"
        
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def extract_form_data(html_content: str) -> List[Dict]:
    """
    Extract form data from HTML content
    
    Args:
        html_content (str): HTML content
        
    Returns:
        list: List of forms with their fields
    """
    forms = []
    
    # Simple regex to extract forms
    form_pattern = r'<form[^>]*>(.*?)</form>'
    form_matches = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
    
    for form_content in form_matches:
        # Extract input fields
        input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*(?:value=["\']([^"\']*)["\'])?[^>]*>'
        input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
        
        form_fields = {}
        for name, value in input_matches:
            form_fields[name] = value or ''
        
        # Extract action and method
        action_pattern = r'action=["\']([^"\']*)["\']'
        method_pattern = r'method=["\']([^"\']*)["\']'
        
        action_match = re.search(action_pattern, form_content, re.IGNORECASE)
        method_match = re.search(method_pattern, form_content, re.IGNORECASE)
        
        forms.append({
            'action': action_match.group(1) if action_match else '',
            'method': method_match.group(1) if method_match else 'GET',
            'fields': form_fields
        })
    
    return forms

def parse_post_data(data_string: str) -> Dict[str, str]:
    """
    Parse POST data string into dictionary
    
    Args:
        data_string (str): POST data string (key=value&key2=value2)
        
    Returns:
        dict: Parsed POST data
    """
    data = {}
    if not data_string:
        return data
    
    pairs = data_string.split('&')
    for pair in pairs:
        if '=' in pair:
            key, value = pair.split('=', 1)
            data[key] = value
    
    return data

def format_bytes(bytes_value: int) -> str:
    """
    Format bytes into human readable format
    
    Args:
        bytes_value (int): Bytes value
        
    Returns:
        str: Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} TB"

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file system usage
    
    Args:
        filename (str): Original filename
        
    Returns:
        str: Sanitized filename
    """
    # Remove invalid characters
    invalid_chars = r'[<>:"/\\|?*]'
    filename = re.sub(invalid_chars, '_', filename)
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip('. ')
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename or 'unnamed'

def print_banner():
    """
    Print the scanner banner with legal disclaimer
    """
    banner = """
================================================================
                SQL INJECTION SCANNER v1.0                     
          Educational & Authorized Testing Tool Only               
================================================================

LEGAL DISCLAIMER & ETHICAL GUIDELINES:
------------------------------------------------------------
This tool is for EDUCATIONAL PURPOSES ONLY.

AUTHORIZED TESTING TARGETS ONLY:
[+] Localhost applications (127.0.0.1, localhost)
[+] Private network addresses (192.168.x.x, 10.x.x.x)
[+] Educational labs (DVWA, Juice Shop, WebGoat)
[+] Systems you own or have explicit permission

STRICTLY PROHIBITED:
[x] Public websites and production systems
[x] Services you do not own or permission to test
[x] Any form of unauthorized access or exploitation
[x] Data extraction, database dumping, or credential theft

RESPONSIBLE USE:
• Test only on authorized systems
• Use results for defensive security purposes
• Report vulnerabilities responsibly
• Follow all applicable laws and regulations

VIOLATION WARNING:
Unauthorized testing may result in:
- Criminal charges under computer crime laws
- Civil liability for damages
- Academic or professional consequences
------------------------------------------------------------

This scanner helps IDENTIFY vulnerabilities - NOT exploit them.
================================================================
    """
    print(banner)

def print_help():
    """
    Print help information
    """
    help_text = """
SQL INJECTION SCANNER - HELP

USAGE:
    python main.py <URL> [OPTIONS]

REQUIRED ARGUMENTS:
    URL                    Target URL to scan (e.g., http://localhost/test.php?id=1)

OPTIONS:
    --method METHOD        HTTP method (GET or POST, default: GET)
    --data DATA           POST data in format: key1=value1&key2=value2
    --delay SECONDS       Delay between requests (default: 1.0)
    --timeout SECONDS     Request timeout (default: 10)
    --threads COUNT       Number of concurrent threads (default: 5)
    --payloads CATEGORY   Use specific payload category (basic, union, error, boolean, time)
    --output-json FILE    Save results as JSON report
    --output-text FILE    Save results as text report
    --log FILE            Log scan activity to file
    --help, -h            Show this help message

EXAMPLES:
    # Basic GET scan on localhost
    python main.py "http://localhost/vuln.php?id=1&name=test"
    
    # POST scan with data
    python main.py "http://localhost/login.php" --method POST --data "username=admin&password=test"
    
    # Advanced scan with custom settings
    python main.py "http://localhost/test.php?id=1" --delay 2 --threads 3 --output-json report.json
    
    # Test specific payload category
    python main.py "http://localhost/test.php?id=1" --payloads basic
    """
    print(help_text)

def check_dependencies():
    """
    Check if required dependencies are installed
    """
    required_modules = ['requests', 'colorama', 'urllib3', 'certifi']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"Missing required modules: {', '.join(missing_modules)}")
        print("Install with: pip install -r requirements.txt")
        return False
    
    return True
