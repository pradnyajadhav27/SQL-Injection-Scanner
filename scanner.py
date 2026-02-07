"""
SQL Injection Scanner Engine
Educational and Authorized Testing Only
Main scanning logic with HTTP request handling and false positive detection
"""

import requests
import time
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Optional, Tuple
import concurrent.futures
from payloads import get_payloads
from detector import SQLInjectionDetector

class SQLInjectionScanner:
    """
    Main SQL injection scanner class for educational testing
    Includes target validation and false positive detection
    """
    
    def __init__(self, delay: float = 1.0, timeout: int = 10, max_workers: int = 5):
        """
        Initialize scanner with configuration
        
        Args:
            delay (float): Delay between requests in seconds
            timeout (int): Request timeout in seconds
            max_workers (int): Maximum number of concurrent threads
        """
        self.delay = delay
        self.timeout = timeout
        self.max_workers = max_workers
        self.detector = SQLInjectionDetector()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SQL-Injection-Scanner-Educational-Tool/1.0'
        })
        
    def validate_target(self, url: str) -> Tuple[bool, str]:
        return validate_target_for_testing(self, url)
        
            
        Returns:
            tuple: (is_valid, reason)
        """
        parsed = urlparse(url)
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        
        # Check for localhost/local network
        local_indicators = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '::1'
        ]
        
        # Check for private IP ranges
        private_ranges = [
            '192.168.',
            '10.',
            '172.16.',
            '172.17.',
            '172.18.',
            '172.19.',
            '172.20.',
            '172.21.',
            '172.22.',
            '172.23.',
            '172.24.',
            '172.25.',
            '172.26.',
            '172.27.',
            '172.28.',
            '172.29.',
            '172.30.',
            '172.31.',
        ]
        
        # Check for educational/lab domains
        educational_domains = [
            'dvwa',
            'juice-shop',
            'webgoat',
            'gruyere',
            'testphp.vulnweb.com',
            'demo.testfire.net',
        ]
        
        # Check if target is appropriate
        is_local = any(indicator in hostname for indicator in local_indicators)
        is_private = any(hostname.startswith(range_prefix) for range_prefix in private_ranges)
        is_educational = any(domain in hostname for domain in educational_domains)
        
        if not (is_local or is_private or is_educational):
            return False, "Target must be localhost, private network, or educational lab environment"
        
        # Check for known public services (block them)
        blocked_domains = [
            'google.com',
            'facebook.com',
            'twitter.com',
            'github.com',
            'stackoverflow.com',
            'amazon.com',
            'microsoft.com',
            'apple.com',
        ]
        
        if any(domain in hostname for domain in blocked_domains):
            return False, "Public websites are not allowed for testing"
        
        return True, "Target validated for educational testing"
    
    def parse_url(self, url: str) -> Dict:
        """
        Parse URL and extract parameters
        
        Args:
            url (str): Target URL
            
        Returns:
            dict: Parsed URL information
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Convert parse_qs format to simple dict
        simple_params = {}
        for key, values in params.items():
            simple_params[key] = values[0] if values else ''
        
        return {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'path': parsed.path,
            'params': parsed.params,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'parameters': simple_params,
            'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        }
    
    def make_request(self, url: str, method: str = 'GET', params: Optional[Dict] = None, 
                    data: Optional[Dict] = None) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling
        
        Args:
            url (str): Target URL
            method (str): HTTP method (GET/POST)
            params (dict): URL parameters
            data (dict): POST data
            
        Returns:
            requests.Response or None
        """
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout)
            else:  # POST
                response = self.session.post(url, data=data, timeout=self.timeout)
            
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None
    
    def get_normal_response(self, url: str, method: str = 'GET', 
                          params: Optional[Dict] = None, data: Optional[Dict] = None) -> Optional[str]:
        """
        Get normal response without any injection
        
        Args:
            url (str): Target URL
            method (str): HTTP method
            params (dict): URL parameters
            data (dict): POST data
            
        Returns:
            str or None: Response text
        """
        response = self.make_request(url, method, params, data)
        return response.text if response else None
    
    def inject_payload_get(self, url_info: Dict, param_name: str, payload: str) -> Optional[str]:
        """
        Inject payload into GET parameter
        
        Args:
            url_info (dict): Parsed URL information
            param_name (str): Parameter to inject into
            payload (str): SQL injection payload
            
        Returns:
            str or None: Response text
        """
        # Copy parameters and inject payload
        injected_params = url_info['parameters'].copy()
        injected_params[param_name] = payload
        
        # Rebuild URL with injected parameters
        query_string = urlencode(injected_params)
        injected_url = f"{url_info['base_url']}?{query_string}"
        
        response = self.make_request(injected_url, 'GET')
        return response.text if response else None
    
    def inject_payload_post(self, url: str, param_name: str, payload: str, 
                          post_data: Optional[Dict] = None) -> Optional[str]:
        """
        Inject payload into POST parameter
        
        Args:
            url (str): Target URL
            param_name (str): Parameter to inject into
            payload (str): SQL injection payload
            post_data (dict): POST data
            
        Returns:
            str or None: Response text
        """
        if post_data is None:
            post_data = {}
        
        # Copy POST data and inject payload
        injected_data = post_data.copy()
        injected_data[param_name] = payload
        
        response = self.make_request(url, 'POST', data=injected_data)
        return response.text if response else None
    
    def scan_parameter(self, url: str, param_name: str, method: str = 'GET',
                      post_data: Optional[Dict] = None, payloads: Optional[List[str]] = None) -> Dict:
        """
        Scan a single parameter for SQL injection vulnerabilities
        
        Args:
            url (str): Target URL
            param_name (str): Parameter name to test
            method (str): HTTP method (GET/POST)
            post_data (dict): POST data for POST requests
            payloads (list): List of payloads to test
            
        Returns:
            dict: Parameter scan results
        """
        print(f"Scanning parameter: {param_name}")
        
        # Parse URL for this scan
        url_info = self.parse_url(url)
        
        # Validate target
        is_valid, validation_reason = self.validate_target_for_testing(url)
        if not is_valid:
            return {
                'parameter': param_name,
                'status': 'INVALID_TARGET',
                'reason': validation_reason,
                'vulnerabilities': []
            }
        
        # Get baseline response for comparison
        if method == 'GET':
            baseline_params = url_info['parameters'].copy()
            baseline_response = self.make_request(url, 'GET', params=baseline_params)
        else:
            baseline_response = self.make_request(url, 'POST', data=post_data)
        
        if not baseline_response:
            return {
                'parameter': param_name,
                'status': 'NOT_REACHABLE',
                'reason': 'Unable to establish baseline connection with target',
                'vulnerabilities': []
            }
        
        baseline_text = baseline_response.text
        
        # Test payloads
        vulnerabilities = []
        request_errors = 0
        
        if payloads is None:
            from payloads import get_payloads
            payloads = get_payloads()
        
        for i, payload in enumerate(payloads, 1):
            print(f"  Testing payload {i}/{len(payloads)}: {payload[:50]}...")
            
            time.sleep(self.delay)
            
            try:
                # Inject payload
                response_text = self.inject_payload(url_info, param_name, payload, method, post_data)
                
                if response_text:
                    # Analyze response
                    analysis = self.detector.analyze_response_differences(baseline_text, response_text)
                    status, reason = self.detector.determine_vulnerability(analysis)
                    
                    if status in ['VULNERABLE', 'POSSIBLY_VULNERABLE', 'FALSE_POSITIVE']:
                        vulnerabilities.append({
                            'payload': payload,
                            'status': status,
                            'reason': reason
                        })
                else:
                    request_errors += 1
                    
            except Exception as e:
                request_errors += 1
                continue
        
        # Determine parameter status
        if request_errors == len(payloads):
            param_status = 'NOT_TESTED'
            reason = 'All payload requests failed - possible connectivity issue'
        elif vulnerabilities:
            false_positives = [v for v in vulnerabilities if v['status'] == 'FALSE_POSITIVE']
            if false_positives and len(false_positives) == len(vulnerabilities):
                param_status = 'FALSE_POSITIVE'
                reason = 'Non-database endpoint detected'
            else:
                vulnerable_count = sum(1 for v in vulnerabilities if v['status'] == 'VULNERABLE')
                if vulnerable_count > 0:
                    param_status = 'VULNERABLE'
                    reason = f'Found {vulnerable_count} SQL injection vulnerabilities'
                else:
                    param_status = 'POSSIBLY_VULNERABLE'
                    reason = 'Potential SQL injection indicators found'
        else:
            param_status = 'SAFE'
            reason = 'No vulnerabilities detected'
        
        return {
            'parameter': param_name,
            'status': param_status,
            'reason': reason,
            'vulnerabilities': vulnerabilities,
            'request_errors': request_errors
        }
    
    def scan_url(self, url: str, method: str = 'GET', post_data: Optional[Dict] = None, payloads: Optional[List[str]] = None) -> Dict:
        """
        Scan entire URL for SQL injection vulnerabilities with connectivity testing
        
        Args:
            url (str): Target URL
            method (str): HTTP method (GET/POST)
            post_data (dict): POST data for POST requests
            payloads (list): List of payloads to test
            
        Returns:
            dict: Complete scan results
        """
        if payloads is None:
            from payloads import get_payloads
            payloads = get_payloads()
        
        # Parse URL and extract parameters
        url_info = self.parse_url(url)
        
        if method == 'GET':
            parameters = url_info['parameters']
        else:
            parameters = post_data if post_data else {}
        
        if not parameters:
            return {
                'url': url,
                'method': method,
                'status': 'NO_PARAMETERS',
                'reason': 'No parameters found to test',
                'results': []
            }
        
        # CRITICAL: Perform baseline connectivity test first
        baseline_success, baseline_reason = self._test_baseline_connectivity(url, method, parameters)
        if not baseline_success:
            return {
                'url': url,
                'method': method,
                'status': 'NOT_REACHABLE',
                'reason': baseline_reason,
                'results': []
            }
        
        results = []
        
        # Scan each parameter
        for param_name in parameters.keys():
            print(f"Testing parameter: {param_name}")
            
            result = self.scan_parameter(url, param_name, method, post_data, payloads)
            results.append(result)
        
        # Calculate overall status
        overall_status = self._calculate_overall_status(results)
        
        return {
            'url': url,
            'method': method,
            'status': overall_status,
            'total_parameters': len(parameters),
            'vulnerable_parameters': len([r for r in results if r['status'] == 'VULNERABLE']),
            'possibly_vulnerable_parameters': len([r for r in results if r['status'] == 'POSSIBLY_VULNERABLE']),
            'false_positive_parameters': len([r for r in results if r['status'] == 'FALSE_POSITIVE']),
            'safe_parameters': len([r for r in results if r['status'] == 'SAFE']),
            'not_tested_parameters': len([r for r in results if r['status'] == 'NOT_TESTED']),
            'results': results
        }
    
    def _test_baseline_connectivity(self, url: str, method: str, params: dict) -> tuple[bool, str]:
        """
        Test baseline connectivity to target before scanning
        
        Args:
            url (str): Target URL
            method (str): HTTP method
            params (dict): Request parameters
            
        Returns:
            tuple: (success, reason)
        """
        try:
            if method == 'GET':
                response = self.session.get(url, params=params, timeout=10)
            else:
                response = self.session.post(url, data=params, timeout=10)
            
            if response.status_code == 200:
                return True, "Connection established successfully"
            elif response.status_code == 404:
                return False, "Target not found (404)"
            elif response.status_code == 403:
                return False, "Access forbidden (403)"
            else:
                return False, f"HTTP error {response.status_code}"
                
        except requests.exceptions.ConnectionError:
            return False, "Connection refused - target not running"
        except requests.exceptions.Timeout:
            return False, "Connection timeout - target not responding"
        except requests.exceptions.RequestException as e:
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"
    
    def _calculate_overall_status(self, results: list) -> str:
        """
        Calculate overall scan status from parameter results
        
        Args:
            results (list): Parameter scan results
            
        Returns:
            str: Overall status
        """
        if not results:
            return 'NO_PARAMETERS'
        
        # Check for any NOT_REACHABLE or NOT_TESTED
        not_reachable = [r for r in results if r['status'] in ['NOT_REACHABLE', 'NOT_TESTED']]
        if not_reachable:
            return 'NOT_REACHABLE'
        
        # Check for vulnerabilities
        vulnerable = [r for r in results if r['status'] == 'VULNERABLE']
        if vulnerable:
            return 'VULNERABLE'
        
        # Check for possibly vulnerable
        possibly_vulnerable = [r for r in results if r['status'] == 'POSSIBLY_VULNERABLE']
        if possibly_vulnerable:
            return 'POSSIBLY_VULNERABLE'
        
        # Check for false positives
        false_positives = [r for r in results if r['status'] == 'FALSE_POSITIVE']
        if false_positives:
            return 'FALSE_POSITIVE'
        
        # If we have safe results and no issues
        safe = [r for r in results if r['status'] == 'SAFE']
        if safe:
            return 'SAFE'
        
        return 'UNKNOWN'
