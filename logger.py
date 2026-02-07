"""
Logging and Reporting Module
Educational and Authorized Testing Only
Handles logging of scan results and report generation with false positive identification
"""

import json
import datetime
from typing import Dict, List
from colorama import init, Fore, Style

# Initialize colorama
init()

class ScanLogger:
    """
    Handles logging and reporting for SQL injection scans
    Includes false positive identification and ethical reporting
    """
    
    def __init__(self, log_file: str = None):
        """
        Initialize logger
        
        Args:
            log_file (str): Optional log file path
        """
        self.log_file = log_file
        self.scan_results = []
    
    def log_scan_start(self, url: str, method: str, parameters: List[str]):
        """
        Log the start of a scan
        
        Args:
            url (str): Target URL
            method (str): HTTP method
            parameters (list): Parameters being tested
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"\n{'='*60}")
        print(f"SQL INJECTION SCAN STARTED")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Timestamp: {timestamp}")
        print(f"Target URL: {url}")
        print(f"Method: {method}")
        print(f"Parameters: {', '.join(parameters)}")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"SQL INJECTION SCAN STARTED\n")
                f.write(f"{'='*60}\n")
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"Target URL: {url}\n")
                f.write(f"Method: {method}\n")
                f.write(f"Parameters: {', '.join(parameters)}\n")
                f.write(f"{'='*60}\n\n")
    
    def log_parameter_result(self, result: Dict):
        """
        Log result for a single parameter
        
        Args:
            result (dict): Parameter scan result
        """
        param_name = result['parameter']
        status = result['status']
        reason = result['reason']
        vulnerabilities = result.get('vulnerabilities', [])
        
        # Color coding for status
        if status == 'VULNERABLE':
            status_color = f"{Fore.RED}VULNERABLE{Style.RESET_ALL}"
        elif status == 'POSSIBLY_VULNERABLE':
            status_color = f"{Fore.YELLOW}POSSIBLY VULNERABLE{Style.RESET_ALL}"
        elif status == 'FALSE_POSITIVE':
            status_color = f"{Fore.CYAN}FALSE POSITIVE{Style.RESET_ALL}"
        elif status == 'SAFE':
            status_color = f"{Fore.GREEN}SAFE{Style.RESET_ALL}"
        else:
            status_color = f"{Fore.MAGENTA}ERROR{Style.RESET_ALL}"
        
        print(f"\nParameter: {param_name}")
        print(f"Status: {status_color}")
        print(f"Reason: {reason}")
        
        if vulnerabilities:
            if status == 'FALSE_POSITIVE':
                print(f"\nFalse Positive Analysis:")
            else:
                print(f"\nVulnerabilities Found:")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                payload = vuln['payload']
                vuln_status = vuln['status']
                vuln_reason = vuln['reason']
                
                print(f"  {i}. Payload: {payload}")
                print(f"     Status: {vuln_status}")
                print(f"     Reason: {vuln_reason}")
        
        print("-" * 50)
        
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(f"\nParameter: {param_name}\n")
                f.write(f"Status: {status}\n")
                f.write(f"Reason: {reason}\n")
                
                if vulnerabilities:
                    if status == 'FALSE_POSITIVE':
                        f.write(f"False Positive Analysis:\n")
                    else:
                        f.write(f"Vulnerabilities Found:\n")
                    
                    for i, vuln in enumerate(vulnerabilities, 1):
                        f.write(f"  {i}. Payload: {vuln['payload']}\n")
                        f.write(f"     Status: {vuln['status']}\n")
                        f.write(f"     Reason: {vuln['reason']}\n")
                
                f.write("-" * 50 + "\n")
    
    def log_scan_summary(self, scan_results: Dict):
        """
        Log final scan summary
        
        Args:
            scan_results (dict): Complete scan results
        """
        url = scan_results.get('url', 'Unknown')
        method = scan_results.get('method', 'Unknown')
        overall_status = scan_results.get('status', 'UNKNOWN')
        total_params = scan_results.get('total_parameters', 0)
        vulnerable_params = scan_results.get('vulnerable_parameters', 0)
        false_positive_params = scan_results.get('false_positive_parameters', 0)
        results = scan_results.get('results', [])
        
        # Count vulnerabilities by severity
        vulnerable_count = sum(1 for r in results if r['status'] == 'VULNERABLE')
        possibly_vulnerable_count = sum(1 for r in results if r['status'] == 'POSSIBLY_VULNERABLE')
        false_positive_count = sum(1 for r in results if r['status'] == 'FALSE_POSITIVE')
        safe_count = sum(1 for r in results if r['status'] == 'SAFE')
        error_count = sum(1 for r in results if r['status'] == 'ERROR')
        
        print(f"\n{'='*60}")
        print(f"SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Target URL: {url}")
        print(f"Method: {method}")
        print(f"Overall Status: {self._get_status_display(overall_status)}")
        print(f"\nStatistics:")
        print(f"  Total Parameters: {total_params}")
        print(f"  Vulnerable Parameters: {vulnerable_count}")
        print(f"  Possibly Vulnerable: {possibly_vulnerable_count}")
        print(f"  False Positives: {false_positive_count}")
        print(f"  Safe Parameters: {safe_count}")
        print(f"  Errors: {error_count}")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        # Educational message for false positives
        if false_positive_count > 0:
            print(f"\n{Fore.CYAN}False Positive Analysis:{Style.RESET_ALL}")
            print(f"  {false_positive_count} parameter(s) detected as non-database endpoints")
            print(f"  Response differences are normal for APIs and static content")
            print(f"  This is expected behavior for non-database applications")
        
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"SCAN SUMMARY\n")
                f.write(f"{'='*60}\n")
                f.write(f"Target URL: {url}\n")
                f.write(f"Method: {method}\n")
                f.write(f"Overall Status: {overall_status}\n")
                f.write(f"\nStatistics:\n")
                f.write(f"  Total Parameters: {total_params}\n")
                f.write(f"  Vulnerable Parameters: {vulnerable_count}\n")
                f.write(f"  Possibly Vulnerable: {possibly_vulnerable_count}\n")
                f.write(f"  False Positives: {false_positive_count}\n")
                f.write(f"  Safe Parameters: {safe_count}\n")
                f.write(f"  Errors: {error_count}\n")
                f.write(f"{'='*60}\n")
    
    def save_report_json(self, scan_results: Dict, filename: str):
        """
        Save scan results as JSON report
        
        Args:
            scan_results (dict): Complete scan results
            filename (str): Output filename
        """
        # Add timestamp to report
        report = {
            'timestamp': datetime.datetime.now().isoformat(),
            'scan_results': scan_results
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}JSON report saved to: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}Error saving JSON report: {e}{Style.RESET_ALL}")
    
    def save_report_text(self, scan_results: Dict, filename: str):
        """
        Save scan results as text report
        
        Args:
            scan_results (dict): Complete scan results
            filename (str): Output filename
        """
        try:
            with open(filename, 'w') as f:
                f.write("SQL INJECTION SCAN REPORT\n")
                f.write("=" * 50 + "\n")
                f.write(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target URL: {scan_results.get('url', 'Unknown')}\n")
                f.write(f"Method: {scan_results.get('method', 'Unknown')}\n")
                f.write(f"Overall Status: {scan_results.get('status', 'UNKNOWN')}\n")
                f.write(f"Total Parameters: {scan_results.get('total_parameters', 0)}\n")
                f.write(f"Vulnerable Parameters: {scan_results.get('vulnerable_parameters', 0)}\n")
                f.write(f"False Positive Parameters: {scan_results.get('false_positive_parameters', 0)}\n\n")
                
                f.write("DETAILED RESULTS\n")
                f.write("-" * 50 + "\n")
                
                for result in scan_results.get('results', []):
                    f.write(f"\nParameter: {result['parameter']}\n")
                    f.write(f"Status: {result['status']}\n")
                    f.write(f"Reason: {result['reason']}\n")
                    
                    if result.get('vulnerabilities'):
                        if result['status'] == 'FALSE_POSITIVE':
                            f.write("False Positive Analysis:\n")
                        else:
                            f.write("Vulnerabilities Found:\n")
                        
                        for i, vuln in enumerate(result['vulnerabilities'], 1):
                            f.write(f"  {i}. Payload: {vuln['payload']}\n")
                            f.write(f"     Status: {vuln['status']}\n")
                            f.write(f"     Reason: {vuln['reason']}\n")
                    
                    f.write("-" * 30 + "\n")
            
            print(f"\n{Fore.GREEN}Text report saved to: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}Error saving text report: {e}{Style.RESET_ALL}")
    
    def _get_status_display(self, status: str) -> tuple[str, str]:
        """Get display color and message for status"""
        status_colors = {
            'SAFE': ('green', 'SAFE'),
            'VULNERABLE': ('red', 'VULNERABLE'),
            'POSSIBLY_VULNERABLE': ('yellow', 'POSSIBLY_VULNERABLE'),
            'FALSE_POSITIVE': ('cyan', 'FALSE_POSITIVE'),
            'NOT_REACHABLE': ('magenta', 'NOT_REACHABLE'),
            'NOT_TESTED': ('magenta', 'NOT_TESTED'),
            'INVALID_TARGET': ('red', 'BLOCKED'),
            'NO_PARAMETERS': ('blue', 'NO_PARAMETERS'),
            'ERROR': ('red', 'ERROR'),
            'UNKNOWN': ('blue', 'UNKNOWN')
        }
        return status_colors.get(status, ('white', status.upper()))
