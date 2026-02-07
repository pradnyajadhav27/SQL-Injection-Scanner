"""
SQL Injection Scanner - Main Entry Point
Educational and Authorized Testing Only

Author: Senior Cyber Security Engineer
Version: 1.0
Purpose: Educational SQL Injection Detection Tool
"""

import argparse
import sys
import os
import time
from scanner import SQLInjectionScanner
from logger import ScanLogger
from payloads import get_payloads, get_categories
from utils import (
    validate_url, validate_target_for_testing, print_banner, print_help, 
    check_dependencies
)

def main():
    """
    Main function - entry point for the SQL Injection Scanner
    """
    # Print banner with legal disclaimer
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='SQL Injection Scanner - Educational & Authorized Testing Only',
        add_help=False
    )
    
    # Required arguments
    parser.add_argument('url', nargs='?', help='Target URL to scan')
    
    # Optional arguments
    parser.add_argument('--method', choices=['GET', 'POST'], default='GET',
                       help='HTTP method (default: GET)')
    parser.add_argument('--data', help='POST data (key1=value1&key2=value2)')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--threads', type=int, default=5,
                       help='Number of concurrent threads (default: 5)')
    parser.add_argument('--payloads', choices=get_categories() + ['all'],
                       default='all', help='Payload category to use (default: all)')
    parser.add_argument('--output-json', help='Save results as JSON report')
    parser.add_argument('--output-text', help='Save results as text report')
    parser.add_argument('--log', help='Log scan activity to file')
    parser.add_argument('--help', '-h', action='store_true', help='Show help information')
    
    args = parser.parse_args()
    
    # Show help if requested
    if args.help or not args.url:
        print_help()
        sys.exit(0)
    
    # Validate URL format
    if not validate_url(args.url):
        print(f"Invalid URL: {args.url}")
        print("Please provide a valid URL including protocol (http:// or https://)")
        sys.exit(1)
    
    # CRITICAL: Validate target for educational testing only
    is_valid, validation_reason = validate_target_for_testing(args.url)
    if not is_valid:
        print(f"\nTARGET VALIDATION FAILED:")
        print(f"[!] {validation_reason}")
        print(f"\nThis scanner is for EDUCATIONAL PURPOSES ONLY.")
        print(f"Allowed targets:")
        print(f"[+] Localhost (127.0.0.1, localhost)")
        print(f"[+] Private networks (192.168.x.x, 10.x.x.x)")
        print(f"[+] Educational labs (DVWA, Juice Shop, WebGoat)")
        print(f"[+] Systems you own or have explicit permission")
        print(f"\nSTRICTLY PROHIBITED:")
        print(f"[x] Public websites and production systems")
        print(f"[x] API services (httpbin.org, reqres.in, etc.)")
        print(f"[x] Any unauthorized testing")
        sys.exit(1)
    
    # Parse POST data if provided
    post_data = None
    if args.method == 'POST':
        if args.data:
            from utils import parse_post_data
            post_data = parse_post_data(args.data)
        else:
            print("Warning: POST method specified but no data provided.")
            print("Use --data to specify POST parameters (e.g., --data \"username=admin&password=test\")")
            
            # Try to proceed with empty POST data
            post_data = {}
    
    # Get payloads based on category
    if args.payloads == 'all':
        payloads = get_payloads()
    else:
        payloads = get_payloads(args.payloads)
    
    print(f"\nSCAN CONFIGURATION:")
    print(f"   Target URL: {args.url}")
    print(f"   Method: {args.method}")
    print(f"   Payloads: {len(payloads)} ({args.payloads})")
    print(f"   Delay: {args.delay}s")
    print(f"   Timeout: {args.timeout}s")
    print(f"   Threads: {args.threads}")
    
    if post_data:
        print(f"   POST Data: {post_data}")
    
    # Safety confirmation
    print(f"\nSAFETY CONFIRMATION:")
    print(f"   Target validated for educational testing")
    print(f"   This is a DETECTION tool - NOT an exploitation tool")
    print(f"   Starting scan in 3 seconds...")
    
    time.sleep(3)
    
    # Initialize scanner and logger
    scanner = SQLInjectionScanner(
        delay=args.delay,
        timeout=args.timeout,
        max_workers=args.threads
    )
    
    logger = ScanLogger(log_file=args.log)
    
    try:
        # Log scan start
        if args.method == 'GET':
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(args.url)
            parameters = list(parse_qs(parsed_url.query).keys())
        else:
            parameters = list(post_data.keys()) if post_data else []
        
        logger.log_scan_start(args.url, args.method, parameters)
        
        # Perform scan
        print(f"\nStarting scan...")
        scan_results = scanner.scan_url(
            url=args.url,
            method=args.method,
            post_data=post_data,
            payloads=payloads
        )
        
        # Handle invalid target
        if scan_results['status'] == 'INVALID_TARGET':
            print(f"\nTARGET REJECTED:")
            print(f"[!] {scan_results['reason']}")
            print(f"\nThis scanner only works on authorized educational targets.")
            sys.exit(1)
        
        # Log results for each parameter
        for result in scan_results['results']:
            logger.log_parameter_result(result)
        
        # Log summary
        logger.log_scan_summary(scan_results)
        
        # Save reports if requested
        if args.output_json:
            logger.save_report_json(scan_results, args.output_json)
        
        if args.output_text:
            logger.save_report_text(scan_results, args.output_text)
        
        # Final status message
        overall_status = scan_results.get('status', 'UNKNOWN')
        if overall_status == 'VULNERABLE':
            print(f"\n\033[91m{overall_status}: SQL injection vulnerabilities detected!\033[0m")
            print("   Please review the detailed results above and take appropriate action.")
            print("   This is an educational finding - do not exploit!")
        elif overall_status == 'POSSIBLY_VULNERABLE':
            print(f"\n\033[93m{overall_status}: Potential SQL injection vulnerabilities detected.\033[0m")
            print("   Manual verification recommended.")
        elif overall_status == 'FALSE_POSITIVE':
            print(f"\n\033[96m{overall_status}: Non-database endpoint detected.\033[0m")
            print("   Response differences are normal for APIs and static content.")
        elif overall_status == 'SAFE':
            print(f"\n\033[92m{overall_status}: No SQL injection vulnerabilities detected.\033[0m")
            print("   Application appears secure against tested payloads.")
        elif overall_status == 'NOT_REACHABLE':
            print(f"\n\033[95m{overall_status}: Target application is not running or accessible.\033[0m")
            print("   Please start the server and verify the target URL.")
        elif overall_status == 'INVALID_TARGET':
            print(f"\n\033[91m{overall_status}: Unauthorized target - testing blocked.\033[0m")
            print("   Only localhost and private networks are allowed.")
        else:
            print(f"\nStatus: {overall_status} - Check details above.")
        
    except KeyboardInterrupt:
        print(f"\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
