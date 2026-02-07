"""
Simple SQL Injection Scanner - Minimal Output
Educational Tool Only
"""

import argparse
import sys
import time
from scanner import SQLInjectionScanner
from logger import ScanLogger
from payloads import get_payloads
from utils import validate_url, validate_target_for_testing, check_dependencies

def main():
    # Quick dependency check
    if not check_dependencies():
        print("Missing required packages. Run: pip install -r requirements.txt")
        sys.exit(1)
    
    # Parse arguments
    parser = argparse.ArgumentParser(description='Simple SQL Injection Scanner')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--method', default='GET', help='HTTP method')
    parser.add_argument('--data', help='POST data')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests')
    parser.add_argument('--threads', type=int, default=3, help='Number of threads')
    parser.add_argument('--output', help='Save results to file')
    
    args = parser.parse_args()
    
    # Validate URL
    if not validate_url(args.url):
        print("Invalid URL")
        sys.exit(1)
    
    # Check if target is allowed
    is_valid, reason = validate_target_for_testing(args.url)
    if not is_valid:
        print(f"{reason}")
        print("Only localhost and private networks allowed")
        sys.exit(1)
    
    # Parse POST data
    post_data = None
    if args.method == 'POST' and args.data:
        from utils import parse_post_data
        post_data = parse_post_data(args.data)
    
    # Show simple config
    print(f"Target: {args.url}")
    print(f"Method: {args.method}")
    print(f"Delay: {args.delay}s")
    print(f"Threads: {args.threads}")
    
    # Start scan
    scanner = SQLInjectionScanner(delay=args.delay, max_workers=args.threads)
    payloads = get_payloads()
    
    print(f"\nScanning {len(payloads)} payloads...")
    print("Please wait...\n")
    
    try:
        # Run scan
        results = scanner.scan_url(args.url, args.method, post_data, payloads)
        
        # Show results
        print("=" * 50)
        print("SCAN RESULTS")
        print("=" * 50)
        
        total_params = results.get('total_parameters', 0)
        vulnerable_count = results.get('vulnerable_parameters', 0)
        false_positive_count = results.get('false_positive_parameters', 0)
        
        print(f"Total Parameters: {total_params}")
        print(f"Vulnerable: {vulnerable_count}")
        print(f"False Positives: {false_positive_count}")
        
        # Show parameter details
        for result in results.get('results', []):
            param = result.get('parameter', 'unknown')
            status = result.get('status', 'UNKNOWN')
            
            if status == 'VULNERABLE':
                print(f"\n{param}: \033[91mVULNERABLE\033[0m")
                vulnerabilities = result.get('vulnerabilities', [])
                print(f"   Found {len(vulnerabilities)} issues")
            elif status == 'FALSE_POSITIVE':
                print(f"\n{param}: \033[96mFALSE_POSITIVE\033[0m")
                print(f"   Not a database endpoint")
            elif status == 'SAFE':
                print(f"\n{param}: \033[92mSAFE\033[0m")
            elif status == 'NOT_REACHABLE':
                print(f"\n{param}: \033[95mNOT_REACHABLE\033[0m")
                print(f"   Target not accessible")
            elif status == 'NOT_TESTED':
                print(f"\n{param}: \033[95mNOT_TESTED\033[0m")
                print(f"   All requests failed")
            else:
                print(f"\n{param}: {status}")
        
        # Overall status
        overall = results.get('status', 'UNKNOWN')
        
        if overall == 'VULNERABLE':
            print(f"\nOverall Status: \033[91mVULNERABLE\033[0m")
            print("SQL Injection found! Fix needed.")
        elif overall == 'POSSIBLY_VULNERABLE':
            print(f"\nOverall Status: \033[93mPOSSIBLY_VULNERABLE\033[0m")
            print("Potential SQL Injection found. Manual verification needed.")
        elif overall == 'FALSE_POSITIVE':
            print(f"\nOverall Status: \033[96mFALSE_POSITIVE\033[0m")
            print("Not a database - normal behavior.")
        elif overall == 'NOT_REACHABLE':
            print(f"\nOverall Status: \033[95mNOT_REACHABLE\033[0m")
            print("Target not running or accessible. Start server and retry.")
        elif overall == 'INVALID_TARGET':
            print(f"\nOverall Status: \033[91mBLOCKED\033[0m")
            print("Unauthorized target - testing blocked.")
        elif overall == 'SAFE':
            print(f"\nOverall Status: \033[92mSAFE\033[0m")
            print("No SQL Injection detected.")
        else:
            print(f"\nOverall Status: {overall} - Check details above.")
        
        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"SQL Injection Scan Results\n")
                f.write(f"Target: {args.url}\n")
                f.write(f"Status: {overall}\n")
                f.write(f"Parameters: {total_params}\n")
                f.write(f"Vulnerable: {vulnerable_count}\n")
                f.write(f"False Positives: {false_positive_count}\n")
            print(f"Results saved to: {args.output}")
        
        print(f"\nUse parameterized queries to prevent SQL injection!")
        
    except KeyboardInterrupt:
        print("\nScan stopped by user")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()
