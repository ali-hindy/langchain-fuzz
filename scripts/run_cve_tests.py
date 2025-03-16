#!/usr/bin/env python3
"""
Script to run CVE tests for known LangChain vulnerabilities.
"""

import os
import sys
import argparse
import subprocess
import json
import time
from typing import Dict, List, Any, Optional, Tuple

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.visualization import generate_summary_report


def parse_arguments():
    """Parse command line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Run LangChain CVE tests")
    
    parser.add_argument(
        "--cves", 
        nargs="+",
        choices=["36258", "44467", "46229", "all"],
        default=["all"],
        help="CVEs to test (default: all)"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default="results",
        help="Directory to store results (default: results)"
    )
    
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate a summary report after testing"
    )
    
    return parser.parse_args()


def get_cve_list(selected_cves: List[str]) -> List[str]:
    """Get list of CVE tests to run.
    
    Args:
        selected_cves: List of selected CVEs
        
    Returns:
        List of CVE test file paths
    """
    all_cves = {
        "36258": "cve_2023_36258.py",  # PALChain code execution
        "44467": "cve_2023_44467.py",  # Code execution via __import__
        "46229": "cve_2023_46229.py",  # SSRF in recursive URL loader
    }
    
    if "all" in selected_cves:
        cves = list(all_cves.values())
    else:
        cves = [all_cves[c] for c in selected_cves if c in all_cves]
    
    # Get absolute paths
    cve_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cve_tests")
    cve_paths = [os.path.join(cve_dir, c) for c in cves]
    
    return cve_paths


def run_cve_test(cve_path: str, output_dir: str) -> Tuple[bool, str]:
    """Run a single CVE test.
    
    Args:
        cve_path: Path to the CVE test file
        output_dir: Directory to store results
        
    Returns:
        Tuple of (success, log)
    """
    cve_name = os.path.basename(cve_path).replace(".py", "")
    print(f"Testing {cve_name}...")
    
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, f"{cve_name}.log")
    
    # Run the test
    start_time = time.time()
    
    try:
        result = subprocess.run(
            [sys.executable, cve_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=300  # 5 minutes timeout
        )
        
        # Write to log file
        with open(log_file, "w") as f:
            f.write(result.stdout)
        
        # Check if test was successful
        success = "VULNERABILITY CONFIRMED" in result.stdout
    except subprocess.TimeoutExpired as e:
        # Handle timeout
        with open(log_file, "w") as f:
            f.write(f"Test timed out after 300 seconds\n")
            if hasattr(e, 'stdout') and e.stdout:
                f.write(e.stdout)
        
        success = False
    except Exception as e:
        # Handle other errors
        with open(log_file, "w") as f:
            f.write(f"Error running test: {str(e)}\n")
        
        success = False
    
    elapsed_time = time.time() - start_time
    
    # Print result
    if success:
        print(f"✅ {cve_name} confirmed (in {elapsed_time:.2f}s)")
    else:
        print(f"❌ {cve_name} not confirmed (in {elapsed_time:.2f}s)")
    
    return success, log_file


def run_all_cve_tests(cve_paths: List[str], output_dir: str) -> Dict[str, Dict[str, Any]]:
    """Run all CVE tests.
    
    Args:
        cve_paths: List of CVE test file paths
        output_dir: Directory to store results
        
    Returns:
        Dictionary with results for each CVE
    """
    results = {}
    
    for cve_path in cve_paths:
        cve_name = os.path.basename(cve_path).replace(".py", "")
        success, log_file = run_cve_test(cve_path, output_dir)
        
        # Read log content
        try:
            with open(log_file, "r") as f:
                log_content = f.read()
        except:
            log_content = "Failed to read log file"
        
        results[cve_name] = {
            "success": success,
            "log_file": log_file,
            "log_content": log_content
        }
    
    return results


def save_results_json(results: Dict[str, Dict[str, Any]], output_dir: str):
    """Save results to a JSON file.
    
    Args:
        results: Dictionary with results for each CVE
        output_dir: Directory to store results
    """
    # Create a simplified version with just success status
    summary = {cve: result["success"] for cve, result in results.items()}
    
    # Save to file
    summary_file = os.path.join(output_dir, "cve_summary.json")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"Results saved to {summary_file}")


def generate_html_report(results: Dict[str, Dict[str, Any]], output_dir: str):
    """Generate an HTML report of CVE test results.
    
    Args:
        results: Dictionary with results for each CVE
        output_dir: Directory to store results
    """
    # Create HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>LangChain CVE Test Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                line-height: 1.6;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            h1, h2, h3 {{
                color: #333;
            }}
            hr {{
                border: 0;
                border-top: 1px solid #eee;
                margin: 20px 0;
            }}
            .success {{
                color: #4CAF50;
                font-weight: bold;
            }}
            .failure {{
                color: #F44336;
                font-weight: bold;
            }}
            .cve-card {{
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 15px;
                margin-bottom: 20px;
            }}
            .cve-header {{
                margin-top: 0;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .log-content {{
                background-color: #f5f5f5;
                padding: 10px;
                border-radius: 4px;
                overflow-x: auto;
                white-space: pre-wrap;
                font-family: monospace;
                max-height: 300px;
                overflow-y: auto;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>LangChain CVE Test Report</h1>
            <p>
                This report presents the results of testing LangChain for 
                known vulnerabilities (CVEs).
            </p>
            
            <h2>Summary</h2>
            <p>
                CVEs Tested: {len(results)}<br>
                Vulnerabilities Confirmed: {sum(1 for r in results.values() if r["success"])}<br>
                Tests Failed: {sum(1 for r in results.values() if not r["success"])}
            </p>
            
            <hr>
            
            <h2>Test Results</h2>
    """
    
    # Add results for each CVE
    cve_descriptions = {
        "cve_2023_36258": "Arbitrary code execution in PALChain via exec()",
        "cve_2023_44467": "Bypass of prior fix allowing arbitrary code via __import__",
        "cve_2023_46229": "SSRF in recursive URL loader"
    }
    
    cve_advisories = {
        "cve_2023_36258": "GHSA-gjjr-63x4-v8cq",
        "cve_2023_44467": "GHSA-gjjr-63x4-v8cq",
        "cve_2023_46229": "GHSA-655w-fm8m-m478"
    }
    
    for cve_name, result in results.items():
        success = result["success"]
        status_class = "success" if success else "failure"
        status_text = "CONFIRMED" if success else "NOT CONFIRMED"
        
        description = cve_descriptions.get(cve_name, "No description available")
        advisory = cve_advisories.get(cve_name, "Unknown")
        
        html_content += f"""
            <div class="cve-card">
                <div class="cve-header">
                    <h3>{cve_name}</h3>
                    <span class="{status_class}">{status_text}</span>
                </div>
                <p><strong>Description:</strong> {description}</p>
                <p><strong>GitHub Advisory:</strong> {advisory}</p>
                <h4>Log Output</h4>
                <div class="log-content">{result["log_content"]}</div>
            </div>
        """
    
    # Close HTML
    html_content += """
        </div>
    </body>
    </html>
    """
    
    # Write to file
    report_file = os.path.join(output_dir, "cve_report.html")
    with open(report_file, "w") as f:
        f.write(html_content)
    
    print(f"HTML report saved to {report_file}")


def main():
    """Main function to run CVE tests."""
    args = parse_arguments()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Get list of CVE tests to run
    cve_paths = get_cve_list(args.cves)
    
    if not cve_paths:
        print("No CVE tests selected.")
        return
    
    print(f"Running {len(cve_paths)} CVE tests...")
    
    # Run all tests
    results = run_all_cve_tests(cve_paths, args.output_dir)
    
    # Save results
    save_results_json(results, args.output_dir)
    
    # Generate HTML report
    generate_html_report(results, args.output_dir)
    
    # Generate summary report if requested
    if args.report:
        # Call the visualization module's report generator
        # We're passing empty DataFrames since CVE tests don't use them
        import pandas as pd
        empty_df = pd.DataFrame()
        generate_summary_report(empty_df, empty_df, args.output_dir, include_cve_results=True, cve_results=results)
    
    # Print final summary
    successes = sum(1 for r in results.values() if r["success"])
    print(f"\nSummary: {successes}/{len(results)} vulnerabilities confirmed")
    
    # Exit with non-zero status if any test failed
    if successes < len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()