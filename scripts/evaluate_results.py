#!/usr/bin/env python3
"""
Script to evaluate fuzzing results and generate comprehensive reports.
"""

import os
import sys
import argparse
import json
import glob
import pandas as pd
import matplotlib.pyplot as plt
from typing import Dict, List, Any, Optional, Tuple, Set

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.coverage_utils import analyze_coverage_from_file, plot_module_coverage
from utils.visualization import (
    parse_crash_logs, create_crash_summary_df, plot_crashes_over_time,
    plot_crashes_by_component, plot_crashes_by_exception,
    parse_fuzzing_stats, plot_fuzzing_progress, plot_bugs_by_type,
    plot_interactive_dashboard, generate_summary_report
)


def parse_arguments():
    """Parse command line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Evaluate LangChain fuzzing results")
    
    parser.add_argument(
        "--results-dir",
        type=str,
        default="results",
        help="Directory containing fuzzing results (default: results)"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to store evaluation results (default: <results-dir>/evaluation)"
    )
    
    parser.add_argument(
        "--coverage-file",
        type=str,
        default=None,
        help="JSON coverage data file (default: looks for coverage_*.json in results dir)"
    )
    
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Generate detailed reports"
    )
    
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Generate interactive HTML reports"
    )
    
    return parser.parse_args()


def find_coverage_file(results_dir: str) -> Optional[str]:
    """Find the latest coverage file in the results directory.
    
    Args:
        results_dir: Directory containing fuzzing results
        
    Returns:
        Path to the latest coverage file or None if not found
    """
    coverage_files = glob.glob(os.path.join(results_dir, "coverage_*.json"))
    
    if not coverage_files:
        return None
    
    # Sort by modification time (newest first)
    return sorted(coverage_files, key=os.path.getmtime, reverse=True)[0]


def find_crash_logs(results_dir: str) -> Dict[str, str]:
    """Find crash log files in the results directory.
    
    Args:
        results_dir: Directory containing fuzzing results
        
    Returns:
        Dictionary mapping harness names to crash log file paths
    """
    crash_logs = {}
    
    # Look for crash log files
    for root, _, files in os.walk(results_dir):
        for file in files:
            if file.endswith("_crashes.log"):
                harness_name = file.replace("_crashes.log", "")
                crash_logs[harness_name] = os.path.join(root, file)
    
    return crash_logs


def find_fuzzing_logs(results_dir: str) -> Dict[str, str]:
    """Find fuzzing log files in the results directory.
    
    Args:
        results_dir: Directory containing fuzzing results
        
    Returns:
        Dictionary mapping harness names to fuzzing log file paths
    """
    fuzzing_logs = {}
    
    # Look for fuzzing log files
    for root, _, files in os.walk(results_dir):
        for file in files:
            if file.endswith("_fuzzing.log"):
                harness_name = file.replace("_fuzzing.log", "")
                fuzzing_logs[harness_name] = os.path.join(root, file)
    
    return fuzzing_logs


def find_cve_results(results_dir: str) -> Optional[Dict[str, Dict[str, Any]]]:
    """Find CVE test results in the results directory.
    
    Args:
        results_dir: Directory containing fuzzing results
        
    Returns:
        Dictionary with CVE test results or None if not found
    """
    cve_summary_file = os.path.join(results_dir, "cve_summary.json")
    
    if not os.path.exists(cve_summary_file):
        return None
    
    with open(cve_summary_file, "r") as f:
        summary = json.load(f)
    
    # Expand with log content if available
    results = {}
    
    for cve_name, success in summary.items():
        log_file = os.path.join(results_dir, f"{cve_name}.log")
        
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                log_content = f.read()
        else:
            log_content = "Log file not found"
        
        results[cve_name] = {
            "success": success,
            "log_file": log_file,
            "log_content": log_content
        }
    
    return results


def analyze_unique_crashes(crash_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze unique crashes from crash data.
    
    Args:
        crash_data: List of crash data dictionaries
        
    Returns:
        Dictionary with unique crash analysis
    """
    if not crash_data:
        return {"count": 0, "types": {}, "components": {}}
    
    # Group by component and exception type
    crash_types = {}
    crash_components = {}
    
    for crash in crash_data:
        exception_type = crash.get("exception_type", "Unknown")
        component_name = crash.get("component_name", "Unknown")
        
        if exception_type not in crash_types:
            crash_types[exception_type] = 0
        crash_types[exception_type] += 1
        
        if component_name not in crash_components:
            crash_components[component_name] = 0
        crash_components[component_name] += 1
    
    return {
        "count": len(crash_data),
        "types": crash_types,
        "components": crash_components
    }


def analyze_vulnerability_types(fuzzing_stats: Dict[str, pd.DataFrame]) -> Dict[str, int]:
    """Analyze vulnerability types from fuzzing statistics.
    
    Args:
        fuzzing_stats: Dictionary mapping harness names to fuzzing statistics DataFrames
        
    Returns:
        Dictionary mapping vulnerability types to counts
    """
    vulnerability_counts = {
        "template_injections": 0,
        "path_traversal": 0,
        "resource_exhaustion": 0,
        "code_executions": 0
    }
    
    for harness, df in fuzzing_stats.items():
        if df.empty:
            continue
        
        # Get the last row which should have the final counts
        last_row = df.iloc[-1]
        
        for vuln_type in vulnerability_counts.keys():
            if vuln_type in last_row:
                vulnerability_counts[vuln_type] += last_row[vuln_type]
    
    return vulnerability_counts


def generate_detailed_evaluation(
    results_dir: str,
    output_dir: str,
    coverage_file: Optional[str],
    crash_logs: Dict[str, str],
    fuzzing_logs: Dict[str, str],
    cve_results: Optional[Dict[str, Dict[str, Any]]]
) -> Dict[str, Any]:
    """Generate detailed evaluation of fuzzing results.
    
    Args:
        results_dir: Directory containing fuzzing results
        output_dir: Directory to store evaluation results
        coverage_file: Path to the coverage file
        crash_logs: Dictionary mapping harness names to crash log file paths
        fuzzing_logs: Dictionary mapping harness names to fuzzing log file paths
        cve_results: Dictionary with CVE test results
        
    Returns:
        Dictionary with evaluation metrics
    """
    os.makedirs(output_dir, exist_ok=True)
    
    evaluation = {
        "coverage": {},
        "crashes": {},
        "vulnerabilities": {},
        "cve_tests": {}
    }
    
    # Analyze code coverage
    if coverage_file and os.path.exists(coverage_file):
        coverage_metrics = analyze_coverage_from_file(coverage_file)
        evaluation["coverage"] = coverage_metrics["overall"]
        
        # Plot module coverage
        coverage_plot_file = os.path.join(output_dir, "module_coverage.png")
        fig = plot_module_coverage(coverage_file)
        fig.savefig(coverage_plot_file)
        plt.close(fig)
        
        print(f"Coverage: {coverage_metrics['overall']['coverage'] * 100:.2f}% ({coverage_metrics['overall']['covered_lines']} / {coverage_metrics['overall']['total_lines']} lines)")
    
    # Analyze crashes
    all_crashes = []
    for harness, log_file in crash_logs.items():
        crashes = parse_crash_logs(log_file)
        evaluation["crashes"][harness] = analyze_unique_crashes(crashes)
        
        # Add harness name to each crash
        for crash in crashes:
            crash["harness"] = harness
            all_crashes.append(crash)
    
    crashes_df = create_crash_summary_df(all_crashes)
    
    # Count total crashes
    total_crashes = sum(data["count"] for data in evaluation["crashes"].values())
    print(f"Total crashes: {total_crashes}")
    
    # Analyze fuzzing statistics
    fuzzing_stats = {}
    for harness, log_file in fuzzing_logs.items():
        stats_df = parse_fuzzing_stats(log_file)
        fuzzing_stats[harness] = stats_df
    
    # Analyze vulnerability types
    vulnerability_counts = analyze_vulnerability_types(fuzzing_stats)
    evaluation["vulnerabilities"] = vulnerability_counts
    
    for vuln_type, count in vulnerability_counts.items():
        if count > 0:
            print(f"{vuln_type.replace('_', ' ').title()}: {count}")
    
    # Analyze CVE tests
    if cve_results:
        confirmed_cves = sum(1 for data in cve_results.values() if data["success"])
        total_cves = len(cve_results)
        evaluation["cve_tests"] = {
            "total": total_cves,
            "confirmed": confirmed_cves,
            "details": {name: data["success"] for name, data in cve_results.items()}
        }
        
        print(f"CVE tests: {confirmed_cves}/{total_cves} confirmed")
    
    # Save evaluation results
    evaluation_file = os.path.join(output_dir, "evaluation.json")
    with open(evaluation_file, "w") as f:
        json.dump(evaluation, f, indent=2)
    
    # Generate plots
    if not crashes_df.empty:
        # Crashes over time
        fig = plot_crashes_over_time(crashes_df)
        fig.savefig(os.path.join(output_dir, "crashes_over_time.png"))
        plt.close(fig)
        
        # Crashes by component
        if "component_name" in crashes_df.columns:
            fig = plot_crashes_by_component(crashes_df)
            fig.savefig(os.path.join(output_dir, "crashes_by_component.png"))
            plt.close(fig)
        
        # Crashes by exception
        if "exception_type" in crashes_df.columns:
            fig = plot_crashes_by_exception(crashes_df)
            fig.savefig(os.path.join(output_dir, "crashes_by_exception.png"))
            plt.close(fig)
    
    # Generate interactive dashboard
    if not crashes_df.empty and fuzzing_stats:
        # Use the first harness for the dashboard
        first_harness = list(fuzzing_stats.keys())[0]
        stats_df = fuzzing_stats[first_harness]
        
        dashboard = plot_interactive_dashboard(stats_df, crashes_df)
        dashboard_file = os.path.join(output_dir, "dashboard.html")
        
        with open(dashboard_file, "w") as f:
            f.write(dashboard.to_html(include_plotlyjs=True, full_html=True))
        
        print(f"Interactive dashboard saved to {dashboard_file}")
    
    # Generate summary report
    if fuzzing_stats:
        # Use the first harness for the report
        first_harness = list(fuzzing_stats.keys())[0]
        stats_df = fuzzing_stats[first_harness]
        
        report_file = generate_summary_report(
            stats_df, 
            crashes_df, 
            output_dir, 
            include_cve_results=bool(cve_results),
            cve_results=cve_results
        )
        print(f"Summary report saved to {report_file}")
    
    return evaluation


def generate_summary_evaluation(
    results_dir: str,
    output_dir: str,
    coverage_file: Optional[str],
    crash_logs: Dict[str, str],
    fuzzing_logs: Dict[str, str],
    cve_results: Optional[Dict[str, Dict[str, Any]]]
) -> Dict[str, Any]:
    """Generate summary evaluation of fuzzing results.
    
    Args:
        results_dir: Directory containing fuzzing results
        output_dir: Directory to store evaluation results
        coverage_file: Path to the coverage file
        crash_logs: Dictionary mapping harness names to crash log file paths
        fuzzing_logs: Dictionary mapping harness names to fuzzing log file paths
        cve_results: Dictionary with CVE test results
        
    Returns:
        Dictionary with evaluation metrics
    """
    os.makedirs(output_dir, exist_ok=True)
    
    evaluation = {
        "coverage": {},
        "crashes": {},
        "vulnerabilities": {},
        "cve_tests": {}
    }
    
    # Quick coverage analysis
    if coverage_file and os.path.exists(coverage_file):
        coverage_metrics = analyze_coverage_from_file(coverage_file)
        evaluation["coverage"] = coverage_metrics["overall"]
        
        print(f"Coverage: {coverage_metrics['overall']['coverage'] * 100:.2f}% ({coverage_metrics['overall']['covered_lines']} / {coverage_metrics['overall']['total_lines']} lines)")
    
    # Count crashes
    total_crashes = 0
    for harness, log_file in crash_logs.items():
        crashes = parse_crash_logs(log_file)
        crash_count = len(crashes)
        evaluation["crashes"][harness] = {"count": crash_count}
        total_crashes += crash_count
    
    print(f"Total crashes: {total_crashes}")
    
    # Count fuzzing runs
    total_runs = 0
    for harness, log_file in fuzzing_logs.items():
        stats_df = parse_fuzzing_stats(log_file)
        if not stats_df.empty and "runs" in stats_df.columns:
            runs = stats_df["runs"].iloc[-1]
            evaluation[harness] = {"runs": runs}
            total_runs += runs
    
    if total_runs > 0:
        print(f"Total fuzzing runs: {total_runs}")
    
    # Analyze CVE tests
    if cve_results:
        confirmed_cves = sum(1 for data in cve_results.values() if data["success"])
        total_cves = len(cve_results)
        evaluation["cve_tests"] = {
            "total": total_cves,
            "confirmed": confirmed_cves,
            "details": {name: data["success"] for name, data in cve_results.items()}
        }
        
        print(f"CVE tests: {confirmed_cves}/{total_cves} confirmed")
    
    # Save evaluation results
    evaluation_file = os.path.join(output_dir, "evaluation_summary.json")
    with open(evaluation_file, "w") as f:
        json.dump(evaluation, f, indent=2)
    
    return evaluation


def main():
    """Main function to evaluate fuzzing results."""
    args = parse_arguments()
    
    # Set output directory
    if args.output_dir is None:
        args.output_dir = os.path.join(args.results_dir, "evaluation")
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Find coverage file if not specified
    coverage_file = args.coverage_file
    if coverage_file is None:
        coverage_file = find_coverage_file(args.results_dir)
        if coverage_file:
            print(f"Found coverage file: {coverage_file}")
        else:
            print("No coverage file found")
    
    # Find crash logs
    crash_logs = find_crash_logs(args.results_dir)
    if crash_logs:
        print(f"Found crash logs for {len(crash_logs)} harnesses")
    else:
        print("No crash logs found")
    
    # Find fuzzing logs
    fuzzing_logs = find_fuzzing_logs(args.results_dir)
    if fuzzing_logs:
        print(f"Found fuzzing logs for {len(fuzzing_logs)} harnesses")
    else:
        print("No fuzzing logs found")
    
    # Find CVE test results
    cve_results = find_cve_results(args.results_dir)
    if cve_results:
        print(f"Found results for {len(cve_results)} CVE tests")
    else:
        print("No CVE test results found")
    
    # Generate evaluation
    if args.detailed:
        print("\nGenerating detailed evaluation...")
        evaluation = generate_detailed_evaluation(
            args.results_dir,
            args.output_dir,
            coverage_file,
            crash_logs,
            fuzzing_logs,
            cve_results
        )
    else:
        print("\nGenerating summary evaluation...")
        evaluation = generate_summary_evaluation(
            args.results_dir,
            args.output_dir,
            coverage_file,
            crash_logs,
            fuzzing_logs,
            cve_results
        )
    
    # Generate interactive HTML report
    if args.interactive:
        print("\nGenerating interactive HTML report...")
        
        # Gather all crashes
        all_crashes = []
        for harness, log_file in crash_logs.items():
            crashes = parse_crash_logs(log_file)
            for crash in crashes:
                crash["harness"] = harness
                all_crashes.append(crash)
        
        crashes_df = create_crash_summary_df(all_crashes)
        
        # Use the first harness for fuzzing stats
        stats_df = pd.DataFrame()
        if fuzzing_logs:
            first_harness = list(fuzzing_logs.keys())[0]
            stats_df = parse_fuzzing_stats(fuzzing_logs[first_harness])
        
        # Generate the report
        report_file = generate_summary_report(
            stats_df, 
            crashes_df, 
            args.output_dir, 
            include_cve_results=bool(cve_results),
            cve_results=cve_results
        )
        print(f"Interactive HTML report saved to {report_file}")
    
    print("\nEvaluation completed successfully!")


if __name__ == "__main__":
    main()