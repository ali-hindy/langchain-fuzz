#!/usr/bin/env python3
"""
Script to run all fuzzing harnesses sequentially or in parallel.
"""

import os
import sys
import time
import argparse
import subprocess
import multiprocessing
from typing import List, Dict, Any, Optional, Tuple
import json
import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.coverage_utils import setup_coverage_tracking, save_coverage_data
from utils.visualization import (
    parse_crash_logs, create_crash_summary_df, plot_crashes_over_time,
    plot_crashes_by_component, plot_crashes_by_exception,
    parse_fuzzing_stats, plot_fuzzing_progress, plot_bugs_by_type,
    generate_summary_report
)


def parse_arguments():
    """Parse command line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Run LangChain fuzzing harnesses")
    
    parser.add_argument(
        "--harnesses", 
        nargs="+",
        choices=["prompt", "document", "chain", "agent", "all"],
        default=["all"],
        help="Harnesses to run (default: all)"
    )
    
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run harnesses in parallel"
    )
    
    parser.add_argument(
        "--time",
        type=int,
        default=3600,
        help="Time to run each harness in seconds (default: 3600)"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default="results",
        help="Directory to store results (default: results)"
    )
    
    parser.add_argument(
        "--track-coverage",
        action="store_true",
        help="Track code coverage during fuzzing"
    )
    
    parser.add_argument(
        "--seeds-dir",
        type=str,
        default="seeds",
        help="Directory containing seed corpora (default: seeds)"
    )
    
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate a summary report after fuzzing"
    )
    
    return parser.parse_args()


def get_harness_list(selected_harnesses: List[str]) -> List[str]:
    """Get list of harnesses to run.
    
    Args:
        selected_harnesses: List of selected harnesses
        
    Returns:
        List of harness file paths
    """
    all_harnesses = {
        "prompt": "prompt_template_harness.py",
        "document": "document_loader_harness.py",
        "chain": "chain_harness.py",
        "agent": "agent_harness.py"
    }
    
    if "all" in selected_harnesses:
        harnesses = list(all_harnesses.values())
    else:
        harnesses = [all_harnesses[h] for h in selected_harnesses if h in all_harnesses]
    
    # Get absolute paths
    harness_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "harnesses")
    harness_paths = [os.path.join(harness_dir, h) for h in harnesses]
    
    return harness_paths


def run_harness(
    harness_path: str, 
    timeout: int, 
    output_dir: str,
    log_file: Optional[str] = None,
    seeds_dir: Optional[str] = None
) -> subprocess.CompletedProcess:
    """Run a single harness.
    
    Args:
        harness_path: Path to the harness file
        timeout: Time to run the harness in seconds
        output_dir: Directory to store results
        log_file: Path to write logs (if None, outputs to console)
        seeds_dir: Directory containing seed corpus for this harness
        
    Returns:
        Completed process
    """
    harness_name = os.path.basename(harness_path).replace("_harness.py", "")
    print(f"Starting {harness_name} harness...")
    
    # Create command arguments
    cmd = [
        sys.executable,
        harness_path,
        "-max_total_time=" + str(timeout)
    ]
    
    # Add seed corpus if provided
    if seeds_dir:
        harness_seeds_dir = os.path.join(seeds_dir, f"{harness_name}_seeds")
        if os.path.exists(harness_seeds_dir):
            cmd.append("-artifact_prefix=" + harness_seeds_dir)
    
    # Run the harness
    if log_file:
        with open(log_file, "w") as f:
            process = subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=timeout + 60  # Add a small buffer to the timeout
            )
    else:
        process = subprocess.run(
            cmd,
            text=True,
            check=False,
            timeout=timeout + 60  # Add a small buffer to the timeout
        )
    
    print(f"Finished {harness_name} harness with return code {process.returncode}")
    return process


def run_harnesses_sequential(
    harness_paths: List[str], 
    timeout: int, 
    output_dir: str,
    seeds_dir: Optional[str] = None
) -> Dict[str, subprocess.CompletedProcess]:
    """Run harnesses sequentially.
    
    Args:
        harness_paths: List of harness file paths
        timeout: Time to run each harness in seconds
        output_dir: Directory to store results
        seeds_dir: Directory containing seed corpora
        
    Returns:
        Dictionary mapping harness names to completed processes
    """
    os.makedirs(output_dir, exist_ok=True)
    
    results = {}
    
    for harness_path in harness_paths:
        harness_name = os.path.basename(harness_path).replace("_harness.py", "")
        log_file = os.path.join(output_dir, f"{harness_name}_fuzzing.log")
        
        start_time = time.time()
        process = run_harness(harness_path, timeout, output_dir, log_file, seeds_dir)
        end_time = time.time()
        
        elapsed_time = end_time - start_time
        print(f"{harness_name} harness ran for {elapsed_time:.2f} seconds")
        
        results[harness_name] = process
    
    return results


def run_harness_worker(args: Tuple[str, int, str, str, Optional[str]]) -> Tuple[str, subprocess.CompletedProcess]:
    """Worker function for parallel harness execution.
    
    Args:
        args: Tuple of (harness_path, timeout, output_dir, log_file, seeds_dir)
        
    Returns:
        Tuple of (harness_name, completed_process)
    """
    harness_path, timeout, output_dir, log_file, seeds_dir = args
    harness_name = os.path.basename(harness_path).replace("_harness.py", "")
    
    start_time = time.time()
    process = run_harness(harness_path, timeout, output_dir, log_file, seeds_dir)
    end_time = time.time()
    
    elapsed_time = end_time - start_time
    print(f"{harness_name} harness ran for {elapsed_time:.2f} seconds")
    
    return harness_name, process


def run_harnesses_parallel(
    harness_paths: List[str], 
    timeout: int, 
    output_dir: str,
    seeds_dir: Optional[str] = None
) -> Dict[str, subprocess.CompletedProcess]:
    """Run harnesses in parallel.
    
    Args:
        harness_paths: List of harness file paths
        timeout: Time to run each harness in seconds
        output_dir: Directory to store results
        seeds_dir: Directory containing seed corpora
        
    Returns:
        Dictionary mapping harness names to completed processes
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Prepare arguments for each worker
    worker_args = []
    for harness_path in harness_paths:
        harness_name = os.path.basename(harness_path).replace("_harness.py", "")
        log_file = os.path.join(output_dir, f"{harness_name}_fuzzing.log")
        worker_args.append((harness_path, timeout, output_dir, log_file, seeds_dir))
    
    # Run harnesses in parallel
    with multiprocessing.Pool(processes=min(len(harness_paths), multiprocessing.cpu_count())) as pool:
        results = dict(pool.map(run_harness_worker, worker_args))
    
    return results


def collect_crash_logs(output_dir: str) -> Dict[str, List[Dict[str, Any]]]:
    """Collect crash logs from all harnesses.
    
    Args:
        output_dir: Directory containing results
        
    Returns:
        Dictionary mapping harness names to lists of crash data
    """
    crash_logs = {}
    
    # Look for crash log files
    for root, _, files in os.walk(output_dir):
        for file in files:
            if file.endswith("_crashes.log"):
                harness_name = file.replace("_crashes.log", "")
                crash_log_path = os.path.join(root, file)
                crash_logs[harness_name] = parse_crash_logs(crash_log_path)
    
    return crash_logs


def collect_fuzzing_stats(output_dir: str) -> Dict[str, Any]:
    """Collect fuzzing statistics from log files.
    
    Args:
        output_dir: Directory containing results
        
    Returns:
        Dictionary mapping harness names to fuzzing statistics DataFrames
    """
    fuzzing_stats = {}
    
    # Look for fuzzing log files
    for root, _, files in os.walk(output_dir):
        for file in files:
            if file.endswith("_fuzzing.log"):
                harness_name = file.replace("_fuzzing.log", "")
                log_file_path = os.path.join(root, file)
                fuzzing_stats[harness_name] = parse_fuzzing_stats(log_file_path)
    
    return fuzzing_stats


def save_summary_data(output_dir: str, crash_logs: Dict[str, List[Dict[str, Any]]], fuzzing_stats: Dict[str, Any]):
    """Save summary data to JSON file.
    
    Args:
        output_dir: Directory to store results
        crash_logs: Dictionary of crash logs
        fuzzing_stats: Dictionary of fuzzing statistics
    """
    os.makedirs(output_dir, exist_ok=True)
    
    summary = {
        "timestamp": datetime.datetime.now().isoformat(),
        "crashes": {
            harness: len(logs) for harness, logs in crash_logs.items()
        },
        "fuzzing_stats": {
            harness: {
                "runs": df["runs"].iloc[-1] if not df.empty and "runs" in df.columns else 0,
                "crashes": df["crashes"].iloc[-1] if not df.empty and "crashes" in df.columns else 0,
                "runs_per_second": df["runs_per_second"].iloc[-1] if not df.empty and "runs_per_second" in df.columns else 0,
            } for harness, df in fuzzing_stats.items()
        }
    }
    
    summary_file = os.path.join(output_dir, "fuzzing_summary.json")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"Summary data saved to {summary_file}")


def generate_plots(output_dir: str, crash_logs: Dict[str, List[Dict[str, Any]]], fuzzing_stats: Dict[str, Any]):
    """Generate plots from fuzzing results.
    
    Args:
        output_dir: Directory to store results
        crash_logs: Dictionary of crash logs
        fuzzing_stats: Dictionary of fuzzing statistics
    """
    plots_dir = os.path.join(output_dir, "plots")
    os.makedirs(plots_dir, exist_ok=True)
    
    # Create DataFrame of all crashes
    all_crashes = []
    for harness, logs in crash_logs.items():
        for log in logs:
            log["harness"] = harness
            all_crashes.append(log)
    
    crashes_df = create_crash_summary_df(all_crashes)
    
    # Generate plots if we have crash data
    if not crashes_df.empty:
        # Crashes over time
        fig = plot_crashes_over_time(crashes_df)
        fig.savefig(os.path.join(plots_dir, "crashes_over_time.png"))
        plt.close(fig)
        
        # Crashes by component
        if "component_name" in crashes_df.columns:
            fig = plot_crashes_by_component(crashes_df)
            fig.savefig(os.path.join(plots_dir, "crashes_by_component.png"))
            plt.close(fig)
        
        # Crashes by exception
        if "exception_type" in crashes_df.columns:
            fig = plot_crashes_by_exception(crashes_df)
            fig.savefig(os.path.join(plots_dir, "crashes_by_exception.png"))
            plt.close(fig)
    
    # Generate plots for each harness
    for harness, stats_df in fuzzing_stats.items():
        if not stats_df.empty:
            # Fuzzing progress
            fig = plot_fuzzing_progress(stats_df, title=f"{harness.title()} Fuzzing Progress")
            fig.savefig(os.path.join(plots_dir, f"{harness}_progress.png"))
            plt.close(fig)
            
            # Bugs by type
            fig = plot_bugs_by_type(stats_df, title=f"{harness.title()} Bugs by Type")
            fig.savefig(os.path.join(plots_dir, f"{harness}_bugs.png"))
            plt.close(fig)
    
    print(f"Plots saved to {plots_dir}")


def main():
    """Main function to run fuzzing harnesses."""
    args = parse_arguments()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Get list of harnesses to run
    harness_paths = get_harness_list(args.harnesses)
    
    # Set up code coverage tracking if requested
    if args.track_coverage:
        setup_coverage_tracking("langchain")
    
    # Run harnesses
    if args.parallel and len(harness_paths) > 1:
        print(f"Running {len(harness_paths)} harnesses in parallel for {args.time} seconds each...")
        results = run_harnesses_parallel(harness_paths, args.time, args.output_dir, args.seeds_dir)
    else:
        print(f"Running {len(harness_paths)} harnesses sequentially for {args.time} seconds each...")
        results = run_harnesses_sequential(harness_paths, args.time, args.output_dir, args.seeds_dir)
    
    # Save coverage data if tracking was enabled
    if args.track_coverage:
        save_coverage_data(args.output_dir, "final")
    
    # Collect and analyze results
    crash_logs = collect_crash_logs(args.output_dir)
    fuzzing_stats = collect_fuzzing_stats(args.output_dir)
    
    # Save summary data
    save_summary_data(args.output_dir, crash_logs, fuzzing_stats)
    
    # Generate plots
    generate_plots(args.output_dir, crash_logs, fuzzing_stats)
    
    # Generate report if requested
    if args.report:
        # Create DataFrame of all crashes
        all_crashes = []
        for harness, logs in crash_logs.items():
            for log in logs:
                log["harness"] = harness
                all_crashes.append(log)
        
        crashes_df = create_crash_summary_df(all_crashes)
        
        # Combine fuzzing stats
        if fuzzing_stats:
            # Just use stats from the first harness for now
            first_harness = list(fuzzing_stats.keys())[0]
            stats_df = fuzzing_stats[first_harness]
            
            # Generate report
            generate_summary_report(stats_df, crashes_df, args.output_dir)
    
    print("Fuzzing completed successfully!")


if __name__ == "__main__":
    main()