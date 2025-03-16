"""
Coverage utilities for tracking code coverage during fuzzing.
"""

import os
import sys
import json
import time
import glob
import subprocess
from typing import Dict, List, Any, Optional, Set, Tuple
import matplotlib.pyplot as plt
import numpy as np


def setup_coverage_tracking(module_name: str = "langchain") -> None:
    """Set up coverage tracking for the specified module.
    
    Args:
        module_name: Name of the module to track coverage for
    """
    # Check if coverage is installed
    try:
        import coverage
    except ImportError:
        print("Coverage package not installed. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "coverage"], check=True)
        import coverage
    
    # Start coverage
    cov = coverage.Coverage(
        source=[module_name],
        data_file=".coverage",
        branch=True,
        concurrency=["thread", "multiprocessing"]
    )
    cov.start()
    
    print(f"Coverage tracking set up for module: {module_name}")


def save_coverage_data(output_dir: str = "results", label: str = "") -> str:
    """Save coverage data to files.
    
    Args:
        output_dir: Directory to save coverage data
        label: Label to add to filenames
        
    Returns:
        Path to the JSON coverage data file
    """
    try:
        import coverage
    except ImportError:
        print("Coverage package not installed")
        return ""
    
    # Create the output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Save the coverage data
    cov = coverage.Coverage(data_file=".coverage")
    cov.load()
    
    # Create a timestamp string
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    # Create a label string
    label_str = f"_{label}" if label else ""
    
    # Save HTML report
    html_dir = os.path.join(output_dir, f"coverage_html{label_str}_{timestamp}")
    cov.html_report(directory=html_dir)
    
    # Save XML report
    xml_file = os.path.join(output_dir, f"coverage{label_str}_{timestamp}.xml")
    cov.xml_report(outfile=xml_file)
    
    # Save JSON data
    json_file = os.path.join(output_dir, f"coverage{label_str}_{timestamp}.json")
    with open(json_file, "w") as f:
        json.dump(cov.get_data().raw_data(), f, indent=2)
    
    print(f"Coverage HTML report saved to: {html_dir}")
    print(f"Coverage XML report saved to: {xml_file}")
    print(f"Coverage JSON data saved to: {json_file}")
    
    return json_file


def analyze_coverage_from_file(json_file: str) -> Dict[str, Any]:
    """Analyze coverage data from a JSON file.
    
    Args:
        json_file: Path to the JSON coverage data file
        
    Returns:
        Dictionary with coverage metrics
    """
    with open(json_file, "r") as f:
        data = json.load(f)
    
    # Extract coverage data
    metrics = {}
    
    # Overall stats
    total_lines = 0
    covered_lines = 0
    
    # Per-file stats
    file_stats = {}
    
    for file_path, file_data in data["lines"].items():
        # Skip non-langchain files
        if "langchain" not in file_path:
            continue
        
        # Get all possible lines
        all_lines = set(data["arcs"].get(file_path, {}).keys())
        for start, _ in data["arcs"].get(file_path, {}).items():
            all_lines.add(start)
        
        # Count lines
        file_total_lines = len(all_lines)
        file_covered_lines = len(file_data)
        file_coverage = file_covered_lines / file_total_lines if file_total_lines > 0 else 0
        
        # Update overall stats
        total_lines += file_total_lines
        covered_lines += file_covered_lines
        
        # Store file stats
        module_path = file_path.split("site-packages/")[-1] if "site-packages" in file_path else file_path
        file_stats[module_path] = {
            "total_lines": file_total_lines,
            "covered_lines": file_covered_lines,
            "coverage": file_coverage
        }
    
    # Calculate overall coverage
    overall_coverage = covered_lines / total_lines if total_lines > 0 else 0
    
    metrics["overall"] = {
        "total_lines": total_lines,
        "covered_lines": covered_lines,
        "coverage": overall_coverage
    }
    
    metrics["files"] = file_stats
    
    return metrics


def compare_coverage(json_file1: str, json_file2: str) -> Dict[str, Any]:
    """Compare coverage between two runs.
    
    Args:
        json_file1: Path to the first JSON coverage data file
        json_file2: Path to the second JSON coverage data file
        
    Returns:
        Dictionary with coverage comparison metrics
    """
    metrics1 = analyze_coverage_from_file(json_file1)
    metrics2 = analyze_coverage_from_file(json_file2)
    
    # Compare overall coverage
    comparison = {
        "overall": {
            "first": metrics1["overall"],
            "second": metrics2["overall"],
            "difference": {
                "total_lines": metrics2["overall"]["total_lines"] - metrics1["overall"]["total_lines"],
                "covered_lines": metrics2["overall"]["covered_lines"] - metrics1["overall"]["covered_lines"],
                "coverage": metrics2["overall"]["coverage"] - metrics1["overall"]["coverage"]
            }
        },
        "files": {}
    }
    
    # Find all unique files
    all_files = set(metrics1["files"].keys()) | set(metrics2["files"].keys())
    
    # Compare file coverage
    for file_path in all_files:
        file1_stats = metrics1["files"].get(file_path, {"total_lines": 0, "covered_lines": 0, "coverage": 0})
        file2_stats = metrics2["files"].get(file_path, {"total_lines": 0, "covered_lines": 0, "coverage": 0})
        
        comparison["files"][file_path] = {
            "first": file1_stats,
            "second": file2_stats,
            "difference": {
                "total_lines": file2_stats["total_lines"] - file1_stats["total_lines"],
                "covered_lines": file2_stats["covered_lines"] - file1_stats["covered_lines"],
                "coverage": file2_stats["coverage"] - file1_stats["coverage"]
            }
        }
    
    return comparison


def track_coverage_over_time(output_dir: str = "results", interval: int = 300) -> None:
    """Track coverage over time at specified intervals.
    
    Args:
        output_dir: Directory to save coverage data
        interval: Interval in seconds between coverage snapshots
    """
    try:
        import coverage
    except ImportError:
        print("Coverage package not installed")
        return
    
    print(f"Starting coverage tracking with {interval}s intervals...")
    
    # Create the output directory
    os.makedirs(output_dir, exist_ok=True)
    
    snapshot_count = 1
    
    try:
        while True:
            # Sleep for the interval
            time.sleep(interval)
            
            # Save coverage snapshot
            cov = coverage.Coverage(data_file=".coverage")
            cov.load()
            
            # Save JSON data
            json_file = os.path.join(output_dir, f"coverage_snapshot_{snapshot_count}.json")
            with open(json_file, "w") as f:
                json.dump(cov.get_data().raw_data(), f, indent=2)
            
            print(f"Saved coverage snapshot {snapshot_count} to {json_file}")
            
            snapshot_count += 1
    except KeyboardInterrupt:
        print("Coverage tracking stopped")


def plot_coverage_progress(snapshots_dir: str, output_file: str = None) -> plt.Figure:
    """Plot coverage progress over multiple snapshots.
    
    Args:
        snapshots_dir: Directory containing coverage snapshots
        output_file: Path to save the plot (if None, the plot is displayed)
        
    Returns:
        Matplotlib figure
    """
    # Find all JSON coverage files
    json_files = sorted(glob.glob(os.path.join(snapshots_dir, "coverage_snapshot_*.json")))
    
    if not json_files:
        print(f"No coverage snapshots found in {snapshots_dir}")
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "No coverage data available", ha='center', va='center')
        return fig
    
    # Extract coverage metrics from each file
    timestamps = []
    overall_coverage = []
    covered_lines = []
    
    for i, json_file in enumerate(json_files):
        metrics = analyze_coverage_from_file(json_file)
        timestamps.append(i + 1)  # Use snapshot number as timestamp
        overall_coverage.append(metrics["overall"]["coverage"] * 100)  # Convert to percentage
        covered_lines.append(metrics["overall"]["covered_lines"])
    
    # Create the figure
    fig, ax1 = plt.subplots(figsize=(12, 6))
    
    # Plot overall coverage percentage
    color = 'tab:blue'
    ax1.set_xlabel('Snapshot')
    ax1.set_ylabel('Coverage (%)', color=color)
    ax1.plot(timestamps, overall_coverage, color=color, marker='o')
    ax1.tick_params(axis='y', labelcolor=color)
    
    # Create a second y-axis for covered lines
    ax2 = ax1.twinx()
    color = 'tab:red'
    ax2.set_ylabel('Covered Lines', color=color)
    ax2.plot(timestamps, covered_lines, color=color, marker='s')
    ax2.tick_params(axis='y', labelcolor=color)
    
    # Add a title
    plt.title('Coverage Progress Over Time')
    
    # Add a grid
    ax1.grid(True, linestyle='--', alpha=0.7)
    
    # Adjust layout
    fig.tight_layout()
    
    # Save the plot if output_file is specified
    if output_file:
        plt.savefig(output_file)
        print(f"Coverage progress plot saved to {output_file}")
    
    return fig


def plot_module_coverage(json_file: str, top_n: int = 10, output_file: str = None) -> plt.Figure:
    """Plot coverage for top modules.
    
    Args:
        json_file: Path to the JSON coverage data file
        top_n: Number of top modules to show
        output_file: Path to save the plot (if None, the plot is displayed)
        
    Returns:
        Matplotlib figure
    """
    metrics = analyze_coverage_from_file(json_file)
    
    # Group by module
    module_data = {}
    
    for file_path, stats in metrics["files"].items():
        # Extract module name (first part of the path)
        parts = file_path.split('/')
        if parts[0] == '':
            parts = parts[1:]
        
        if len(parts) > 0:
            module = parts[0]
            
            # Accumulate lines
            if module not in module_data:
                module_data[module] = {"total_lines": 0, "covered_lines": 0}
            
            module_data[module]["total_lines"] += stats["total_lines"]
            module_data[module]["covered_lines"] += stats["covered_lines"]
    
    # Calculate coverage percentage
    for module in module_data:
        if module_data[module]["total_lines"] > 0:
            module_data[module]["coverage"] = (
                module_data[module]["covered_lines"] / module_data[module]["total_lines"] * 100
            )
        else:
            module_data[module]["coverage"] = 0
    
    # Sort by coverage
    sorted_modules = sorted(
        module_data.items(),
        key=lambda x: x[1]["covered_lines"],
        reverse=True
    )
    
    # Take top N modules
    top_modules = sorted_modules[:top_n]
    
    # Create the plot
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Extract data for plotting
    modules = [m[0] for m in top_modules]
    coverages = [m[1]["coverage"] for m in top_modules]
    covered_lines = [m[1]["covered_lines"] for m in top_modules]
    total_lines = [m[1]["total_lines"] for m in top_modules]
    
    # Plot the stacked bars
    bar_width = 0.5
    indices = np.arange(len(modules))
    
    ax.bar(indices, total_lines, bar_width, label='Total Lines', color='lightgray')
    ax.bar(indices, covered_lines, bar_width, label='Covered Lines', color='green')
    
    # Add coverage percentage on top of bars
    for i, (coverage, covered, total) in enumerate(zip(coverages, covered_lines, total_lines)):
        ax.text(i, total + 50, f"{coverage:.1f}%", ha='center', va='bottom')
        ax.text(i, covered / 2, f"{covered}", ha='center', va='center', color='white', fontweight='bold')
    
    # Customize the plot
    ax.set_ylabel('Number of Lines')
    ax.set_title('Code Coverage by Module')
    ax.set_xticks(indices)
    ax.set_xticklabels(modules, rotation=45, ha='right')
    ax.legend()
    
    plt.tight_layout()
    
    # Save the plot if output_file is specified
    if output_file:
        plt.savefig(output_file)
        print(f"Module coverage plot saved to {output_file}")
    
    return fig


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "setup":
            module_name = sys.argv[2] if len(sys.argv) > 2 else "langchain"
            setup_coverage_tracking(module_name)
        
        elif command == "save":
            output_dir = sys.argv[2] if len(sys.argv) > 2 else "results"
            label = sys.argv[3] if len(sys.argv) > 3 else ""
            save_coverage_data(output_dir, label)
        
        elif command == "analyze":
            json_file = sys.argv[2]
            metrics = analyze_coverage_from_file(json_file)
            print(f"Overall Coverage: {metrics['overall']['coverage'] * 100:.2f}%")
            print(f"Covered Lines: {metrics['overall']['covered_lines']} / {metrics['overall']['total_lines']}")
        
        elif command == "compare":
            json_file1 = sys.argv[2]
            json_file2 = sys.argv[3]
            comparison = compare_coverage(json_file1, json_file2)
            diff = comparison["overall"]["difference"]["coverage"] * 100
            sign = "+" if diff >= 0 else ""
            print(f"Coverage Change: {sign}{diff:.2f}%")
            print(f"Additional Lines Covered: {comparison['overall']['difference']['covered_lines']}")
        
        elif command == "track":
            output_dir = sys.argv[2] if len(sys.argv) > 2 else "results"
            interval = int(sys.argv[3]) if len(sys.argv) > 3 else 300
            track_coverage_over_time(output_dir, interval)
        
        elif command == "plot":
            json_file = sys.argv[2]
            output_file = sys.argv[3] if len(sys.argv) > 3 else None
            plot_module_coverage(json_file, output_file=output_file)
            if not output_file:
                plt.show()
    else:
        print("Usage:")
        print("  python coverage_utils.py setup [module_name]")
        print("  python coverage_utils.py save [output_dir] [label]")
        print("  python coverage_utils.py analyze <json_file>")
        print("  python coverage_utils.py compare <json_file1> <json_file2>")
        print("  python coverage_utils.py track [output_dir] [interval]")
        print("  python coverage_utils.py plot <json_file> [output_file]")