"""
Visualization utilities for displaying fuzzing results.
"""

import os
import re
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Any, Optional, Tuple
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np


def parse_crash_logs(log_file: str) -> List[Dict[str, Any]]:
    """Parse crash logs to extract structured data.
    
    Args:
        log_file: Path to the crash log file
        
    Returns:
        List of crash data dictionaries
    """
    if not os.path.exists(log_file):
        return []
    
    with open(log_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Split log entries by the separator
    separator = '=' * 80
    entries = content.split(separator)
    
    # Process each entry
    crashes = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        
        crash_data = {}
        
        # Extract timestamp
        timestamp_match = re.search(r'Crash at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', entry)
        if timestamp_match:
            crash_data['timestamp'] = timestamp_match.group(1)
        
        # Extract component/chain/loader type
        component_match = re.search(r'(Chain|Loader|Prompt|Agent): (.+)', entry)
        if component_match:
            crash_data['component_type'] = component_match.group(1)
            crash_data['component_name'] = component_match.group(2)
        
        # Extract exception
        exception_match = re.search(r'Exception: (.+?):', entry)
        if exception_match:
            crash_data['exception_type'] = exception_match.group(1)
        
        # Extract exception message
        message_match = re.search(r'Exception: .+?: (.+)', entry)
        if message_match:
            crash_data['exception_message'] = message_match.group(1)
        
        crashes.append(crash_data)
    
    return crashes


def create_crash_summary_df(crash_data: List[Dict[str, Any]]) -> pd.DataFrame:
    """Create a DataFrame summarizing crash data.
    
    Args:
        crash_data: List of crash data dictionaries
        
    Returns:
        DataFrame with crash summary
    """
    if not crash_data:
        return pd.DataFrame()
    
    # Convert to DataFrame
    df = pd.DataFrame(crash_data)
    
    # Convert timestamp to datetime
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    return df


def plot_crashes_over_time(df: pd.DataFrame, title: str = "Crashes Over Time") -> plt.Figure:
    """Plot crashes over time using matplotlib.
    
    Args:
        df: DataFrame with crash data
        title: Plot title
        
    Returns:
        Matplotlib figure
    """
    if df.empty or 'timestamp' not in df.columns:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "No crash data available", ha='center', va='center')
        return fig
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Group by timestamp (hourly)
    df['hour'] = df['timestamp'].dt.floor('H')
    crash_counts = df.groupby('hour').size()
    
    # Create a cumulative sum series
    cumulative_crashes = crash_counts.cumsum()
    
    # Plot
    ax.plot(cumulative_crashes.index, cumulative_crashes.values, 'b-', linewidth=2)
    ax.set_title(title)
    ax.set_xlabel('Time')
    ax.set_ylabel('Cumulative Crashes')
    ax.grid(True, linestyle='--', alpha=0.7)
    
    # Format x-axis to show readable dates
    fig.autofmt_xdate()
    
    return fig


def plot_crashes_by_component(df: pd.DataFrame, title: str = "Crashes by Component") -> plt.Figure:
    """Plot crashes by component using matplotlib.
    
    Args:
        df: DataFrame with crash data
        title: Plot title
        
    Returns:
        Matplotlib figure
    """
    if df.empty or 'component_name' not in df.columns:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "No component data available", ha='center', va='center')
        return fig
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Group by component
    component_counts = df['component_name'].value_counts()
    
    # Plot
    component_counts.plot(kind='bar', ax=ax, color='skyblue')
    ax.set_title(title)
    ax.set_xlabel('Component')
    ax.set_ylabel('Number of Crashes')
    ax.grid(True, linestyle='--', alpha=0.7, axis='y')
    
    # Rotate labels for better readability
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    return fig


def plot_crashes_by_exception(df: pd.DataFrame, title: str = "Crashes by Exception Type") -> plt.Figure:
    """Plot crashes by exception type using matplotlib.
    
    Args:
        df: DataFrame with crash data
        title: Plot title
        
    Returns:
        Matplotlib figure
    """
    if df.empty or 'exception_type' not in df.columns:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "No exception data available", ha='center', va='center')
        return fig
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Group by exception type
    exception_counts = df['exception_type'].value_counts()
    
    # Plot
    exception_counts.plot(kind='bar', ax=ax, color='salmon')
    ax.set_title(title)
    ax.set_xlabel('Exception Type')
    ax.set_ylabel('Number of Crashes')
    ax.grid(True, linestyle='--', alpha=0.7, axis='y')
    
    # Rotate labels for better readability
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    return fig


def parse_fuzzing_stats(log_file: str) -> pd.DataFrame:
    """Parse fuzzing statistics from a log file.
    
    Args:
        log_file: Path to the log file
        
    Returns:
        DataFrame with fuzzing statistics
    """
    if not os.path.exists(log_file):
        return pd.DataFrame()
    
    stats_data = []
    
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            # Look for the statistics lines
            if "Runs:" in line and "Crashes:" in line:
                stats = {}
                
                # Extract runs
                runs_match = re.search(r'Runs: (\d+)', line)
                if runs_match:
                    stats['runs'] = int(runs_match.group(1))
                
                # Extract crashes
                crashes_match = re.search(r'Crashes: (\d+)', line)
                if crashes_match:
                    stats['crashes'] = int(crashes_match.group(1))
                
                # Extract runs per second
                rps_match = re.search(r'Runs/sec: ([\d.]+)', line)
                if rps_match:
                    stats['runs_per_second'] = float(rps_match.group(1))
                
                # Check for specific vulnerability types
                if "Template injections:" in line:
                    ti_match = re.search(r'Template injections: (\d+)', line)
                    if ti_match:
                        stats['template_injections'] = int(ti_match.group(1))
                
                if "Path traversal:" in line:
                    pt_match = re.search(r'Path traversal: (\d+)', line)
                    if pt_match:
                        stats['path_traversal'] = int(pt_match.group(1))
                
                if "Resource exhaustion:" in line:
                    re_match = re.search(r'Resource exhaustion: (\d+)', line)
                    if re_match:
                        stats['resource_exhaustion'] = int(re_match.group(1))
                
                if "Code executions:" in line:
                    ce_match = re.search(r'Code executions: (\d+)', line)
                    if ce_match:
                        stats['code_executions'] = int(ce_match.group(1))
                
                stats_data.append(stats)
    
    # Convert to DataFrame
    if stats_data:
        df = pd.DataFrame(stats_data)
        return df
    else:
        return pd.DataFrame()


def plot_fuzzing_progress(df: pd.DataFrame, title: str = "Fuzzing Progress") -> plt.Figure:
    """Plot fuzzing progress using matplotlib.
    
    Args:
        df: DataFrame with fuzzing statistics
        title: Plot title
        
    Returns:
        Matplotlib figure
    """
    if df.empty or 'runs' not in df.columns:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "No fuzzing progress data available", ha='center', va='center')
        return fig
    
    fig, ax1 = plt.subplots(figsize=(12, 6))
    
    # Plot runs
    color = 'tab:blue'
    ax1.set_xlabel('Progress')
    ax1.set_ylabel('Runs', color=color)
    ax1.plot(df.index, df['runs'], color=color)
    ax1.tick_params(axis='y', labelcolor=color)
    
    # Create a second y-axis for crashes
    ax2 = ax1.twinx()
    color = 'tab:red'
    ax2.set_ylabel('Crashes', color=color)
    ax2.plot(df.index, df['crashes'], color=color)
    ax2.tick_params(axis='y', labelcolor=color)
    
    # Add title and grid
    plt.title(title)
    ax1.grid(True, linestyle='--', alpha=0.7)
    
    fig.tight_layout()
    return fig


def plot_bugs_by_type(df: pd.DataFrame, title: str = "Bugs by Type") -> plt.Figure:
    """Plot bugs by type using matplotlib.
    
    Args:
        df: DataFrame with fuzzing statistics
        title: Plot title
        
    Returns:
        Matplotlib figure
    """
    # List of potential bug type columns
    bug_types = ['template_injections', 'path_traversal', 'resource_exhaustion', 'code_executions']
    
    # Filter and rename columns that exist in the DataFrame
    bug_data = {}
    for bug_type in bug_types:
        if bug_type in df.columns:
            # Use the last value (most recent) for each type
            bug_data[bug_type.replace('_', ' ').title()] = df[bug_type].iloc[-1]
    
    if not bug_data:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "No vulnerability data available", ha='center', va='center')
        return fig
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Plot
    bug_series = pd.Series(bug_data)
    bug_series.plot(kind='bar', ax=ax, color='lightgreen')
    ax.set_title(title)
    ax.set_xlabel('Bug Type')
    ax.set_ylabel('Count')
    ax.grid(True, linestyle='--', alpha=0.7, axis='y')
    
    # Add value labels on top of bars
    for i, v in enumerate(bug_series):
        ax.text(i, v + 0.1, str(v), ha='center')
    
    plt.tight_layout()
    return fig


def plot_interactive_dashboard(
    fuzzing_stats_df: pd.DataFrame,
    crash_summary_df: pd.DataFrame,
    title: str = "LangChain Fuzzing Results"
) -> go.Figure:
    """Create an interactive dashboard with Plotly.
    
    Args:
        fuzzing_stats_df: DataFrame with fuzzing statistics
        crash_summary_df: DataFrame with crash data
        title: Dashboard title
        
    Returns:
        Plotly figure
    """
    # Create subplots with 2 rows and 2 columns
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=("Fuzzing Progress", "Bugs by Type", "Crashes Over Time", "Crashes by Component"),
        specs=[[{"type": "scatter"}, {"type": "bar"}],
               [{"type": "scatter"}, {"type": "bar"}]]
    )
    
    # 1. Fuzzing Progress (top left)
    if not fuzzing_stats_df.empty and 'runs' in fuzzing_stats_df.columns:
        fig.add_trace(
            go.Scatter(
                x=list(range(len(fuzzing_stats_df))), 
                y=fuzzing_stats_df['runs'],
                mode='lines',
                name='Runs',
                line=dict(color='blue')
            ),
            row=1, col=1
        )
        
        fig.add_trace(
            go.Scatter(
                x=list(range(len(fuzzing_stats_df))), 
                y=fuzzing_stats_df['crashes'],
                mode='lines',
                name='Crashes',
                line=dict(color='red')
            ),
            row=1, col=1
        )
    
    # 2. Bugs by Type (top right)
    bug_types = ['template_injections', 'path_traversal', 'resource_exhaustion', 'code_executions']
    bug_data = {}
    
    for bug_type in bug_types:
        if bug_type in fuzzing_stats_df.columns and not fuzzing_stats_df.empty:
            # Use the last value (most recent) for each type
            bug_data[bug_type.replace('_', ' ').title()] = fuzzing_stats_df[bug_type].iloc[-1]
    
    if bug_data:
        fig.add_trace(
            go.Bar(
                x=list(bug_data.keys()),
                y=list(bug_data.values()),
                name='Bug Types',
                marker_color='lightgreen'
            ),
            row=1, col=2
        )
    
    # 3. Crashes Over Time (bottom left)
    if not crash_summary_df.empty and 'timestamp' in crash_summary_df.columns:
        # Group by timestamp (hourly)
        crash_summary_df['hour'] = pd.to_datetime(crash_summary_df['timestamp']).dt.floor('H')
        crash_counts = crash_summary_df.groupby('hour').size()
        cumulative_crashes = crash_counts.cumsum()
        
        fig.add_trace(
            go.Scatter(
                x=cumulative_crashes.index,
                y=cumulative_crashes.values,
                mode='lines',
                name='Cumulative Crashes',
                line=dict(color='darkblue')
            ),
            row=2, col=1
        )
    
    # 4. Crashes by Component (bottom right)
    if not crash_summary_df.empty and 'component_name' in crash_summary_df.columns:
        component_counts = crash_summary_df['component_name'].value_counts()
        
        fig.add_trace(
            go.Bar(
                x=component_counts.index,
                y=component_counts.values,
                name='Components',
                marker_color='skyblue'
            ),
            row=2, col=2
        )
    
    # Update layout
    fig.update_layout(
        title_text=title,
        height=800,
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )
    
    # Update x-axis and y-axis labels
    fig.update_xaxes(title_text="Progress", row=1, col=1)
    fig.update_yaxes(title_text="Count", row=1, col=1)
    
    fig.update_xaxes(title_text="Bug Type", row=1, col=2)
    fig.update_yaxes(title_text="Count", row=1, col=2)
    
    fig.update_xaxes(title_text="Time", row=2, col=1)
    fig.update_yaxes(title_text="Cumulative Crashes", row=2, col=1)
    
    fig.update_xaxes(title_text="Component", row=2, col=2)
    fig.update_yaxes(title_text="Number of Crashes", row=2, col=2)
    
    return fig


def generate_summary_report(
    fuzzing_stats_df: pd.DataFrame,
    crash_summary_df: pd.DataFrame,
    output_dir: str = "results"
) -> str:
    """Generate a summary report in HTML format.
    
    Args:
        fuzzing_stats_df: DataFrame with fuzzing statistics
        crash_summary_df: DataFrame with crash data
        output_dir: Directory for the output report
        
    Returns:
        Path to the generated report
    """
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "fuzzing_report.html")
    
    # Create the dashboard
    fig = plot_interactive_dashboard(fuzzing_stats_df, crash_summary_df)
    
    # Statistics summary
    stats_summary = "<h2>Fuzzing Statistics Summary</h2>"
    
    if not fuzzing_stats_df.empty:
        last_stats = fuzzing_stats_df.iloc[-1]
        
        stats_summary += f"<p><strong>Total Runs:</strong> {last_stats.get('runs', 'N/A')}</p>"
        stats_summary += f"<p><strong>Total Crashes:</strong> {last_stats.get('crashes', 'N/A')}</p>"
        stats_summary += f"<p><strong>Runs per Second:</strong> {last_stats.get('runs_per_second', 'N/A'):.2f}</p>"
        
        # Add vulnerability-specific counts if available
        bug_types = {
            'template_injections': 'Template Injections',
            'path_traversal': 'Path Traversal Attempts',
            'resource_exhaustion': 'Resource Exhaustion Cases',
            'code_executions': 'Code Execution Attempts'
        }
        
        stats_summary += "<h3>Detected Vulnerabilities</h3><ul>"
        for key, label in bug_types.items():
            if key in last_stats:
                stats_summary += f"<li><strong>{label}:</strong> {last_stats.get(key, 0)}</li>"
        stats_summary += "</ul>"
    
    # Crash summary
    crash_summary = "<h2>Crash Summary</h2>"
    
    if not crash_summary_df.empty:
        # Top components
        if 'component_name' in crash_summary_df.columns:
            top_components = crash_summary_df['component_name'].value_counts().head(5)
            
            crash_summary += "<h3>Top Components with Crashes</h3><ul>"
            for component, count in top_components.items():
                crash_summary += f"<li><strong>{component}:</strong> {count} crashes</li>"
            crash_summary += "</ul>"
        
        # Top exceptions
        if 'exception_type' in crash_summary_df.columns:
            top_exceptions = crash_summary_df['exception_type'].value_counts().head(5)
            
            crash_summary += "<h3>Top Exception Types</h3><ul>"
            for exception, count in top_exceptions.items():
                crash_summary += f"<li><strong>{exception}:</strong> {count} occurrences</li>"
            crash_summary += "</ul>"
    
    # Create the HTML report
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>LangChain Fuzzing Report</title>
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
        </style>
    </head>
    <body>
        <div class="container">
            <h1>LangChain Fuzzing Security Analysis Report</h1>
            <p>
                This report presents the results of security analysis performed on LangChain 
                using Atheris fuzzing. It includes statistics, detected vulnerabilities, and crash analysis.
            </p>
            <hr>
            {stats_summary}
            <hr>
            {crash_summary}
            <hr>
            <h2>Fuzzing Dashboard</h2>
            <div id="dashboard">
                {fig.to_html(include_plotlyjs=True, full_html=False)}
            </div>
        </div>
    </body>
    </html>
    """
    
    # Write the report
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"Report generated at: {report_path}")
    return report_path