# LangChain Fuzzing Project

A comprehensive security analysis of LangChain using Atheris fuzzing to identify vulnerabilities in production-grade LLM libraries.

## Overview

This project provides a framework for fuzzing [LangChain](https://github.com/langchain-ai/langchain), an open-source framework for building LLM-powered applications. It uses [Atheris](https://github.com/google/atheris), a coverage-guided fuzzing tool for Python, to identify potential vulnerabilities in LangChain's security-sensitive components.

The project focuses on four key bug classes:
1. **Input Validation Vulnerabilities**: Including template injection, path traversal, etc.
2. **Code Execution Vulnerabilities**: Such as eval/exec-based vulnerabilities and command injection
3. **Resource Exhaustion Vulnerabilities**: Recursive processing, unbound memory consumption, etc.
4. **Information Leakage**: Improper error handling, verbose logging exposing credentials, etc.

## Features

- **Modular Fuzzing Harnesses**: Specialized for different LangChain components
- **Vulnerability Reproduction**: Tests for known CVEs to validate approach
- **Coverage Tracking**: Monitors code coverage during fuzzing
- **Visualization Tools**: Graphs and reports for analyzing results
- **Docker Support**: Containerized setup for reproducible results

## System Requirements

- Python 3.6-3.11
- Docker (for containerized setup)
- Git
- LLVM/Clang (required for Atheris)

## Installation

### Using the Setup Script

The easiest way to set up the environment is to use the provided setup script:

```bash
git clone https://github.com/ali-hindy/langchain-fuzzing-project
cd langchain-fuzzing-project
bash scripts/setup_environment.sh
```

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ali-hindy/langchain-fuzzing-project
   cd langchain-fuzzing-project
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install LangChain (latest development version for CVE testing):
   ```bash
   pip install git+https://github.com/langchain-ai/langchain.git
   ```

### Docker Setup

To use Docker instead:

```bash
docker build -t langchain-fuzzer .
docker run -it langchain-fuzzer /bin/bash
```

## Project Structure

```
langchain-fuzzing-project/
├── Dockerfile               # Container setup for reproducible environment
├── README.md                # This documentation file
├── requirements.txt         # Python dependencies
├── harnesses/               # Atheris fuzzing harnesses for LangChain components
│   ├── prompt_template_harness.py
│   ├── document_loader_harness.py
│   ├── agent_harness.py
│   └── chain_harness.py
├── cve_tests/               # Tests to reproduce known vulnerabilities
│   ├── cve_2023_36258.py    # PALChain code execution via exec()
│   ├── cve_2023_44467.py    # Bypass via __import__
│   └── cve_2023_46229.py    # SSRF in recursive URL loader
├── toy_apps/                # Simplified apps with known bugs for evaluation
│   ├── vulnerable_prompt_template.py
│   └── vulnerable_document_loader.py
├── utils/                   # Helper utilities
│   ├── coverage_utils.py    # Code coverage tracking
│   ├── visualization.py     # Results visualization
│   └── data_generators.py   # Test data generation
├── seeds/                   # Initial input corpus for fuzzing
│   ├── prompt_template_seeds/
│   ├── document_loader_seeds/
│   └── agent_seeds/
├── scripts/                 # Automation scripts
│   ├── run_all_harnesses.py         # Run all fuzzing tests
│   ├── run_cve_tests.py             # Test CVE reproduction
│   ├── evaluate_results.py          # Collect and analyze metrics
│   └── setup_environment.sh         # Environment setup helper
└── results/                 # Directory for storing results (will be created during runs)
```

## Usage

### Running Fuzzing Harnesses

To run all harnesses:

```bash
python scripts/run_all_harnesses.py --time 3600 --output-dir results
```

Options:
- `--harnesses`: Specify harnesses to run (prompt, document, chain, agent, all)
- `--parallel`: Run harnesses in parallel
- `--time`: Time to run each harness in seconds (default: 3600)
- `--output-dir`: Directory to store results (default: results)
- `--track-coverage`: Track code coverage during fuzzing
- `--report`: Generate a summary report after fuzzing

To run a specific harness directly:

```bash
python -m atheris.run -c harnesses/prompt_template_harness.py
```

### Testing Known CVEs

To test for known vulnerabilities:

```bash
python scripts/run_cve_tests.py --output-dir results
```

Options:
- `--cves`: Specify CVEs to test (36258, 44467, 46229, all)
- `--output-dir`: Directory to store results (default: results)
- `--report`: Generate a summary report after testing

### Evaluating Results

To analyze and visualize fuzzing results:

```bash
python scripts/evaluate_results.py --results-dir results --detailed --interactive
```

Options:
- `--results-dir`: Directory containing fuzzing results (default: results)
- `--output-dir`: Directory to store evaluation results (default: <results-dir>/evaluation)
- `--coverage-file`: JSON coverage data file
- `--detailed`: Generate detailed reports
- `--interactive`: Generate interactive HTML reports

## Targeted Vulnerabilities

### CVE-2023-36258
Arbitrary code execution in PALChain via exec(). [GitHub Advisory: GHSA-gjjr-63x4-v8cq](https://github.com/advisories/GHSA-gjjr-63x4-v8cq)

### CVE-2023-44467
Bypass of prior fix allowing arbitrary code via `__import__`. [GitHub Advisory: GHSA-gjjr-63x4-v8cq](https://github.com/advisories/GHSA-gjjr-63x4-v8cq)

### CVE-2023-46229
SSRF in recursive URL loader. [GitHub Advisory: GHSA-655w-fm8m-m478](https://github.com/advisories/GHSA-655w-fm8m-m478)

## Example Results

After running the fuzzer, you will find several types of result files:

- `*.log`: Fuzzing execution logs and crash details
- `coverage_*.json`: Code coverage data
- `evaluation/`: Analysis results and visualizations
- `fuzzing_report.html`: Interactive summary report

## Troubleshooting

### Atheris Installation Issues

If you encounter problems with Atheris installation:

- Ensure you have LLVM/Clang installed
- On macOS, try: `brew install llvm`
- On Ubuntu/Debian, try: `sudo apt-get install clang`

### LangChain Version Conflicts

For CVE testing, specific LangChain versions may be needed:

- The CVE test scripts will automatically check out vulnerable versions
- If you encounter import errors, ensure your main LangChain installation is recent

## Acknowledgements

- [LangChain](https://github.com/langchain-ai/langchain) for creating a powerful LLM framework
- [Atheris](https://github.com/google/atheris) for providing Python fuzzing capabilities
- Contributors to the fuzzing and security testing fields


