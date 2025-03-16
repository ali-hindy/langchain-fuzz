#!/bin/bash
# Run all tests and generate a comprehensive report

# Exit on error
set -e

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create results directory
RESULTS_DIR="results/$(date '+%Y%m%d_%H%M%S')"
mkdir -p "$RESULTS_DIR"

echo -e "${YELLOW}Results will be saved to: ${RESULTS_DIR}${NC}"

# Start with CVE tests
echo -e "\n${YELLOW}Running CVE tests...${NC}"
python scripts/run_cve_tests.py --output-dir "$RESULTS_DIR"

# Run fuzzing harnesses
echo -e "\n${YELLOW}Running fuzzing harnesses...${NC}"
python scripts/run_all_harnesses.py --time 1800 --output-dir "$RESULTS_DIR" --track-coverage

# Evaluate results
echo -e "\n${YELLOW}Evaluating results...${NC}"
python scripts/evaluate_results.py --results-dir "$RESULTS_DIR" --detailed --interactive

echo -e "\n${GREEN}All tests completed!${NC}"
echo -e "Full report available at: ${RESULTS_DIR}/fuzzing_report.html"