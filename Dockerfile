FROM python:3.10-slim

# Set up environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV ASAN_OPTIONS=detect_leaks=0

# Install system dependencies including LLVM for libFuzzer
RUN apt-get update && apt-get install -y \
    git \
    clang \
    llvm \
    build-essential \
    curl \
    procps \
    lsof \
    vim \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir git+https://github.com/langchain-ai/langchain.git

# Create directory structure
RUN mkdir -p seeds/{prompt_template_seeds,document_loader_seeds,chain_seeds,agent_seeds} && \
    mkdir -p results

# Copy project files
COPY . .

# Create entrypoint script
RUN echo '#!/bin/bash\n\
echo "LangChain Fuzzing Container"\n\
echo "========================"\n\
echo "Available commands:"\n\
echo "  python scripts/run_all_harnesses.py    # Run all fuzzing harnesses"\n\
echo "  python scripts/run_cve_tests.py        # Test known CVEs"\n\
echo "  python scripts/evaluate_results.py     # Evaluate results"\n\
echo ""\n\
exec "$@"\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["/bin/bash"]