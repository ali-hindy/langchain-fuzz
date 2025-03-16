#!/bin/bash
# Setup script for LangChain Fuzzing Project environment

# Exit on error
set -e

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print section header
print_header() {
    echo -e "\n${YELLOW}== $1 ==${NC}\n"
}

# Print success message
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Print error message
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if the working directory path contains spaces
check_path_for_spaces() {
    local path="$(pwd)"
    if [[ "$path" =~ \  ]]; then
        print_error "The working directory path contains spaces: $path"
        echo "This might cause issues with some build tools."
        echo "Consider moving the project to a directory without spaces, e.g., /Users/Ali/Projects/langchain-fuzz"
        echo "Do you want to continue anyway? [y/N]"
        read -r continue_anyway
        if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Print current directory
echo "Working directory: $(pwd)"
check_path_for_spaces

# Check Python version
print_header "Checking Python"
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version)
    print_success "Python installed: $PYTHON_VERSION"
    PYTHON=python3
elif command_exists python; then
    PYTHON_VERSION=$(python --version)
    print_success "Python installed: $PYTHON_VERSION"
    PYTHON=python
else
    print_error "Python not found. Please install Python 3.6 or higher."
    exit 1
fi

# Check if we're inside a virtual environment
print_header "Checking Virtual Environment"
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "Not running inside a virtual environment."
    
    # Check if venv module is available
    if $PYTHON -c "import venv" 2>/dev/null; then
        echo "Creating a new virtual environment..."
        $PYTHON -m venv venv
        
        # Activate the virtual environment
        source venv/bin/activate
        print_success "Virtual environment created and activated"
    else
        print_error "Python venv module not available. Please create a virtual environment manually."
        exit 1
    fi
else
    print_success "Already running in a virtual environment: $VIRTUAL_ENV"
fi

# Check pip
print_header "Checking pip"
if command_exists pip; then
    PIP_VERSION=$(pip --version)
    print_success "pip installed: $PIP_VERSION"
    PIP=pip
elif command_exists pip3; then
    PIP_VERSION=$(pip3 --version)
    print_success "pip3 installed: $PIP_VERSION"
    PIP=pip3
else
    print_error "pip not found. Please install pip."
    exit 1
fi

# Upgrade pip
echo "Upgrading pip..."
$PIP install --upgrade pip
print_success "pip upgraded to $($PIP --version)"

# Check for clang/LLVM and prepare for Atheris
print_header "Checking Atheris requirements"

# Function to build Clang with libFuzzer from source
build_clang_with_libfuzzer() {
    echo "Building Clang with libFuzzer from source..."
    echo "This process may take a while."

    # Check for dependencies needed for building LLVM
    if ! command_exists cmake; then
        print_error "cmake not found. Please install cmake."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            echo "On macOS, install with: brew install cmake"
        fi
        exit 1
    fi

    if ! command_exists git; then
        print_error "git not found. Please install git."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            echo "On macOS, install with: brew install git"
        fi
        exit 1
    fi

    # Prompt user for build type
    echo "Select a build type for LLVM:"
    echo "  1) Release (optimized, no debug info)"
    echo "  2) Debug (unoptimized, with debug info)"
    echo "  3) RelWithDebInfo (optimized, with debug info) [default]"
    echo "  4) MinSizeRel (optimized for size)"
    echo "Enter choice (1-4) or press Enter for default (RelWithDebInfo):"
    read -r build_type_choice

    case $build_type_choice in
        1) BUILD_TYPE="Release" ;;
        2) BUILD_TYPE="Debug" ;;
        4) BUILD_TYPE="MinSizeRel" ;;
        *) BUILD_TYPE="RelWithDebInfo" ;;
    esac
    print_success "Selected build type: $BUILD_TYPE"

    # Clone LLVM project (use a stable release branch)
    if [ ! -d "llvm-project" ]; then
        echo "Cloning LLVM project (using stable release branch release/17.x)..."
        git clone -b release/17.x https://github.com/llvm/llvm-project.git
    fi

    cd llvm-project
    mkdir -p build
    cd build

    # Configure LLVM with minimal components needed for libFuzzer
    echo "Configuring LLVM build for ARM64 macOS..."
    cmake -DLLVM_ENABLE_PROJECTS='clang;compiler-rt' \
          -G "Unix Makefiles" \
          -S ../llvm \
          -B . \
          -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
          -DCMAKE_OSX_ARCHITECTURES="arm64" \
          -DLLVM_TARGETS_TO_BUILD="AArch64" \
          -DLLVM_DEFAULT_TARGET_TRIPLE="arm64-apple-darwin" \
          -DLLVM_ENABLE_LIBCXX=ON \
          -DLLVM_ENABLE_RUNTIMES="" \
          -DCOMPILER_RT_BUILD_BUILTINS=OFF \
          -DCOMPILER_RT_BUILD_SANITIZERS=ON \
          -DCOMPILER_RT_BUILD_XRAY=OFF \
          -DCOMPILER_RT_BUILD_LIBFUZZER=ON \
          -DCOMPILER_RT_BUILD_PROFILE=OFF \
          -DCMAKE_POLICY_DEFAULT_CMP0116=NEW \
          2>&1 | tee cmake_configure.log

    if [ $? -ne 0 ]; then
        print_error "CMake configuration failed. Check cmake_configure.log for details."
        exit 1
    fi

    echo "Building LLVM (this may take some time)..."
    cmake --build . --parallel $(sysctl -n hw.logicalcpu 2>/dev/null || nproc) 2>&1 | tee cmake_build.log

    if [ $? -ne 0 ]; then
        print_error "LLVM build failed. Check cmake_build.log for details."
        exit 1
    fi

    # Verify Clang binary exists
    CLANG_BIN=$(pwd)/bin/clang
    if [ ! -f "$CLANG_BIN" ]; then
        print_error "Clang binary not found at $CLANG_BIN. Build may have failed."
        exit 1
    fi

    # Set environment variables for Clang
    export CLANG_BIN
    export CC="$CLANG_BIN"
    export CXX="$CLANG_BIN++"
    print_success "Clang with libFuzzer built successfully at $CLANG_BIN"
    cd ../..
}

# Check for Clang and libFuzzer support
LIBFUZZER_AVAILABLE=false
if command_exists clang; then
    CLANG_VERSION=$(clang --version | head -n 1)
    print_success "Clang installed: $CLANG_VERSION"

    # Attempt to check for libFuzzer support by compiling a simple fuzzer
    echo "int main() { return 0; }" > /tmp/test_fuzzer.c
    if clang -fsanitize=fuzzer /tmp/test_fuzzer.c -o /tmp/test_fuzzer 2>/dev/null; then
        LIBFUZZER_AVAILABLE=true
        print_success "libFuzzer support detected in Clang"
        rm -f /tmp/test_fuzzer /tmp/test_fuzzer.c
    else
        print_error "Current Clang does not support libFuzzer, which is required for Atheris."
        rm -f /tmp/test_fuzzer.c
    fi
else
    print_error "Clang not found, which is required for Atheris."
fi

# If libFuzzer is not available, prompt to build Clang from source
if [ "$LIBFUZZER_AVAILABLE" = false ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "On macOS, the default Apple Clang often lacks libFuzzer."
        echo "Would you like to build a custom Clang with libFuzzer support? [y/N]"
        read -r build_clang
        if [[ $build_clang =~ ^[Yy]$ ]]; then
            build_clang_with_libfuzzer
        else
            print_error "Atheris installation may fail without libFuzzer support."
            echo "You can try installing LLVM via Homebrew: brew install llvm"
            echo "Or manually set CLANG_BIN to a compatible Clang binary."
            echo "Proceeding with installation, but it might fail."
        fi
    else
        print_error "Please install a Clang version with libFuzzer support."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            echo "On Ubuntu/Debian, install with: sudo apt-get install clang"
            echo "On Fedora/CentOS, install with: sudo dnf install clang"
        fi
        echo "Proceeding with installation, but it might fail."
    fi
fi

# Install dependencies including Atheris
print_header "Installing dependencies"
echo "Installing required packages..."

# First install other dependencies from requirements.txt if it exists
if [ -f "requirements.txt" ]; then
    $PIP install -r requirements.txt
else
    echo "No requirements.txt found, skipping dependency installation."
fi

# Install Atheris explicitly
echo "Installing Atheris..."
# Verify environment variables are set
if [ -z "$CLANG_BIN" ] || [ -z "$CC" ] || [ -z "$CXX" ]; then
    print_error "Environment variables CLANG_BIN, CC, and CXX must be set before installing Atheris."
    exit 1
fi

# Ensure the Clang binary is accessible
if [ ! -x "$CLANG_BIN" ]; then
    print_error "Clang binary at $CLANG_BIN is not executable or does not exist."
    exit 1
fi

if ! $PIP install atheris; then
    print_error "Failed to install Atheris. Ensure Clang with libFuzzer is properly set up."
    exit 1
fi
print_success "Atheris installed successfully"

# Check if we need to install langchain from GitHub
print_header "Installing LangChain"
echo "Do you want to install LangChain from GitHub (latest development version)? [y/N]"
read -r install_dev

if [[ $install_dev =~ ^[Yy]$ ]]; then
    echo "Installing LangChain from GitHub..."
    $PIP install git+https://github.com/langchain-ai/langchain.git
    print_success "Installed LangChain development version"
else
    echo "Installing LangChain from PyPI..."
    $PIP install langchain
    print_success "Installed LangChain stable version"
fi

# Create directory structure
print_header "Creating directory structure"
mkdir -p seeds/{prompt_template_seeds,document_loader_seeds,chain_seeds,agent_seeds}
mkdir -p results

# Create seed files
echo "Creating sample seed files..."
echo "Hello {name}!" > seeds/prompt_template_seeds/basic_template.txt
echo "SELECT * FROM users WHERE id = {id}" > seeds/prompt_template_seeds/sql_template.txt

print_success "Seed directories created"

# Check if everything is installed correctly
print_header "Verifying installation"

# Check Atheris
echo "Checking Atheris installation..."
if $PYTHON -c "import atheris" 2>/dev/null; then
    print_success "Atheris installed successfully"
else
    print_error "Atheris installation failed. Please check the error messages above."
    exit 1
fi

# Check LangChain
echo "Checking LangChain installation..."
if $PYTHON -c "import langchain" 2>/dev/null; then
    LC_VERSION=$($PYTHON -c "import langchain; print(langchain.__version__)")
    print_success "LangChain installed successfully: version $LC_VERSION"
else
    print_error "LangChain installation failed. Please check the error messages above."
    exit 1
fi

# Final instructions
print_header "Setup complete!"
echo "The environment has been set up successfully."
echo ""
echo "To run all fuzzing harnesses:"
echo "  python scripts/run_all_harnesses.py"
echo ""
echo "To run CVE tests:"
echo "  python scripts/run_cve_tests.py"
echo ""
echo "To evaluate results:"
echo "  python scripts/evaluate_results.py --results-dir results"
echo ""
print_success "Happy fuzzing!"