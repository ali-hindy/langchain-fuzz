#!/usr/bin/env python3
"""
Fuzzing harness for LangChain document loaders.
Tests for path traversal, resource exhaustion, and other vulnerabilities.
"""

import atheris
import sys
import os
import time
import traceback
import tempfile
import shutil
from typing import Dict, Any, List, Optional, Tuple

# Add parent directory to path to import utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.data_generators import (
    generate_string, generate_temporary_file, 
    generate_temporary_csv_file, generate_temporary_json_file
)

# Import LangChain components - with try/except to handle different LangChain versions
try:
    from langchain.document_loaders import (
        TextLoader, CSVLoader, JSONLoader, DirectoryLoader, UnstructuredFileLoader
    )
    from langchain.document_loaders.base import BaseLoader
except ImportError:
    try:
        from langchain_community.document_loaders import (
            TextLoader, CSVLoader, JSONLoader, DirectoryLoader, UnstructuredFileLoader
        )
        from langchain_community.document_loaders.base import BaseLoader
    except ImportError:
        print("Error: LangChain document loaders not installed properly")
        sys.exit(1)

# Global counters for statistics
stats = {
    "runs": 0,
    "crashes": 0,
    "path_traversal_detected": 0,
    "resource_exhaustion_detected": 0,
    "start_time": time.time()
}

# Setup a file for crash reproduction
crash_log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                             "results", "document_loader_crashes.log")
os.makedirs(os.path.dirname(crash_log_path), exist_ok=True)

# Custom exceptions for vulnerability detection
class PathTraversalDetected(Exception):
    """Exception raised when potential path traversal is detected."""
    pass

class ResourceExhaustionDetected(Exception):
    """Exception raised when potential resource exhaustion is detected."""
    pass


def check_for_path_traversal(path: str) -> bool:
    """Check if a path might be attempting path traversal.
    
    Args:
        path: The path to check
        
    Returns:
        True if path traversal is suspected, False otherwise
    """
    # Simple check for path traversal patterns
    suspicious_patterns = [
        "../", "..\\", 
        "%2e%2e%2f", "%2e%2e/", 
        "..%2f", "..%5c"
    ]
    
    return any(pattern in path for pattern in suspicious_patterns)


def log_crash(loader_type: str, args: Dict[str, Any], exception: Exception):
    """Log crash details to a file for later reproduction.
    
    Args:
        loader_type: The type of document loader
        args: The arguments used to create the loader
        exception: The exception that occurred
    """
    with open(crash_log_path, "a") as f:
        f.write(f"{'=' * 80}\n")
        f.write(f"Crash at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Loader: {loader_type}\n")
        f.write(f"Exception: {type(exception).__name__}: {str(exception)}\n")
        f.write(f"Arguments: {repr(args)}\n")
        f.write(f"Traceback:\n{traceback.format_exc()}\n")
        f.write(f"{'=' * 80}\n\n")


def test_text_loader(fdp) -> Optional[BaseLoader]:
    """Test the TextLoader with fuzzed inputs.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        The loader if created successfully, None otherwise
    """
    file_path = generate_temporary_file(fdp)
    
    try:
        # Fuzz loader initialization parameters
        encoding = fdp.PickValueInList(['utf-8', 'latin-1', 'ascii', 'utf-16', 'utf-32', None])
        autodetect_encoding = fdp.ConsumeBool()
        
        loader = TextLoader(
            file_path=file_path,
            encoding=encoding,
            autodetect_encoding=autodetect_encoding
        )
        
        return loader
    except Exception as e:
        stats["crashes"] += 1
        log_crash("TextLoader", {
            "file_path": file_path,
            "encoding": encoding,
            "autodetect_encoding": autodetect_encoding
        }, e)
        return None
    finally:
        # Clean up the temporary file
        try:
            os.remove(file_path)
        except:
            pass


def test_csv_loader(fdp) -> Optional[BaseLoader]:
    """Test the CSVLoader with fuzzed inputs.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        The loader if created successfully, None otherwise
    """
    file_path = generate_temporary_csv_file(fdp)
    
    try:
        # Fuzz loader initialization parameters
        csv_args = {}
        if fdp.ConsumeBool():
            csv_args["delimiter"] = fdp.PickValueInList([',', ';', '\t', '|'])
        if fdp.ConsumeBool():
            csv_args["quotechar"] = fdp.PickValueInList(['"', "'"])
        
        loader = CSVLoader(
            file_path=file_path,
            csv_args=csv_args if csv_args else None,
            source_column=fdp.PickValueInList([None, "source", "text"]) if fdp.ConsumeBool() else None
        )
        
        return loader
    except Exception as e:
        stats["crashes"] += 1
        log_crash("CSVLoader", {
            "file_path": file_path,
            "csv_args": csv_args,
        }, e)
        return None
    finally:
        # Clean up the temporary file
        try:
            os.remove(file_path)
        except:
            pass


def test_json_loader(fdp) -> Optional[BaseLoader]:
    """Test the JSONLoader with fuzzed inputs.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        The loader if created successfully, None otherwise
    """
    file_path = generate_temporary_json_file(fdp)
    
    try:
        # Create a simple jq-like path
        jq_schema = fdp.PickValueInList([".", ".data", ".content", ".[]", ".[0]"])
        
        loader = JSONLoader(
            file_path=file_path,
            jq_schema=jq_schema,
            text_content=fdp.ConsumeBool()
        )
        
        return loader
    except Exception as e:
        stats["crashes"] += 1
        log_crash("JSONLoader", {
            "file_path": file_path,
            "jq_schema": jq_schema,
        }, e)
        return None
    finally:
        # Clean up the temporary file
        try:
            os.remove(file_path)
        except:
            pass


def test_directory_loader(fdp) -> Optional[BaseLoader]:
    """Test the DirectoryLoader with fuzzed inputs.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        The loader if created successfully, None otherwise
    """
    # Create a temporary directory with a few files
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create a few files in the directory
        for i in range(fdp.ConsumeIntInRange(1, 5)):
            file_path = os.path.join(temp_dir, f"file_{i}.txt")
            with open(file_path, "w") as f:
                f.write(generate_string(fdp, 100))
        
        # Fuzz loader initialization parameters
        glob = fdp.PickValueInList(["**/*.txt", "*.txt", "**/*"])
        
        if check_for_path_traversal(glob):
            stats["path_traversal_detected"] += 1
            raise PathTraversalDetected(f"Potential path traversal detected in glob: {glob}")
        
        loader = DirectoryLoader(
            path=temp_dir,
            glob=glob,
            recursive=fdp.ConsumeBool(),
            use_multithreading=fdp.ConsumeBool(),
            max_concurrency=fdp.ConsumeIntInRange(1, 10) if fdp.ConsumeBool() else None
        )
        
        return loader
    except Exception as e:
        if not isinstance(e, PathTraversalDetected):
            stats["crashes"] += 1
            log_crash("DirectoryLoader", {
                "path": temp_dir,
                "glob": glob,
            }, e)
        return None
    finally:
        # Clean up the temporary directory
        try:
            shutil.rmtree(temp_dir)
        except:
            pass


def test_loader_load(loader: BaseLoader):
    """Test the load method on a document loader.
    
    Args:
        loader: The document loader to test
    """
    try:
        # Set a timeout to prevent resource exhaustion
        import signal
        
        def timeout_handler(signum, frame):
            raise ResourceExhaustionDetected("Loading documents timed out")
        
        # Set timeout of 5 seconds
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(5)
        
        # Load documents
        docs = loader.load()
        
        # Cancel the alarm
        signal.alarm(0)
        
        return docs
    except ResourceExhaustionDetected as e:
        stats["resource_exhaustion_detected"] += 1
        raise e
    except Exception as e:
        stats["crashes"] += 1
        log_crash(f"load() on {type(loader).__name__}", {}, e)
        raise


def test_one_input(data):
    """Test function called by Atheris to fuzz one input.
    
    Args:
        data: Input data from Atheris
    """
    fdp = atheris.FuzzedDataProvider(data)
    stats["runs"] += 1
    
    # Choose a document loader type to test
    loader_type = fdp.ConsumeIntInRange(1, 4)
    
    try:
        loader = None
        if loader_type == 1:
            loader = test_text_loader(fdp)
        elif loader_type == 2:
            loader = test_csv_loader(fdp)
        elif loader_type == 3:
            loader = test_json_loader(fdp)
        elif loader_type == 4:
            loader = test_directory_loader(fdp)
        
        if loader:
            test_loader_load(loader)
    except Exception:
        # Exceptions are already logged in the test functions
        pass
    
    # Print statistics occasionally
    if stats["runs"] % 100 == 0:
        elapsed_time = time.time() - stats["start_time"]
        runs_per_second = stats["runs"] / elapsed_time if elapsed_time > 0 else 0
        print(f"Runs: {stats['runs']}, "
              f"Crashes: {stats['crashes']}, "
              f"Path traversal: {stats['path_traversal_detected']}, "
              f"Resource exhaustion: {stats['resource_exhaustion_detected']}, "
              f"Runs/sec: {runs_per_second:.2f}")


def main():
    """Main function to set up and run the fuzzing."""
    # Create the results directory if it doesn't exist
    os.makedirs(os.path.dirname(crash_log_path), exist_ok=True)
    
    # Print header
    print(f"{'=' * 80}")
    print(f"LangChain Document Loaders Fuzzing")
    print(f"Crash logs will be written to: {crash_log_path}")
    print(f"{'=' * 80}")
    
    # Initialize seed corpus if provided
    seed_corpus_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "seeds",
        "document_loader_seeds"
    )
    
    corpus = []
    if os.path.exists(seed_corpus_dir):
        for filename in os.listdir(seed_corpus_dir):
            filepath = os.path.join(seed_corpus_dir, filename)
            with open(filepath, 'rb') as f:
                corpus.append(f.read())
    
    # Setup Atheris with the seed corpus
    atheris.Setup(sys.argv, test_one_input, enable_python_coverage=True, corpus=corpus)
    
    # Run the fuzzer
    atheris.Fuzz()


if __name__ == "__main__":
    main()