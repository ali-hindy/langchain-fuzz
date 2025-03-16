"""
Vulnerable Document Loader implementation for LangChain fuzzing.
Contains deliberate path traversal and resource exhaustion vulnerabilities for testing.
"""

import os
import json
import csv
from typing import Dict, Any, List, Optional, Union


class Document:
    """Simple document class, similar to LangChain's Document."""
    
    def __init__(self, page_content: str, metadata: Optional[Dict[str, Any]] = None):
        """Initialize a document.
        
        Args:
            page_content: The content of the document
            metadata: Metadata about the document
        """
        self.page_content = page_content
        self.metadata = metadata or {}


class VulnerableDocumentLoader:
    """Base class for vulnerable document loaders."""
    
    def __init__(self):
        """Initialize the document loader."""
        pass
    
    def load(self) -> List[Document]:
        """Load documents.
        
        Returns:
            List of documents
        """
        raise NotImplementedError("Subclasses must implement this method")


class VulnerableTextLoader(VulnerableDocumentLoader):
    """A deliberately vulnerable text loader implementation.
    
    This class is similar to LangChain's TextLoader but has a 
    path traversal vulnerability.
    """
    
    def __init__(self, file_path: str, encoding: Optional[str] = None):
        """Initialize the text loader.
        
        Args:
            file_path: Path to the file to load
            encoding: File encoding (default: utf-8)
        """
        super().__init__()
        self.file_path = file_path
        self.encoding = encoding or "utf-8"
    
    def load(self) -> List[Document]:
        """Load text from a file.
        
        VULNERABLE: Does not properly validate file paths, allowing for path traversal.
        
        Returns:
            List containing a single document with the file contents
        """
        # VULNERABLE: No path validation or normalization
        # This allows for path traversal, e.g., "../../../etc/passwd"
        
        # Read the file content
        try:
            with open(self.file_path, "r", encoding=self.encoding) as f:
                text = f.read()
        except UnicodeDecodeError:
            # Try again with a different encoding
            with open(self.file_path, "r", encoding="latin-1") as f:
                text = f.read()
        
        # Create metadata with the file path
        metadata = {"source": self.file_path}
        
        # Return a document with the text
        return [Document(page_content=text, metadata=metadata)]


class VulnerableDirectoryLoader(VulnerableDocumentLoader):
    """A deliberately vulnerable directory loader implementation.
    
    This class is similar to LangChain's DirectoryLoader but has
    path traversal and resource exhaustion vulnerabilities.
    """
    
    def __init__(self, path: str, glob: str = "*", recursive: bool = False):
        """Initialize the directory loader.
        
        Args:
            path: Path to the directory
            glob: Glob pattern for files
            recursive: Whether to recursively search subdirectories
        """
        super().__init__()
        self.path = path
        self.glob = glob
        self.recursive = recursive
        
        # VULNERABLE: Does not validate the glob pattern
        # This allows for potential path traversal
    
    def load(self) -> List[Document]:
        """Load documents from files in a directory.
        
        VULNERABLE: Does not properly validate file paths or handle resource constraints.
        
        Returns:
            List of documents from the directory
        """
        import glob as glob_module
        
        # Construct the glob pattern
        if self.recursive:
            # VULNERABLE: No validation of self.glob, allowing for path traversal
            pattern = os.path.join(self.path, "**", self.glob)
        else:
            pattern = os.path.join(self.path, self.glob)
        
        # Get list of files
        file_paths = glob_module.glob(pattern, recursive=self.recursive)
        
        # VULNERABLE: No limit on the number of files, allowing for resource exhaustion
        
        # Create a text loader for each file and load it
        documents = []
        for file_path in file_paths:
            if os.path.isfile(file_path):
                loader = VulnerableTextLoader(file_path=file_path)
                documents.extend(loader.load())
        
        return documents


class VulnerableCSVLoader(VulnerableDocumentLoader):
    """A deliberately vulnerable CSV loader implementation.
    
    This class is similar to LangChain's CSVLoader but has
    resource exhaustion and improper error handling vulnerabilities.
    """
    
    def __init__(self, file_path: str, encoding: Optional[str] = None):
        """Initialize the CSV loader.
        
        Args:
            file_path: Path to the CSV file
            encoding: File encoding (default: utf-8)
        """
        super().__init__()
        self.file_path = file_path
        self.encoding = encoding or "utf-8"
    
    def load(self) -> List[Document]:
        """Load documents from a CSV file.
        
        VULNERABLE: Does not handle large files properly and has improper error handling.
        
        Returns:
            List of documents from the CSV
        """
        # VULNERABLE: Loads the entire CSV into memory at once
        # For large files, this can cause memory exhaustion
        
        documents = []
        
        try:
            with open(self.file_path, "r", encoding=self.encoding) as f:
                # VULNERABLE: No limit on CSV size
                csv_reader = csv.DictReader(f)
                
                for i, row in enumerate(csv_reader):
                    # Create a document for each row
                    content = json.dumps(row)
                    metadata = {"source": self.file_path, "row": i}
                    
                    documents.append(Document(page_content=content, metadata=metadata))
        except Exception as e:
            # VULNERABLE: Catches all exceptions and returns a partial result
            # This can hide errors and lead to unexpected behavior
            print(f"Error loading CSV: {str(e)}")
        
        return documents


# Example usage (if run directly)
if __name__ == "__main__":
    import tempfile
    
    # Example 1: Text loader
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("This is a test file.")
        temp_file = f.name
    
    # Normal usage
    text_loader = VulnerableTextLoader(file_path=temp_file)
    text_docs = text_loader.load()
    print(f"Text loader loaded {len(text_docs)} document(s)")
    print(f"Content: {text_docs[0].page_content}")
    
    # Clean up
    os.unlink(temp_file)
    
    # Example 2: Directory loader
    temp_dir = tempfile.mkdtemp()
    for i in range(3):
        with open(os.path.join(temp_dir, f"test_{i}.txt"), "w") as f:
            f.write(f"Test file {i}")
    
    # Normal usage
    dir_loader = VulnerableDirectoryLoader(path=temp_dir, glob="*.txt")
    dir_docs = dir_loader.load()
    print(f"\nDirectory loader loaded {len(dir_docs)} document(s)")
    
    # Path traversal attempt
    try:
        traversal_loader = VulnerableDirectoryLoader(path=temp_dir, glob="../*")
        traversal_docs = traversal_loader.load()
        print(f"Path traversal loaded {len(traversal_docs)} document(s)")
    except Exception as e:
        print(f"Path traversal failed: {str(e)}")
    
    # Clean up
    for i in range(3):
        os.unlink(os.path.join(temp_dir, f"test_{i}.txt"))
    os.rmdir(temp_dir)