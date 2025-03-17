#!/usr/bin/env python3
"""
Fuzzing harness for LangChain prompt templates.
Tests for template injection vulnerabilities and other input validation issues.
"""

import atheris
with atheris.instrument_imports():
    import sys
    import os
    import time
    import traceback
    from typing import Dict, Any, Optional, List

# Add parent directory to path to import utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.data_generators import generate_string, generate_prompt_template_inputs

# Import LangChain components - with try/except to handle different LangChain versions
with atheris.instrument_imports():
    try:
        from langchain.prompts import PromptTemplate
        from langchain.prompts.chat import ChatPromptTemplate
    except ImportError:
        try:
            from langchain_core.prompts import PromptTemplate
            from langchain_core.prompts.chat import ChatPromptTemplate
        except ImportError:
            print("Error: LangChain not installed properly")
            sys.exit(1)

# Global counters for statistics
stats = {
    "runs": 0,
    "crashes": 0,
    "template_injection_detected": 0,
    "start_time": time.time()
}

# Setup a file for crash reproduction
crash_log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                             "results", "prompt_template_crashes.log")
os.makedirs(os.path.dirname(crash_log_path), exist_ok=True)

# Custom exception for template injection detection
class TemplateInjectionDetected(Exception):
    """Exception raised when potential template injection is detected."""
    pass


def monitor_execution(func, *args, **kwargs):
    """Wrapper function to monitor for code execution or dangerous behavior.
    
    Args:
        func: Function to call
        *args: Arguments to pass to the function
        **kwargs: Keyword arguments to pass to the function
        
    Returns:
        Result of the function call
    """
    # Dangerous functions to monitor
    # In a real implementation, we'd use more sophisticated methods like system call tracing
    original_exec = __builtins__.exec
    original_eval = __builtins__.eval
    original_import = __builtins__.__import__
    
    injection_detected = False
    
    def detect_template_injection(*args, **kwargs):
        nonlocal injection_detected
        injection_detected = True
        stats["template_injection_detected"] += 1
        raise TemplateInjectionDetected("Template injection detected: attempt to execute code")
    
    try:
        # Replace dangerous functions
        __builtins__.exec = detect_template_injection
        __builtins__.eval = detect_template_injection
        __builtins__.__import__ = detect_template_injection
        
        # Execute the function
        result = func(*args, **kwargs)
        return result
    finally:
        # Restore original functions - using attribute assignment instead of item assignment
        setattr(__builtins__, 'exec', original_exec)
        setattr(__builtins__, 'eval', original_eval)
        setattr(__builtins__, '__import__', original_import)


def log_crash(template: str, variables: Dict[str, Any], exception: Exception):
    """Log crash details to a file for later reproduction.
    
    Args:
        template: The template string
        variables: The template variables
        exception: The exception that occurred
    """
    with open(crash_log_path, "a") as f:
        f.write(f"{'=' * 80}\n")
        f.write(f"Crash at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Exception: {type(exception).__name__}: {str(exception)}\n")
        f.write(f"Template: {repr(template)}\n")
        f.write(f"Variables: {repr(variables)}\n")
        f.write(f"Traceback:\n{traceback.format_exc()}\n")
        f.write(f"{'=' * 80}\n\n")


def test_prompt_template_regular(template: str, variables: Dict[str, Any]):
    """Test a regular PromptTemplate with the given inputs.
    
    Args:
        template: The template string
        variables: The template variables
    """
    # Create a PromptTemplate
    try:
        # Extract input variables from the template
        input_variables = list(variables.keys())
        prompt = PromptTemplate(template=template, input_variables=input_variables)
        
        # Format the template with the variables
        result = monitor_execution(prompt.format, **variables)
        return result
    except Exception as e:
        if not isinstance(e, TemplateInjectionDetected):  # Don't log template injection as crashes
            stats["crashes"] += 1
            log_crash(template, variables, e)
        raise


def test_chat_prompt_template(template: str, variables: Dict[str, Any]):
    """Test a ChatPromptTemplate with the given inputs.
    
    Args:
        template: The template string
        variables: The template variables
    """
    try:
        # Create a system message template
        from langchain_core.prompts import SystemMessagePromptTemplate
        system_message_prompt = SystemMessagePromptTemplate.from_template(template)
        
        # Create a chat prompt from the system message
        chat_prompt = ChatPromptTemplate.from_messages([system_message_prompt])
        
        # Format the chat prompt
        result = monitor_execution(chat_prompt.format_messages, **variables)
        return result
    except Exception as e:
        if not isinstance(e, TemplateInjectionDetected):  # Don't log template injection as crashes
            stats["crashes"] += 1
            log_crash(template, variables, e)
        raise


def test_one_input(data):
    fdp = atheris.FuzzedDataProvider(data)
    stats["runs"] += 1
    
    try:
        # Generate a template and variables
        template, variables = generate_prompt_template_inputs(fdp)
        
        # Choose between different prompt template types
        choice = fdp.ConsumeIntInRange(1, 2)
        
        if choice == 1:
            test_prompt_template_regular(template, variables)
        else:
            test_chat_prompt_template(template, variables)
        
        # Print statistics occasionally
        if stats["runs"] % 100 == 0:
            elapsed_time = time.time() - stats["start_time"]
            runs_per_second = stats["runs"] / elapsed_time if elapsed_time > 0 else 0
            print(f"Runs: {stats['runs']}, "
                  f"Crashes: {stats['crashes']}, "
                  f"Template injections: {stats['template_injection_detected']}, "
                  f"Runs/sec: {runs_per_second:.2f}")
    except Exception as e:
        # Make sure any exceptions here are logged but don't halt the fuzzer
        stats["crashes"] += 1
        print(f"Error in test_one_input: {type(e).__name__}: {str(e)}")
        # We don't raise the exception so the fuzzer can continue


def main():
    """Main function to set up and run the fuzzing."""
    # Create the results directory if it doesn't exist
    os.makedirs(os.path.dirname(crash_log_path), exist_ok=True)
    
    # Print header
    print(f"{'=' * 80}")
    print(f"LangChain Prompt Template Fuzzing")
    print(f"Crash logs will be written to: {crash_log_path}")
    print(f"{'=' * 80}")
    
    # Initialize seed corpus if provided
    seed_corpus_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "seeds",
        "prompt_template_seeds"
    )
    
    corpus = []
    if os.path.exists(seed_corpus_dir) and os.listdir(seed_corpus_dir):  # Check if directory exists and is not empty
        for filename in os.listdir(seed_corpus_dir):
            filepath = os.path.join(seed_corpus_dir, filename)
            with open(filepath, 'rb') as f:
                corpus.append(f.read())
    else:
        print("Warning: Seed corpus directory is empty or does not exist. Fuzzer may not find interesting inputs.")
    
    # Setup Atheris with the seed corpus
    atheris.instrument_all()  # Explicitly instrument all modules
    atheris.Setup(sys.argv, test_one_input, enable_python_coverage=True, corpus=corpus)
    
    # Run the fuzzer
    atheris.Fuzz()


if __name__ == "__main__":
    main()