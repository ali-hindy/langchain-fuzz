#!/usr/bin/env python3
"""
Fuzzing harness for LangChain chain components.
Tests for code execution vulnerabilities and input validation issues.
"""

import atheris
import sys
import os
import time
import traceback
from typing import Dict, Any, List, Optional, Tuple

# Add parent directory to path to import utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.data_generators import generate_string, generate_dict, generate_prompt_template_inputs

# Import LangChain components
try:
    from langchain.prompts import PromptTemplate
    from langchain.chains import LLMChain, SimpleSequentialChain, SequentialChain, TransformChain
    from langchain.chains.base import Chain
    from langchain.llms.fake import FakeListLLM
except ImportError:
    try:
        from langchain_core.prompts import PromptTemplate
        from langchain.chains import LLMChain, SimpleSequentialChain, SequentialChain, TransformChain
        from langchain_core.chains.base import Chain
        from langchain_core.llms.fake import FakeListLLM
    except ImportError:
        print("Error: LangChain not installed properly")
        sys.exit(1)

# Global counters for statistics
stats = {
    "runs": 0,
    "crashes": 0,
    "code_execution_detected": 0,
    "start_time": time.time()
}

# Setup a file for crash reproduction
crash_log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                             "results", "chain_crashes.log")
os.makedirs(os.path.dirname(crash_log_path), exist_ok=True)

# Custom exception for code execution detection
class CodeExecutionDetected(Exception):
    """Exception raised when potential code execution is detected."""
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
    original_exec = __builtins__.get('exec')
    original_eval = __builtins__.get('eval')
    original_import = __builtins__.get('__import__')
    
    code_execution_detected = False
    
    def detect_code_execution(*args, **kwargs):
        nonlocal code_execution_detected
        code_execution_detected = True
        stats["code_execution_detected"] += 1
        raise CodeExecutionDetected("Code execution detected")
    
    try:
        # Replace dangerous functions
        __builtins__['exec'] = detect_code_execution
        __builtins__['eval'] = detect_code_execution
        __builtins__['__import__'] = detect_code_execution
        
        # Execute the function
        result = func(*args, **kwargs)
        return result
    finally:
        # Restore original functions
        __builtins__['exec'] = original_exec
        __builtins__['eval'] = original_eval
        __builtins__['__import__'] = original_import


def log_crash(chain_type: str, args: Dict[str, Any], exception: Exception):
    """Log crash details to a file for later reproduction.
    
    Args:
        chain_type: The type of chain
        args: The arguments used to create the chain
        exception: The exception that occurred
    """
    with open(crash_log_path, "a") as f:
        f.write(f"{'=' * 80}\n")
        f.write(f"Crash at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Chain: {chain_type}\n")
        f.write(f"Exception: {type(exception).__name__}: {str(exception)}\n")
        f.write(f"Arguments: {repr(args)}\n")
        f.write(f"Traceback:\n{traceback.format_exc()}\n")
        f.write(f"{'=' * 80}\n\n")


def create_fake_llm(fdp) -> FakeListLLM:
    """Create a fake LLM for testing.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        FakeListLLM instance
    """
    # Generate a list of responses
    num_responses = fdp.ConsumeIntInRange(1, 5)
    responses = [generate_string(fdp, 200) for _ in range(num_responses)]
    
    return FakeListLLM(responses=responses)


def test_llm_chain(fdp) -> Optional[Chain]:
    """Test an LLMChain with fuzzed inputs.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        The chain if created successfully, None otherwise
    """
    try:
        # Create a fake LLM
        llm = create_fake_llm(fdp)
        
        # Generate a template and variables
        template, variables = generate_prompt_template_inputs(fdp)
        
        # Create a prompt template
        input_variables = list(variables.keys())
        prompt = PromptTemplate(template=template, input_variables=input_variables)
        
        # Create the LLMChain
        chain = LLMChain(
            llm=llm,
            prompt=prompt,
            verbose=fdp.ConsumeBool()
        )
        
        return chain, variables
    except Exception as e:
        stats["crashes"] += 1
        log_crash("LLMChain", {
            "template": template,
            "input_variables": input_variables
        }, e)
        return None, None


def test_transform_chain(fdp) -> Optional[Chain]:
    """Test a TransformChain with fuzzed inputs.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        The chain if created successfully, None otherwise
    """
    try:
        # Generate input and output keys
        num_input_keys = fdp.ConsumeIntInRange(1, 3)
        input_keys = [f"input_{i}" for i in range(num_input_keys)]
        
        num_output_keys = fdp.ConsumeIntInRange(1, 3)
        output_keys = [f"output_{i}" for i in range(num_output_keys)]
        
        # Create a simple transform function
        def transform_func(inputs):
            outputs = {}
            for i, output_key in enumerate(output_keys):
                # Simple transformation to prevent actual code execution
                if i < len(input_keys):
                    outputs[output_key] = f"Transformed: {inputs.get(input_keys[i], '')}"
                else:
                    outputs[output_key] = "Default output"
            return outputs
        
        # Create the TransformChain
        chain = TransformChain(
            input_keys=input_keys,
            output_keys=output_keys,
            transform=transform_func,
            verbose=fdp.ConsumeBool()
        )
        
        # Generate input variables
        variables = {}
        for key in input_keys:
            variables[key] = generate_string(fdp, 100)
        
        return chain, variables
    except Exception as e:
        stats["crashes"] += 1
        log_crash("TransformChain", {
            "input_keys": input_keys,
            "output_keys": output_keys
        }, e)
        return None, None


def test_sequential_chain(fdp) -> Optional[Chain]:
    """Test a SequentialChain with fuzzed inputs.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        The chain if created successfully, None otherwise
    """
    try:
        # Create a few LLMChains to put in sequence
        num_chains = fdp.ConsumeIntInRange(2, 3)
        chains = []
        variables = {}
        
        for i in range(num_chains):
            # Create a fake LLM
            llm = create_fake_llm(fdp)
            
            # Create input and output keys
            input_key = f"input_{i}"
            output_key = f"output_{i}"
            
            # Create a simple template
            template = f"{{{input_key}}} -> output"
            
            # Create a prompt template
            prompt = PromptTemplate(template=template, input_variables=[input_key])
            
            # Create the LLMChain
            chain = LLMChain(
                llm=llm,
                prompt=prompt,
                output_key=output_key
            )
            
            chains.append(chain)
            
            # Generate a value for this chain's input key
            variables[input_key] = generate_string(fdp, 100)
        
        # Determine the overall input and output keys
        overall_input_keys = [f"input_{i}" for i in range(num_chains)]
        overall_output_keys = [f"output_{i}" for i in range(num_chains)]
        
        # Create the SequentialChain
        chain = SequentialChain(
            chains=chains,
            input_keys=overall_input_keys,
            output_keys=overall_output_keys,
            verbose=fdp.ConsumeBool()
        )
        
        return chain, variables
    except Exception as e:
        stats["crashes"] += 1
        log_crash("SequentialChain", {
            "num_chains": num_chains
        }, e)
        return None, None


def test_chain_run(chain: Chain, variables: Dict[str, Any]):
    """Test the run method on a chain.
    
    Args:
        chain: The chain to test
        variables: Input variables for the chain
    """
    try:
        # Run the chain with monitoring
        result = monitor_execution(chain.run, variables)
        return result
    except CodeExecutionDetected as e:
        # This is already counted in the monitor_execution function
        raise e
    except Exception as e:
        stats["crashes"] += 1
        log_crash(f"run() on {type(chain).__name__}", {
            "variables": variables
        }, e)
        raise


def test_one_input(data):
    """Test function called by Atheris to fuzz one input.
    
    Args:
        data: Input data from Atheris
    """
    fdp = atheris.FuzzedDataProvider(data)
    stats["runs"] += 1
    
    # Choose a chain type to test
    chain_type = fdp.ConsumeIntInRange(1, 3)
    
    try:
        chain, variables = None, None
        if chain_type == 1:
            chain, variables = test_llm_chain(fdp)
        elif chain_type == 2:
            chain, variables = test_transform_chain(fdp)
        elif chain_type == 3:
            chain, variables = test_sequential_chain(fdp)
        
        if chain and variables:
            test_chain_run(chain, variables)
    except Exception:
        # Exceptions are already logged in the test functions
        pass
    
    # Print statistics occasionally
    if stats["runs"] % 100 == 0:
        elapsed_time = time.time() - stats["start_time"]
        runs_per_second = stats["runs"] / elapsed_time if elapsed_time > 0 else 0
        print(f"Runs: {stats['runs']}, "
              f"Crashes: {stats['crashes']}, "
              f"Code executions: {stats['code_execution_detected']}, "
              f"Runs/sec: {runs_per_second:.2f}")


def main():
    """Main function to set up and run the fuzzing."""
    # Create the results directory if it doesn't exist
    os.makedirs(os.path.dirname(crash_log_path), exist_ok=True)
    
    # Print header
    print(f"{'=' * 80}")
    print(f"LangChain Chain Fuzzing")
    print(f"Crash logs will be written to: {crash_log_path}")
    print(f"{'=' * 80}")
    
    # Initialize seed corpus if provided
    seed_corpus_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "seeds",
        "chain_seeds"
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