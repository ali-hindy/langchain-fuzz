#!/usr/bin/env python3
"""
Direct test for template injection vulnerabilities in LangChain.
This script directly tests known dangerous templates without using the fuzzer.
"""

import sys
import os
import traceback

# Add parent directory to path to import from your project
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)

# Import necessary components
try:
    from langchain.prompts import PromptTemplate
    from langchain.prompts.chat import ChatPromptTemplate, SystemMessagePromptTemplate
except ImportError:
    try:
        from langchain_core.prompts import PromptTemplate
        from langchain_core.prompts.chat import ChatPromptTemplate, SystemMessagePromptTemplate
    except ImportError:
        print("Error: LangChain not installed properly")
        sys.exit(1)

# TemplateInjectionDetected exception
class TemplateInjectionDetected(Exception):
    """Exception raised when potential template injection is detected."""
    pass

# Dangerous function replacements
def detect_injection(*args, **kwargs):
    print("⚠️ INJECTION DETECTED: Attempt to execute code")
    raise TemplateInjectionDetected("Template injection detected: attempt to execute code")

# Function to test a template
def test_template(template, variables=None):
    if variables is None:
        variables = {"user_input": "test"}
    
    print(f"\n{'='*80}")
    print(f"Testing template: {template}")
    print(f"With variables: {variables}")
    
    # Save original functions
    original_exec = __builtins__.exec
    original_eval = __builtins__.eval
    original_import = __builtins__.__import__
    
    # Replace dangerous functions
    __builtins__.exec = detect_injection
    __builtins__.eval = detect_injection
    __builtins__.__import__ = detect_injection
    
    try:
        # Create a PromptTemplate with all variables
        input_variables = list(variables.keys())
        prompt = PromptTemplate(template=template, input_variables=input_variables)
        
        # Format the template
        result = prompt.format(**variables)
        print(f"✅ Template processed without detected injection")
        print(f"Result: {result}")
        
        # Create and test a chat template too
        system_message = SystemMessagePromptTemplate.from_template(template)
        chat_prompt = ChatPromptTemplate.from_messages([system_message])
        chat_result = chat_prompt.format_messages(**variables)
        print(f"✅ Chat template processed without detected injection")
        
        return False  # No injection detected
    except TemplateInjectionDetected:
        print(f"🚨 Template injection detected!")
        return True   # Injection detected
    except Exception as e:
        print(f"❌ Error during template processing: {type(e).__name__}: {str(e)}")
        traceback.print_exc()
        return False  # Not an injection, but an error
    finally:
        # Restore original functions
        setattr(__builtins__, 'exec', original_exec)
        setattr(__builtins__, 'eval', original_eval)
        setattr(__builtins__, '__import__', original_import)
        print(f"{'='*80}")

# Class with dangerous methods for testing
class DangerousObject:
    def __init__(self):
        self.data = "sensitive_data"
    
    def __str__(self):
        return self.data
    
    def __repr__(self):
        return f"DangerousObject({self.data})"
    
    def format(self, *args, **kwargs):
        return "format called"

# Dangerous variables
dangerous_vars = {
    # Basic variable
    "user_input": "normal_string",
    
    # Object with dangerous attributes
    "obj": DangerousObject(),
    
    # Dictionary with dangerous keys
    "config": {"__class__": {"__init__": {"__globals__": {"os": "os_module"}}}},
    
    # Direct access to dangerous objects
    "__builtins__": {"eval": eval, "exec": exec, "__import__": __import__}
}

# Templates to test
dangerous_templates = [
    # Your existing template
    "Let me evaluate this: {user_input.__class__.__init__.__globals__['os'].system('id')}",
    
    # Basic injection attempts
    "{eval('2+2')}",
    "{exec('import os; print(os.listdir(\".\"))')}",
    "{__import__('os').system('ls')}",
    
    # Object attribute access
    "{obj.__class__}",
    "{obj.__dict__}",
    "{obj.__globals__}",
    
    # Complex injection attempts
    "{().__class__.__base__.__subclasses__()}",
    "{''.__class__.__mro__[1].__subclasses__()}",
    
    # Formatted string injection
    "{user_input.format(x='{__import__(\\'os\\').system(\\'ls\\')}', y=2)}",
    
    # Simple expressions
    "{2+2}",
    "{{2+2}}",
    
    # Complex formatting
    "{user_input!r}",
    "{user_input:{obj}}"
]

def main():
    print("Testing LangChain template injection vulnerabilities")
    print(f"Using LangChain version: {getattr(sys.modules.get('langchain', sys.modules.get('langchain_core', None)), '__version__', 'unknown')}")
    
    injections_detected = 0
    
    # First, run tests with basic variables
    print("\n🔍 TESTING WITH BASIC VARIABLES")
    for template in dangerous_templates:
        if test_template(template):
            injections_detected += 1
    
    # Then, run tests with dangerous variables
    print("\n🔍 TESTING WITH DANGEROUS VARIABLES")
    for template in dangerous_templates:
        if test_template(template, dangerous_vars):
            injections_detected += 1
    
    # Add some more targeted tests
    print("\n🔍 TESTING SPECIFIC VARIABLE COMBINATIONS")
    specific_tests = [
        ("The answer is {eval('2+2')}", {}),
        ("{obj.__class__.__bases__[0].__subclasses__()}", {"obj": DangerousObject()}),
        ("{globals()}", {}),
        ("{locals()}", {})
    ]
    
    for template, vars in specific_tests:
        if test_template(template, vars):
            injections_detected += 1
    
    print(f"\nSummary: {injections_detected} template injections detected out of {len(dangerous_templates)*2 + len(specific_tests)} tests")

if __name__ == "__main__":
    main()