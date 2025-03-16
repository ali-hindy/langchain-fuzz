"""
Vulnerable Prompt Template implementation for LangChain fuzzing.
Contains a deliberate template injection vulnerability for testing.
"""

import re
from typing import Dict, Any, List, Optional, Union


class VulnerablePromptTemplate:
    """A deliberately vulnerable prompt template implementation.
    
    This class is similar to LangChain's PromptTemplate but has a 
    template injection vulnerability in the format method.
    """
    
    def __init__(self, template: str, input_variables: List[str]):
        """Initialize the prompt template.
        
        Args:
            template: The template string
            input_variables: List of variable names used in the template
        """
        self.template = template
        self.input_variables = input_variables
        
        # Validate that all input variables are in the template
        for var in input_variables:
            if "{" + var + "}" not in template:
                raise ValueError(f"Variable '{var}' not found in template")
    
    def format(self, **kwargs) -> str:
        """Format the template with the given variables.
        
        VULNERABLE: Uses Python's string.format() directly, which allows for
        attribute access and potential code execution.
        
        Args:
            **kwargs: The values for the input variables
            
        Returns:
            The formatted template
        """
        # Check that all variables are provided
        for var in self.input_variables:
            if var not in kwargs:
                raise ValueError(f"Missing value for variable: {var}")
        
        # VULNERABLE: Direct use of format() without proper sanitization
        return self.template.format(**kwargs)


class VulnerableTemplateEngine:
    """A deliberately vulnerable template engine implementation.
    
    This class implements a simple template engine with a 
    code execution vulnerability.
    """
    
    def __init__(self):
        """Initialize the template engine."""
        self.templates = {}
    
    def add_template(self, name: str, template: str):
        """Add a template to the engine.
        
        Args:
            name: Name of the template
            template: The template string
        """
        self.templates[name] = template
    
    def render(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render a template with the given context.
        
        VULNERABLE: Allows potential code execution through eval().
        
        Args:
            template_name: Name of the template to render
            context: Variables for the template
            
        Returns:
            The rendered template
        """
        if template_name not in self.templates:
            raise ValueError(f"Template not found: {template_name}")
        
        template = self.templates[template_name]
        
        # Find all expressions in the template
        pattern = r"\{\{(.+?)\}\}"
        expressions = re.findall(pattern, template)
        
        # Replace each expression with its evaluated value
        for expr in expressions:
            expr = expr.strip()
            
            # VULNERABLE: Using eval() on user-controlled input
            try:
                # Create a combined namespace with builtins and context
                namespace = {**context}
                
                # VULNERABLE: Direct eval() of user input
                result = eval(expr, namespace)
                
                template = template.replace("{{" + expr + "}}", str(result))
            except Exception as e:
                template = template.replace("{{" + expr + "}}", f"[Error: {str(e)}]")
        
        return template


# Example usage (if run directly)
if __name__ == "__main__":
    # Example 1: Simple prompt template
    template = "Hello, {name}! You are a {profession}."
    prompt = VulnerablePromptTemplate(template=template, input_variables=["name", "profession"])
    
    # Normal usage
    result = prompt.format(name="Alice", profession="doctor")
    print("Normal result:", result)
    
    # Exploit attempt (accesses object attributes)
    try:
        exploit = prompt.format(name="Bob", profession="{name.__class__}")
        print("Exploit result:", exploit)
    except Exception as e:
        print("Exploit failed:", str(e))
    
    # Example 2: Template engine with code execution
    engine = VulnerableTemplateEngine()
    engine.add_template("welcome", "Welcome, {{name}}! Today is {{import datetime; datetime.datetime.now().strftime('%Y-%m-%d')}}.")
    
    # Normal usage
    result = engine.render("welcome", {"name": "Charlie"})
    print("\nNormal result:", result)
    
    # Exploit attempt (executes arbitrary code)
    try:
        engine.add_template("exploit", "Result: {{__import__('os').listdir('.')}}.")
        exploit = engine.render("exploit", {})
        print("Exploit result:", exploit)
    except Exception as e:
        print("Exploit failed:", str(e))