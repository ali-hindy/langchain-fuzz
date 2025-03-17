import sys
import os
import types
import inspect
import traceback

# Dictionary to hold original system functions
original_functions = {}

def setup_enhanced_monitoring():
    """
    Set up enhanced monitoring for code execution attempts.
    This adds more detection points beyond just the basic exec/eval/__import__.
    """
    # Store original functions
    original_functions.update({
        'exec': __builtins__.exec,
        'eval': __builtins__.eval,
        '__import__': __builtins__.__import__,
        'open': __builtins__.open,
        'compile': __builtins__.compile,
        'getattr': __builtins__.getattr,
        'globals': __builtins__.globals,
        'locals': __builtins__.locals
    })
    
    # Try to capture os.system, subprocess.run, etc.
    try:
        import os
        original_functions['os.system'] = os.system
        original_functions['os.popen'] = os.popen
        original_functions['os.execl'] = os.execl
        original_functions['os.execle'] = os.execle
        original_functions['os.execlp'] = os.execlp
        original_functions['os.execv'] = os.execv
        original_functions['os.execve'] = os.execve
        original_functions['os.execvp'] = os.execvp
        original_functions['os.spawnl'] = os.spawnl
        original_functions['os.spawnle'] = os.spawnle
        original_functions['os.spawnlp'] = os.spawnlp
        original_functions['os.spawnv'] = os.spawnv
        original_functions['os.spawnve'] = os.spawnve
        original_functions['os.spawnvp'] = os.spawnvp
    except ImportError:
        pass
    
    try:
        import subprocess
        original_functions['subprocess.run'] = subprocess.run
        original_functions['subprocess.call'] = subprocess.call
        original_functions['subprocess.check_call'] = subprocess.check_call
        original_functions['subprocess.check_output'] = subprocess.check_output
        original_functions['subprocess.Popen'] = subprocess.Popen
    except ImportError:
        pass

def monitor_template_function(stats_dict, template, variables):
    """
    Enhanced monitoring wrapper for template function evaluation.
    
    Args:
        stats_dict: Dictionary to update with detection statistics
        template: The template being evaluated
        variables: The variables used for evaluation
        
    Returns:
        A wrapper function that detects template injection attempts
    """
    class TemplateInjectionDetected(Exception):
        """Exception raised when potential template injection is detected."""
        pass
    
    def detect_injection(*args, **kwargs):
        # Get the calling function name
        caller_frame = inspect.currentframe().f_back
        caller_info = inspect.getframeinfo(caller_frame)
        function_name = caller_info.function
        
        # Get stack trace for more context
        stack = traceback.extract_stack()
        
        # Log the detection
        stats_dict["template_injection_detected"] += 1
        
        detection_msg = f"Template injection detected: attempt to execute {function_name}"
        print(f"\n{'='*80}\nALERT! {detection_msg}")
        print(f"Template: {template}")
        print(f"Variables: {variables}")
        print(f"Call stack: {stack[-3:]}")
        print(f"{'='*80}\n")
        
        raise TemplateInjectionDetected(detection_msg)
    
    return detect_injection

def patch_system_functions(stats_dict, template, variables):
    """
    Replace system functions with monitoring versions.
    
    Args:
        stats_dict: Dictionary to update with detection statistics
        template: The template being evaluated
        variables: The variables used for evaluation
    """
    # Basic builtins
    detector = monitor_template_function(stats_dict, template, variables)
    __builtins__.exec = detector
    __builtins__.eval = detector
    __builtins__.__import__ = detector
    __builtins__.open = detector
    __builtins__.compile = detector
    
    # More sophisticated ways to access dangerous functionality
    __builtins__.getattr = detector
    __builtins__.globals = detector
    __builtins__.locals = detector
    
    # Try to patch os functions
    try:
        import os
        os.system = detector
        os.popen = detector
        os.execl = detector
        os.execle = detector
        os.execlp = detector
        os.execv = detector
        os.execve = detector
        os.execvp = detector
        os.spawnl = detector
        os.spawnle = detector
        os.spawnlp = detector
        os.spawnv = detector
        os.spawnve = detector
        os.spawnvp = detector
    except ImportError:
        pass
    
    # Try to patch subprocess functions
    try:
        import subprocess
        subprocess.run = detector
        subprocess.call = detector
        subprocess.check_call = detector
        subprocess.check_output = detector
        subprocess.Popen = detector
    except ImportError:
        pass

def restore_system_functions():
    """
    Restore all patched system functions to their original versions.
    """
    for name, func in original_functions.items():
        if '.' in name:
            # Handle module.function format (like os.system)
            module_name, func_name = name.split('.')
            module = sys.modules.get(module_name)
            if module:
                setattr(module, func_name, func)
        else:
            # Handle builtins
            setattr(__builtins__, name, func)

def get_dangerous_template_patterns():
    """
    Return a list of known dangerous template patterns to try.
    
    Returns:
        list: List of potentially dangerous template patterns
    """
    return [
        # Format string injection patterns
        "{0.__class__}",
        "{0.__dict__}",
        "{0.__class__.__bases__[0].__subclasses__()}",
        "{0.__class__.__mro__[1].__subclasses__()}",
        "{0.__init__.__globals__}",
        
        # Python expression injection
        "{0+0}",
        "{1+1}",
        "{{1+1}}",
        "{{__import__('os').system('ls')}}",
        
        # Jinja2 style injections (might be confused by template engines)
        "{{ config.__class__.__init__.__globals__['os'].system('ls') }}",
        "{% for i in range(5) %}{{ i }}{% endfor %}",
        
        # Nested format strings
        "{user:{admin}}",
        
        # OS command injection attempts
        "{os.system('ls')}",
        "{subprocess.check_output(['ls', '-la'])}",
        
        # Data exfiltration attempts
        "{open('/etc/passwd', 'r').read()}",
        "{__import__('base64').b64encode(open('/etc/passwd','rb').read())}",
        
        # Timing attacks
        "{__import__('time').sleep(5)}",
        
        # Using different syntax/encoding to bypass filters
        "{0.__\u200bclass__}", # Zero-width space
        "{0['__class__']}",
        "{}".format().__class__.__bases__[0].__subclasses__()[40](''.join(map(chr, [47, 101, 116, 99, 47, 112, 97, 115, 115, 119, 100])))"
    ]