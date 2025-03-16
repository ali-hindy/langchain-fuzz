#!/usr/bin/env python3
"""
Fuzzing harness for LangChain agent components.
Tests for code execution vulnerabilities, agent tools misuse, and error handling.
"""

import atheris
import sys
import os
import time
import traceback
from typing import Dict, Any, List, Optional, Tuple, Callable

# Add parent directory to path to import utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.data_generators import generate_string, generate_dict

# Import LangChain components - with try/except to handle different LangChain versions
try:
    from langchain.agents import Tool, AgentExecutor, ZeroShotAgent, LLMSingleActionAgent
    from langchain.agents.agent import AgentOutputParser
    from langchain.prompts import PromptTemplate
    from langchain.llms.fake import FakeListLLM
    from langchain.schema import AgentAction, AgentFinish
except ImportError:
    try:
        from langchain_core.prompts import PromptTemplate
        from langchain_core.agents import Tool, AgentExecutor
        from langchain.agents import ZeroShotAgent, LLMSingleActionAgent
        from langchain_core.agents import AgentOutputParser
        from langchain_core.language_models import FakeListLLM
        from langchain_core.agents import AgentAction, AgentFinish
    except ImportError:
        print("Error: LangChain agent components not installed properly")
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
                             "results", "agent_crashes.log")
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


def log_crash(agent_type: str, args: Dict[str, Any], exception: Exception):
    """Log crash details to a file for later reproduction.
    
    Args:
        agent_type: The type of agent
        args: The arguments used to create the agent
        exception: The exception that occurred
    """
    with open(crash_log_path, "a") as f:
        f.write(f"{'=' * 80}\n")
        f.write(f"Crash at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Agent: {agent_type}\n")
        f.write(f"Exception: {type(exception).__name__}: {str(exception)}\n")
        f.write(f"Arguments: {repr(args)}\n")
        f.write(f"Traceback:\n{traceback.format_exc()}\n")
        f.write(f"{'=' * 80}\n\n")


def create_fake_llm(fdp) -> FakeListLLM:
    """Create a fake LLM for testing agents.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        FakeListLLM instance
    """
    # Create responses that look like LLM agent responses
    responses = []
    num_responses = fdp.ConsumeIntInRange(1, 3)
    
    for _ in range(num_responses):
        response_type = fdp.ConsumeIntInRange(1, 4)
        
        if response_type == 1:
            # Valid action response
            responses.append(f"""I need to use a tool to help with this.
Action: calculator
Action Input: 2 + 2
""")
        elif response_type == 2:
            # Valid finish response
            responses.append(f"""I know the answer to this.
Final Answer: The answer is {fdp.ConsumeIntInRange(1, 100)}
""")
        elif response_type == 3:
            # Malformed response
            responses.append(f"""I'm going to do something unexpected.
{generate_string(fdp, 50)}
""")
        else:
            # Potentially malicious response attempting code execution
            responses.append(f"""Let me try executing some code.
Action: python
Action Input: __import__('os').system('echo "test"')
""")
    
    return FakeListLLM(responses=responses)


def create_safe_tools(fdp) -> List[Tool]:
    """Create a list of safe tools for testing.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        List of Tool objects
    """
    # Define some simple safe tools
    def calculator(query: str) -> str:
        """Safely compute simple math expressions."""
        try:
            # Safe calculation without eval
            if '+' in query:
                parts = query.split('+')
                if len(parts) == 2:
                    return str(float(parts[0].strip()) + float(parts[1].strip()))
            if '-' in query:
                parts = query.split('-')
                if len(parts) == 2:
                    return str(float(parts[0].strip()) - float(parts[1].strip()))
            if '*' in query:
                parts = query.split('*')
                if len(parts) == 2:
                    return str(float(parts[0].strip()) * float(parts[1].strip()))
            if '/' in query:
                parts = query.split('/')
                if len(parts) == 2 and float(parts[1].strip()) != 0:
                    return str(float(parts[0].strip()) / float(parts[1].strip()))
            return "Could not calculate. Please provide a valid expression."
        except:
            return "Error in calculation"
    
    def search(query: str) -> str:
        """Fake search function that safely returns dummy results."""
        return f"Search results for: {query}\n- Result 1\n- Result 2\n- Result 3"
    
    def random_fact() -> str:
        """Return a random fact."""
        facts = [
            "Water boils at 100 degrees Celsius at sea level.",
            "The Earth orbits the Sun at an average distance of 93 million miles.",
            "Honey never spoils. Archaeologists have found pots of honey in ancient Egyptian tombs that are over 3,000 years old and still perfectly good to eat."
        ]
        return facts[fdp.ConsumeIntInRange(0, len(facts) - 1)]
    
    # Create list of tools
    tools = [
        Tool(
            name="calculator",
            func=calculator,
            description="Useful for performing simple calculations."
        ),
        Tool(
            name="search",
            func=search,
            description="Useful for searching for information."
        ),
        Tool(
            name="random_fact",
            func=random_fact,
            description="Provides a random fact."
        )
    ]
    
    # Randomly select a subset of tools
    num_tools = fdp.ConsumeIntInRange(1, len(tools))
    selected_tools = []
    for i in range(num_tools):
        selected_tools.append(tools[i])
    
    return selected_tools


class VulnerableTool:
    """A deliberately vulnerable tool for testing purposes."""
    
    def __init__(self, fdp):
        self.fdp = fdp
        
        # Determine how vulnerable this tool should be
        self.vulnerability_level = fdp.ConsumeIntInRange(0, 2)  # 0=safe, 1=moderate, 2=high
    
    def create_tool(self) -> Tool:
        """Create a vulnerable tool.
        
        Returns:
            Tool object
        """
        if self.vulnerability_level == 0:
            # Safe tool
            return Tool(
                name="echo",
                func=self._safe_echo,
                description="Echoes back the input."
            )
        elif self.vulnerability_level == 1:
            # Moderately vulnerable tool (might have injection issues)
            return Tool(
                name="command_executor",
                func=self._moderate_command_executor,
                description="Runs commands in a sandboxed environment."
            )
        else:
            # Highly vulnerable tool (direct code execution)
            return Tool(
                name="python_executor",
                func=self._vulnerable_code_executor,
                description="Executes Python code."
            )
    
    def _safe_echo(self, input_str: str) -> str:
        """Safe echo function.
        
        Args:
            input_str: Input string
            
        Returns:
            Echoed string
        """
        return f"Echo: {input_str}"
    
    def _moderate_command_executor(self, input_str: str) -> str:
        """Moderately vulnerable command executor.
        
        Args:
            input_str: Input string
            
        Returns:
            Command output
        """
        # This simulates a restricted command executor that might be exploitable
        allowed_commands = ["list", "echo", "help"]
        
        # Check if command is allowed
        cmd_parts = input_str.split()
        if not cmd_parts:
            return "No command provided"
        
        cmd = cmd_parts[0].lower()
        
        if cmd not in allowed_commands:
            return f"Command not allowed: {cmd}"
        
        # Process allowed commands
        if cmd == "list":
            return "Available commands: list, echo, help"
        elif cmd == "echo":
            return " ".join(cmd_parts[1:])
        elif cmd == "help":
            return "Help: Use 'list' to see available commands, 'echo' to echo text."
        
        return "Unknown error"
    
    def _vulnerable_code_executor(self, input_str: str) -> str:
        """Vulnerable code executor.
        
        Args:
            input_str: Python code to execute
            
        Returns:
            Execution result
        """
        # This is deliberately vulnerable - in a real system, this would be a security risk
        # It's implemented to test if the fuzzer can detect such vulnerabilities
        try:
            # This should trigger our code execution monitor
            result = eval(input_str)
            return f"Result: {result}"
        except Exception as e:
            return f"Error: {str(e)}"


class CustomOutputParser(AgentOutputParser):
    """Custom output parser for testing."""
    
    def parse(self, llm_output: str) -> Union[AgentAction, AgentFinish]:
        """Parse LLM output into agent action or finish.
        
        Args:
            llm_output: Output from the LLM
            
        Returns:
            AgentAction or AgentFinish
        """
        if "Final Answer:" in llm_output:
            # Extract the final answer
            final_answer = llm_output.split("Final Answer:")[-1].strip()
            return AgentFinish(
                return_values={"output": final_answer},
                log=llm_output
            )
        
        # Check for an action
        if "Action:" in llm_output and "Action Input:" in llm_output:
            # Extract the action and action input
            action_match = re.search(r"Action: (.*?)[\n$]", llm_output)
            action_input_match = re.search(r"Action Input: (.*?)$", llm_output, re.DOTALL)
            
            if action_match and action_input_match:
                action = action_match.group(1).strip()
                action_input = action_input_match.group(1).strip()
                
                return AgentAction(
                    tool=action,
                    tool_input=action_input,
                    log=llm_output
                )
        
        # If we get here, we couldn't parse the output
        return AgentFinish(
            return_values={"output": "I couldn't determine what to do based on the input."},
            log=llm_output
        )


def test_zeroshot_agent(fdp) -> Tuple[Optional[AgentExecutor], Optional[str]]:
    """Test a ZeroShotAgent with fuzzed inputs.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        Tuple of (agent executor, input question) if created successfully, (None, None) otherwise
    """
    try:
        # Create a fake LLM
        llm = create_fake_llm(fdp)
        
        # Create tools
        tools = create_safe_tools(fdp)
        
        # Randomly add a vulnerable tool
        if fdp.ConsumeBool():
            vulnerable_tool = VulnerableTool(fdp).create_tool()
            tools.append(vulnerable_tool)
        
        # Create the prompt template
        prefix = """You are an AI assistant. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought:"""
        
        # Create the agent
        agent = ZeroShotAgent.from_llm_and_tools(
            llm=llm,
            tools=tools,
            prefix=prefix,
            verbose=fdp.ConsumeBool()
        )
        
        # Create the agent executor
        agent_executor = AgentExecutor.from_agent_and_tools(
            agent=agent,
            tools=tools,
            verbose=fdp.ConsumeBool(),
            max_iterations=fdp.ConsumeIntInRange(1, 5)
        )
        
        # Generate a test question
        question = fdp.PickValueInList([
            "What is 2+2?",
            "Tell me a random fact",
            "Search for information about AI",
            generate_string(fdp, 50)
        ])
        
        return agent_executor, question
    except Exception as e:
        stats["crashes"] += 1
        log_crash("ZeroShotAgent", {
            "tools": [t.name for t in tools] if 'tools' in locals() else "Not created",
            "question": question if 'question' in locals() else "Not created",
        }, e)
        return None, None


def test_custom_agent(fdp) -> Tuple[Optional[AgentExecutor], Optional[str]]:
    """Test a custom agent with fuzzed inputs.
    
    Args:
        fdp: Atheris FuzzedDataProvider
        
    Returns:
        Tuple of (agent executor, input question) if created successfully, (None, None) otherwise
    """
    try:
        # Create a fake LLM
        llm = create_fake_llm(fdp)
        
        # Create tools
        tools = create_safe_tools(fdp)
        
        # Create the prompt template
        template = """You are an AI assistant. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought: {agent_scratchpad}"""
        
        prompt = PromptTemplate(
            template=template,
            input_variables=["input", "tools", "tool_names", "agent_scratchpad"]
        )
        
        # Create a custom output parser
        output_parser = CustomOutputParser()
        
        # Create a custom LLM chain
        llm_chain = LLMChain(llm=llm, prompt=prompt)
        
        # Create the custom agent
        agent = LLMSingleActionAgent(
            llm_chain=llm_chain,
            output_parser=output_parser,
            stop=["\nObservation:"],
            allowed_tools=[tool.name for tool in tools]
        )
        
        # Create the agent executor
        agent_executor = AgentExecutor.from_agent_and_tools(
            agent=agent,
            tools=tools,
            verbose=fdp.ConsumeBool(),
            max_iterations=fdp.ConsumeIntInRange(1, 5)
        )
        
        # Generate a test question
        question = fdp.PickValueInList([
            "What is 2+2?",
            "Tell me a random fact",
            "Search for information about AI",
            generate_string(fdp, 50)
        ])
        
        return agent_executor, question
    except Exception as e:
        stats["crashes"] += 1
        log_crash("CustomAgent", {
            "tools": [t.name for t in tools] if 'tools' in locals() else "Not created",
            "question": question if 'question' in locals() else "Not created",
        }, e)
        return None, None


def test_agent_run(agent_executor: AgentExecutor, question: str):
    """Test the run method on an agent executor.
    
    Args:
        agent_executor: The agent executor to test
        question: Input question for the agent
    """
    try:
        # Run the agent with monitoring
        result = monitor_execution(agent_executor.run, question)
        return result
    except CodeExecutionDetected as e:
        # This is already counted in the monitor_execution function
        raise e
    except Exception as e:
        stats["crashes"] += 1
        log_crash(f"run() on {type(agent_executor).__name__}", {
            "question": question
        }, e)
        raise


def test_one_input(data):
    """Test function called by Atheris to fuzz one input.
    
    Args:
        data: Input data from Atheris
    """
    fdp = atheris.FuzzedDataProvider(data)
    stats["runs"] += 1
    
    # Choose an agent type to test
    agent_type = fdp.ConsumeIntInRange(1, 2)
    
    try:
        agent_executor, question = None, None
        if agent_type == 1:
            agent_executor, question = test_zeroshot_agent(fdp)
        elif agent_type == 2:
            agent_executor, question = test_custom_agent(fdp)
        
        if agent_executor and question:
            test_agent_run(agent_executor, question)
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
    print(f"LangChain Agent Fuzzing")
    print(f"Crash logs will be written to: {crash_log_path}")
    print(f"{'=' * 80}")
    
    # Initialize seed corpus if provided
    seed_corpus_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "seeds",
        "agent_seeds"
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