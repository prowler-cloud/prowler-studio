# Agent Development Best Practices

This document outlines the coding standards and best practices for developing agents in Prowler Studio. Following these guidelines ensures maintainable, scalable, and high-quality code.

## Table of Contents

- [Architecture Principles](#architecture-principles)
- [Code Organization](#code-organization)
- [Method Decomposition](#method-decomposition)
- [Type Safety](#type-safety)
- [Named Parameters](#named-parameters)
- [Return Types with Pydantic](#return-types-with-pydantic)
- [Constants Management](#constants-management)
- [File Structure](#file-structure)
- [Examples](#examples)

---

## Architecture Principles

### Base Agent Class

All agents inherit from the `Agent` base class ([src/agents/base.py](src/agents/base.py)), which provides:

- **`working_dir`**: Path to the working directory
- **`config`**: Agent-specific configuration from kwargs
- **`_process_agent_messages(client)`**: Shared method for processing Claude SDK responses
  - Streams `TextBlock` content to console and logs
  - Logs `ToolUseBlock` inputs at DEBUG level (`[TOOL CALL]`)
  - Logs `ToolResultBlock` outputs at DEBUG level (`[TOOL RESULT]`)

Agents must implement the abstract `run()` method.

### Single Responsibility Principle (SRP)

Each method should have **one clear purpose**. If a method does multiple things, break it down.

**❌ Bad Example:**
```python
async def run(self):
    # 127 lines doing: loading prompts, creating options, running agent,
    # discovering checks, verifying, fixing, and returning results
    ...
```

**✅ Good Example:**
```python
async def run(self):
    """High-level orchestration."""
    prompt = self._load_implementation_prompt()
    options = self._create_claude_options()

    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        discovery_result = self._discover_check_info()
        verification_result = await self._verify_and_fix_check(...)

    return CheckImplementationResult(...)
```

---

## Code Organization

### 1. File Structure

Organize agent code into separate, focused files:

```
src/agents/implementation/
├── __init__.py          # Public API exports
├── agent.py            # Agent business logic
├── models.py           # Pydantic models (data structures)
└── prompts/            # Jinja templates
    ├── implement_check.jinja
    └── fix_check.jinja
```

### 2. Separation of Concerns

**Models should be separate from business logic:**

- **models.py**: Data structures, validation, serialization
- **agent.py**: Business logic, orchestration, workflows
- **__init__.py**: Public API surface

**Benefits:**
- ✅ Easier to test models independently
- ✅ Prevents circular imports
- ✅ Models can be reused across agents
- ✅ Cleaner code organization

---

## Method Decomposition

### Break Down Large Methods

Keep methods **under 50 lines**. Extract logical sections into private methods.

**✅ Good Method Decomposition:**

```python
class ChecKreatorAgent(Agent):
    # Setup methods
    def _load_implementation_prompt(self) -> str: ...
    def _load_fix_prompt(self, check_name: str, message: str) -> str: ...
    def _create_claude_options(self) -> ClaudeAgentOptions: ...

    # Inherited from Agent base class:
    # async def _process_agent_messages(self, client: ClaudeSDKClient) -> None: ...

    # Business logic methods
    def _discover_check_info(self) -> CheckDiscoveryResult: ...
    async def _verify_and_fix_check(self, ...) -> CheckVerificationResult: ...

    # Main orchestration (clean and readable)
    async def run(self) -> CheckImplementationResult: ...
```

**Benefits:**
- ✅ Each method has a clear purpose
- ✅ Easier to test individual components
- ✅ Better code reusability
- ✅ Simpler to understand and maintain

---

## Type Safety

### Always Use Type Hints

**Every variable, parameter, and return type must have a type hint.**

**✅ Good Type Hints:**

```python
def _load_fix_prompt(self, check_name: str, verification_message: str) -> str:
    """Load the check fix prompt template."""
    fix_prompt_path: Path = Path(__file__).parent / "prompts" / "fix_check.jinja"
    return load_prompt(
        path=fix_prompt_path,
        context={
            "check_name": check_name,
            "verification_message": verification_message,
        },
    )

async def run(self) -> CheckImplementationResult:
    """Implement a Prowler check."""
    implement_check_prompt: str = self._load_implementation_prompt()
    options: ClaudeAgentOptions = self._create_claude_options()

    discovery_result: CheckDiscoveryResult = self._discover_check_info()
    verification_result: CheckVerificationResult = await self._verify_and_fix_check(...)

    return CheckImplementationResult(...)
```

**Benefits:**
- ✅ IDE autocomplete and IntelliSense
- ✅ Early error detection with type checkers (mypy, pyright)
- ✅ Self-documenting code
- ✅ Easier refactoring

---

## Named Parameters

### Always Use Named Parameters in Function Calls

**Never rely on positional arguments** (except for single, obvious parameters like `Path()`).

**❌ Bad Example:**
```python
result = self._load_fix_prompt(check_name, message)
await self._verify_and_fix_check(client, check_name, check_provider)
load_prompt(prompt_path, {"check_ticket": self.check_ticket})
```

**✅ Good Example:**
```python
result = self._load_fix_prompt(
    check_name=check_name,
    verification_message=message
)

await self._verify_and_fix_check(
    client=client,
    check_name=check_name,
    check_provider=check_provider
)

load_prompt(
    path=prompt_path,
    context={"check_ticket": self.check_ticket}
)
```

**Benefits:**
- ✅ Self-documenting code
- ✅ Prevents parameter order mistakes
- ✅ Easier to refactor (add/remove/reorder parameters)
- ✅ Clearer intent

---

## Return Types with Pydantic

### Never Return Tuples or Plain Dicts

**Always use Pydantic models** for return types. This makes the API explicit and self-documenting.

**❌ Bad Example:**
```python
def _discover_check_info(self) -> tuple[bool, str, str]:
    """What are these three values? Must check definition!"""
    return True, "my_check", "aws"

# Usage - unclear what each value represents
success, name, provider = self._discover_check_info()
```

**✅ Good Example:**
```python
# models.py
class CheckDiscoveryResult(BaseModel):
    """Result of discovering a check from repository changes."""
    success: bool = Field(description="Whether check discovery was successful")
    check_name: str = Field(default="", description="Name of the discovered check")
    check_provider: str = Field(
        default="", description="Provider of the check (e.g., 'aws', 'azure')"
    )

# agent.py
def _discover_check_info(self) -> CheckDiscoveryResult:
    """Crystal clear return type."""
    return CheckDiscoveryResult(
        success=True,
        check_name="my_check",
        check_provider="aws"
    )

# Usage - explicit and clear
result = self._discover_check_info()
if result.success:
    print(f"Found: {result.check_name} for {result.check_provider}")
```

**Benefits:**
- ✅ No need to check function definition to understand return structure
- ✅ IDE autocomplete on result fields
- ✅ Type validation at runtime
- ✅ Easy serialization/deserialization (`.model_dump()`, `.model_validate()`)
- ✅ Field descriptions serve as inline documentation
- ✅ Easier to add/modify fields without breaking callers

### Pydantic Model Best Practices

```python
from pydantic import BaseModel, Field

class CheckImplementationResult(BaseModel):
    """Always include a docstring."""

    # Use Field() with descriptions
    success: bool = Field(description="Whether implementation was successful")
    check_name: str = Field(default="", description="Name of the implemented check")
    message: str = Field(default="", description="Result message")
    attempts: int = Field(default=0, description="Number of verification attempts")

    # Use Optional for nullable fields
    error: str | None = Field(default=None, description="Error message if failed")

    # Provide sensible defaults when appropriate
```

---

## Constants Management

### Replace All Magic Numbers with Named Constants

**Magic numbers** make code hard to understand and maintain. Use class-level constants with descriptive names.

**❌ Bad Example:**
```python
tools_server = create_sdk_mcp_server(name="utils", version="1.0.0", tools=[mkcheck])

max_attempts = 5
while attempt < 5 and not success:
    ...

check_provider = check_path.parents[2].name  # What does 2 mean?
```

**✅ Good Example:**
```python
class ChecKreatorAgent(Agent):
    """Agent that implements Prowler checks from tickets."""

    # MCP Server Configuration
    MCP_SERVER_NAME: str = "utils"
    MCP_SERVER_VERSION: str = "1.0.0"

    # Check Verification
    MAX_CHECK_VERIFICATION_ATTEMPTS: int = 5

    # Path Navigation
    PROVIDER_PATH_LEVEL: int = 3  # Number of parent levels to reach provider

    def _create_claude_options(self) -> ClaudeAgentOptions:
        tools_server = create_sdk_mcp_server(
            name=self.MCP_SERVER_NAME,
            version=self.MCP_SERVER_VERSION,
            tools=[mkcheck],
        )

    async def _verify_and_fix_check(self, ...) -> CheckVerificationResult:
        max_attempts: int = self.MAX_CHECK_VERIFICATION_ATTEMPTS
        while attempt < max_attempts and not success:
            ...

    def _discover_check_info(self) -> CheckDiscoveryResult:
        check_provider = check_path.parents[self.PROVIDER_PATH_LEVEL - 1].name
```

**Benefits:**
- ✅ Self-documenting code
- ✅ Easy to modify values in one place
- ✅ No mysterious numbers scattered throughout code
- ✅ Clear intent and meaning

### Constant Naming Convention

- Use `UPPER_CASE_WITH_UNDERSCORES` for constants
- Group related constants together
- Add comments when the purpose isn't obvious
- Type hint constants for additional clarity

---

## File Structure

### Complete Agent Package Example

```
src/agents/implementation/
├── __init__.py
├── agent.py
├── models.py
└── prompts/
    ├── implement_check.jinja
    └── fix_check.jinja
```

**__init__.py** - Public API:
```python
"""Implementation agent for creating Prowler checks."""

from agents.implementation.agent import ChecKreatorAgent
from agents.implementation.models import (
    CheckDiscoveryResult,
    CheckVerificationResult,
    CheckImplementationResult,
)

__all__ = [
    "ChecKreatorAgent",
    "CheckDiscoveryResult",
    "CheckVerificationResult",
    "CheckImplementationResult",
]
```

**models.py** - Data structures:
```python
"""Pydantic models for ChecKreatorAgent results."""

from pydantic import BaseModel, Field


class CheckDiscoveryResult(BaseModel):
    """Result of discovering a check from repository changes."""
    success: bool = Field(description="Whether check discovery was successful")
    check_name: str = Field(default="", description="Name of the discovered check")
    check_provider: str = Field(
        default="", description="Provider of the check (e.g., 'aws', 'azure')"
    )
```

**agent.py** - Business logic:
```python
"""Implementation agent for creating Prowler checks."""

from pathlib import Path
from typing import Any

from agents.base import Agent
from agents.implementation.models import (
    CheckDiscoveryResult,
    CheckVerificationResult,
    CheckImplementationResult,
)


class ChecKreatorAgent(Agent):
    """Agent that implements Prowler checks from tickets."""

    # Constants
    MCP_SERVER_NAME: str = "utils"
    MAX_CHECK_VERIFICATION_ATTEMPTS: int = 5

    def __init__(self, working_dir: Path, check_ticket: str, prowler_repo: Repo, **kwargs):
        super().__init__(working_dir, **kwargs)
        self.check_ticket: str = check_ticket
        self.prowler_repo: Repo = prowler_repo

    # Private helper methods
    def _load_implementation_prompt(self) -> str: ...
    def _discover_check_info(self) -> CheckDiscoveryResult: ...

    # Public interface
    async def run(self) -> CheckImplementationResult: ...
```

---

## Examples

### Complete Example: Before and After

**❌ BEFORE (Poor Practices):**

```python
class Agent:
    def run(self):
        # 127 lines of code
        prompt_path = Path(__file__).parent / "prompts" / "implement_check.jinja"
        prompt = load_prompt(prompt_path, {"check_ticket": self.ticket})

        server = create_sdk_mcp_server("utils", "1.0.0", [mkcheck])

        # ... lots of code ...

        max_attempts = 5
        attempt = 0
        success = False
        message = ""

        while attempt < 5 and not success:
            # ... more code ...
            pass

        # What does this tuple contain?
        return success, check_name, message, attempt
```

**✅ AFTER (Best Practices):**

```python
# models.py
class CheckImplementationResult(BaseModel):
    """Result of implementing a Prowler check."""
    success: bool = Field(description="Whether implementation was successful")
    check_name: str = Field(default="", description="Name of the implemented check")
    message: str = Field(default="", description="Result message")
    attempts: int = Field(default=0, description="Number of verification attempts")


# agent.py
class ChecKreatorAgent(Agent):
    """Agent that implements Prowler checks from tickets."""

    # Constants
    MCP_SERVER_NAME: str = "utils"
    MCP_SERVER_VERSION: str = "1.0.0"
    MAX_CHECK_VERIFICATION_ATTEMPTS: int = 5

    def _load_implementation_prompt(self) -> str:
        """Load the check implementation prompt template."""
        prompt_path: Path = Path(__file__).parent / "prompts" / "implement_check.jinja"
        return load_prompt(path=prompt_path, context={"check_ticket": self.check_ticket})

    def _create_claude_options(self) -> ClaudeAgentOptions:
        """Create Claude agent options with tools and MCP servers."""
        tools_server: Any = create_sdk_mcp_server(
            name=self.MCP_SERVER_NAME,
            version=self.MCP_SERVER_VERSION,
            tools=[mkcheck],
        )
        return ClaudeAgentOptions(
            allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
            mcp_servers={"utils": tools_server},
            permission_mode="bypassPermissions",
            cwd=str(self.working_dir),
        )

    async def _verify_and_fix_check(
        self, client: ClaudeSDKClient, check_name: str, check_provider: str
    ) -> CheckVerificationResult:
        """Verify the check implementation and fix issues in a loop."""
        max_attempts: int = self.MAX_CHECK_VERIFICATION_ATTEMPTS
        attempt: int = 0
        success: bool = False
        message: str = ""

        while attempt < max_attempts and not success:
            attempt += 1
            success, message = verify_check_loaded(
                check_name=check_name,
                provider=check_provider,
                prowler_directory=Path(self.prowler_repo.working_dir),
            )
            # ... handle failures ...

        return CheckVerificationResult(
            success=success,
            message=message,
            attempts=attempt
        )

    async def run(self) -> CheckImplementationResult:
        """Implement a Prowler check."""
        implement_check_prompt: str = self._load_implementation_prompt()
        options: ClaudeAgentOptions = self._create_claude_options()

        async with ClaudeSDKClient(options=options) as client:
            await client.query(implement_check_prompt)

            discovery_result: CheckDiscoveryResult = self._discover_check_info()
            if not discovery_result.success:
                return CheckImplementationResult(
                    success=False,
                    error="No check folders found in repository changes",
                )

            verification_result: CheckVerificationResult = await self._verify_and_fix_check(
                client=client,
                check_name=discovery_result.check_name,
                check_provider=discovery_result.check_provider,
            )

        return CheckImplementationResult(
            success=verification_result.success,
            check_name=discovery_result.check_name,
            message=verification_result.message,
            attempts=verification_result.attempts,
        )
```

---

## Checklist for New Agents

When creating a new agent, ensure:

- [ ] **File Structure**: Separate models.py, agent.py, __init__.py
- [ ] **Type Hints**: All variables, parameters, and return types are typed
- [ ] **Named Parameters**: All function calls use named parameters
- [ ] **Pydantic Models**: No tuples or plain dicts for return types
- [ ] **Constants**: All magic numbers replaced with named constants
- [ ] **Method Size**: No method exceeds 50 lines
- [ ] **Single Responsibility**: Each method has one clear purpose
- [ ] **Docstrings**: All classes and methods have docstrings
- [ ] **Public API**: __init__.py exports only what's needed
- [ ] **Tests**: Unit tests for all public methods

---

## Additional Resources

- [PEP 484 - Type Hints](https://peps.python.org/pep-0484/)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Python Style Guide (PEP 8)](https://peps.python.org/pep-0008/)

**Remember: These practices exist to make our codebase maintainable and our team productive. Follow them consistently!**
